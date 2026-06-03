# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""``contentops rule-test`` -- run a detection's KQL against the live workspace.

F2-lite implementation (per user memory): retrospective Log Analytics
query, never a Python KQL evaluator. The detection's KQL body is sent
verbatim to the workspace's Log Analytics Query API; the response row
count gates against optional ``--expect-min`` / ``--expect-max``
bounds.

This validates four things at once that the existing pipeline cannot:

* The KQL **parses on the server side** (a column typo that the
  regex-based KQL lint missed surfaces here as a server 400).
* The KQL **references tables / columns the workspace actually has**
  (an undefined column shows up as ``SemanticError`` from LA).
* The KQL **produces output of an expected order of magnitude** over
  a real window (catches "rule has been silent for a year" + "rule
  is firing 50k times per hour" before deploy).
* The active **identity has Log Analytics Reader** on the workspace
  (a missing role surfaces here as a 403, faster than waiting for
  a portal click).

Module named ``rule_test`` (not ``test``) so pytest collection doesn't
treat this module as a test module.
"""

from __future__ import annotations

import sys
from pathlib import Path

import click


@click.command("rule-test")
@click.argument("rule_id")
@click.option(
    "--path", "detections_path",
    type=click.Path(path_type=Path),
    default=Path("detections"),
    help="Root detections directory (default ``detections/``).",
)
@click.option(
    "--asset",
    default=None,
    help="Restrict the search to one asset kind (e.g. ``sentinel_analytic``). "
         "Useful when the same id slug exists across kinds.",
)
@click.option(
    "--workspace-id", "workspace_id",
    envvar="PIPELINE_WORKSPACE_ID",
    default=None,
    help="Log Analytics workspace GUID. Defaults to auto-derive from "
         "``config/tenant.yml`` via the ``--role`` entry; pass explicitly "
         "(or set ``PIPELINE_WORKSPACE_ID``) to override.",
)
@click.option(
    "--role",
    type=click.Choice(["prod", "integration", "dev", "test"]),
    default="prod", show_default=True,
    help="Which tenant.yml ``sentinelWorkspaces`` entry to auto-derive "
         "the workspace ID from. Ignored when --workspace-id is given.",
)
@click.option(
    "--limit", type=int, default=10,
    help="Cap rows returned for display (default 10). The full row "
         "count is reported regardless.",
)
@click.option(
    "--expect-min", type=int, default=None,
    help="Fail (exit 1) if the rule returns fewer than this many rows. "
         "Useful for 'this rule must fire at least N times per day to "
         "be worth shipping' gates in CI.",
)
@click.option(
    "--expect-max", type=int, default=None,
    help="Fail (exit 1) if the rule returns more than this many rows. "
         "Useful for 'this rule must not be noisier than N per day' "
         "gates. Common before promoting from experimental to production.",
)
def rule_test_cmd(
    rule_id: str,
    detections_path: Path,
    asset: str | None,
    workspace_id: str | None,
    role: str,
    limit: int,
    expect_min: int | None,
    expect_max: int | None,
) -> None:
    """Run a detection's KQL against the live workspace.

    \b
    Examples:
      contentops rule-test brute-force-ssh --expect-min 1
      contentops rule-test newly-registered-domain --expect-max 50
      contentops rule-test some-rule --role integration --expect-min 1

    The query body comes from the envelope's KQL field (per asset
    kind). The rule's existing time filter (``ago(7d)`` etc.) is the
    sole time scope -- the harness does NOT impose a default lookback
    because that would change rule semantics. A rule that's not time-
    scoped will return everything and trip ``--expect-max`` -- which is
    correct: that rule has a bug.

    Requires Log Analytics Reader on the workspace. Auth is
    ``DefaultAzureCredential`` (same as the rest of contentops).
    """
    from contentops.core.asset import Asset, kql_body_from_payload
    from contentops.core.discovery import iter_loaded_assets
    from contentops.utils.auth import get_credential
    from contentops.workspace_kql import (
        LA_SCOPE, WorkspaceKqlError, query, resolve_workspace_id,
    )

    if not detections_path.is_dir():
        click.echo(f"error: {detections_path} is not a directory", err=True)
        sys.exit(2)

    # Find the matching envelope. We don't pre-filter by ``--asset``
    # in discover_assets because the discovery layer doesn't expose
    # that filter -- it's a per-file LoadedAsset check post-load.
    target_asset = Asset(asset) if asset else None
    matches: list = []
    for loaded in iter_loaded_assets(detections_path):
        if target_asset is not None and loaded.envelope.asset != target_asset:
            continue
        if loaded.envelope.id == rule_id:
            matches.append(loaded)

    if not matches:
        click.echo(
            f"error: no envelope with id={rule_id!r}"
            + (f" and asset={asset!r}" if asset else "")
            + f" under {detections_path}",
            err=True,
        )
        sys.exit(1)
    if len(matches) > 1:
        kinds = ", ".join(la.envelope.asset.value for la in matches)
        click.echo(
            f"error: id={rule_id!r} matches {len(matches)} envelopes "
            f"across asset kinds: {kinds}. Pass --asset to disambiguate.",
            err=True,
        )
        sys.exit(2)

    loaded = matches[0]
    asset_value = loaded.envelope.asset.value
    kql_body = kql_body_from_payload(loaded.envelope.asset, loaded.payload)
    if not kql_body:
        click.echo(
            f"error: envelope {rule_id!r} ({asset_value}) carries no "
            f"KQL body to test.",
            err=True,
        )
        sys.exit(1)

    click.echo(f"rule:      {asset_value}/{rule_id}")

    try:
        cred = get_credential()
    except Exception as exc:
        click.echo(f"error: credential acquisition failed: {exc}", err=True)
        sys.exit(1)

    # Resolve the workspace from --role unless an explicit id was given.
    if not workspace_id:
        try:
            workspace_id = resolve_workspace_id(role=role, credential=cred)
        except WorkspaceKqlError as exc:
            click.echo(f"error: {exc}", err=True)
            sys.exit(1)

    click.echo(f"workspace: {workspace_id}")

    try:
        token = cred.get_token(LA_SCOPE).token
    except Exception as exc:
        click.echo(f"error: token acquisition failed: {exc}", err=True)
        sys.exit(1)

    # Wrap the rule's KQL with a tail ``| take`` so display output is
    # bounded. The wrap is purely for CLI legibility -- the gate
    # compares the FULL count via a separate count branch.
    display_query = f"{kql_body}\n| take {max(1, int(limit))}"
    count_query = f"{kql_body}\n| count"

    try:
        display = query(display_query, workspace_id=workspace_id, token=token)
        count_result = query(count_query, workspace_id=workspace_id, token=token)
    except WorkspaceKqlError as exc:
        click.echo(f"error: query failed: {exc}", err=True)
        sys.exit(1)

    # ``| count`` returns one row with a single Count column.
    total = 0
    if count_result.rows:
        first = count_result.rows[0]
        # LA returns the column as "Count" by convention.
        val = first.get("Count")
        if val is None and first:
            val = next(iter(first.values()))
        try:
            total = int(val) if val is not None else 0
        except (TypeError, ValueError):
            total = 0

    click.echo(f"\nrows:      {total} total ({len(display.rows)} shown)")
    if display.rows:
        cols = display.column_names or list(display.rows[0].keys())
        click.echo("  " + " | ".join(cols))
        click.echo("  " + "-+-".join("-" * len(c) for c in cols))
        for r in display.rows:
            click.echo("  " + " | ".join(str(r.get(c, "")) for c in cols))

    # Gate.
    failures: list[str] = []
    if expect_min is not None and total < expect_min:
        failures.append(
            f"row count {total} < --expect-min={expect_min} "
            f"(rule may be silent, broken, or KQL drifted)"
        )
    if expect_max is not None and total > expect_max:
        failures.append(
            f"row count {total} > --expect-max={expect_max} "
            f"(rule is noisier than the configured ceiling)"
        )
    if failures:
        click.echo("", err=True)
        for f in failures:
            click.echo(f"FAIL: {f}", err=True)
        sys.exit(1)

    click.echo("\nPASS")
