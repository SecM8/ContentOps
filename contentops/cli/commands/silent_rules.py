# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""``contentops silent-rules`` command (F4)."""

from __future__ import annotations

import sys
from pathlib import Path

import click


@click.command("silent-rules")
@click.option(
    "--path", "detections_path",
    type=click.Path(path_type=Path),
    default=Path("detections"), show_default=True,
    help="Root detections directory: the repo rules to list.",
)
@click.option(
    "--workspace-id", "workspace_id",
    envvar="PIPELINE_WORKSPACE_ID",
    default=None,
    help="Log Analytics workspace ID (GUID). Defaults to auto-derive "
         "from `config/tenant.yml` via ARM; only pass explicitly when "
         "you need to override the tenant-config selection.",
)
@click.option(
    "--role",
    type=click.Choice(["prod", "integration", "dev", "test"]),
    default="prod", show_default=True,
    help="Which tenant.yml `sentinelWorkspaces` entry to auto-derive "
         "the workspace ID from (ignored when --workspace-id is given), "
         "and which rule statuses that workspace deploys.",
)
@click.option(
    "--since", "since_days", type=click.IntRange(min=1, max=365), default=30,
    help="Lookback window in days (default 30).",
)
@click.option(
    "--include-unmatched", "include_unmatched", is_flag=True, default=False,
    help="Also list telemetry rows no repo rule matched (source=workspace): "
         "rules deployed outside the repo, built-in product alerts.",
)
@click.option(
    "--format", "output_format",
    type=click.Choice(["table", "json", "csv"]),
    default="table",
)
@click.option(
    "--out", type=click.Path(path_type=Path), default=None,
    help="Write output to this file instead of stdout.",
)
def silent_rules_cmd(
    detections_path: Path, workspace_id: str | None, role: str,
    since_days: int, include_unmatched: bool, output_format: str, out: Path | None,
) -> None:
    """List the repo's deployed rules with their telemetry, silent first (F4).

    \b
    Closes G7. Lists every enabled sentinel_analytic /
    defender_custom_detection rule whose status --role's workspace
    deploys (prod: production; integration: test + production; test:
    test; dev: experimental + test + production; Defender rules for
    prod only, as apply does), with de-duplicated SecurityAlert +
    SecurityIncident counts summed over its rule keys: `id:<rule>`
    when the alert / incident names its Sentinel analytic rule
    (AlertType / RelatedAnalyticRuleIds), else `name:<display name>`.
    A rule with no alert and no incident in the window is silent -
    (a) tuned out by an upstream change, (b) waiting for an attack
    pattern that hasn't recurred, (c) broken (KQL evaluates to zero
    rows). The pipeline can't distinguish, but it surfaces the
    candidates.

    Workspace selection: auto-derives the LA workspace GUID from
    config/tenant.yml's --role entry. Pass --workspace-id to override
    (or set PIPELINE_WORKSPACE_ID env var for the legacy code path).
    """
    import csv as _csv
    import io as _io
    import json as _json
    from contentops.silent_rules import (
        COLUMNS, build_report, deployed_statuses, select_rules,
    )
    from contentops.utils.auth import get_credential
    from contentops.workspace_kql import (
        LA_SCOPE, WorkspaceKqlError, query, resolve_workspace_id,
        silent_rules_query,
    )

    if not detections_path.is_dir():
        click.echo(
            f"error: detections path not found: {detections_path} (pass --path)",
            err=True,
        )
        sys.exit(1)
    load_errors: list[Path] = []
    rules = select_rules(
        detections_path, role=role,
        on_error=lambda path, _exc: load_errors.append(path),
    )
    if load_errors:
        click.echo(
            f"warning: {len(load_errors)} file(s) under {detections_path} don't "
            "load and are not listed; run `contentops lint` for details.",
            err=True,
        )

    try:
        cred = get_credential()
    except Exception as exc:
        click.echo(f"error: credential acquisition failed: {exc}", err=True)
        sys.exit(1)

    if not workspace_id:
        try:
            workspace_id = resolve_workspace_id(role=role, credential=cred)
        except WorkspaceKqlError as exc:
            click.echo(f"error: {exc}", err=True)
            sys.exit(1)

    try:
        token = cred.get_token(LA_SCOPE).token
    except Exception as exc:
        click.echo(f"error: token acquisition failed: {exc}", err=True)
        sys.exit(1)

    try:
        result = query(
            silent_rules_query(since_days=since_days),
            workspace_id=workspace_id, token=token,
        )
    except WorkspaceKqlError as exc:
        click.echo(f"error: {exc}", err=True)
        sys.exit(1)

    report = build_report(rules, result.rows, include_unmatched=include_unmatched)
    rows = report.rows
    statuses = ", ".join(deployed_statuses(role))
    if output_format == "json":
        rendered = _json.dumps(rows, indent=2, default=str) + "\n"
    elif output_format == "csv":
        buf = _io.StringIO()
        writer = _csv.writer(buf, lineterminator="\n")
        writer.writerow(COLUMNS)
        for r in rows:
            writer.writerow([_csv_cell(r[c]) for c in COLUMNS])
        rendered = buf.getvalue()
    else:  # table
        cols = [c for c in COLUMNS if c != "rule_keys" and (include_unmatched or c != "source")]
        if not rows:
            rendered = (
                f"(no enabled rule with status {statuses} under {detections_path})\n"
            )
        else:
            cells = [{c: _table_cell(r[c]) for c in cols} for r in rows]
            widths = {c: max(len(c), *(len(cell[c]) for cell in cells)) for c in cols}
            lines = [" ".join(c.ljust(widths[c]) for c in cols)]
            lines.append(" ".join("-" * widths[c] for c in cols))
            for cell in cells:
                lines.append(" ".join(cell[c].ljust(widths[c]) for c in cols).rstrip())
            lines.append("")
            lines.append(
                f"{report.silent_count} of {report.rule_count} rule(s) silent over "
                f"the last {since_days}d (no alert and no incident; status {statuses})."
            )
            rendered = "\n".join(lines) + "\n"
    for note in report.notes:
        click.echo(f"note: {note}", err=True)

    if out is not None:
        out.write_text(rendered, encoding="utf-8")
        click.echo(f"wrote {len(rows)} row(s) to {out}", err=True)
    else:
        sys.stdout.write(rendered)
        sys.stdout.flush()


def _csv_cell(value: object) -> object:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, list):
        return " ".join(str(v) for v in value)
    return "" if value is None else value


def _table_cell(value: object) -> str:
    """0 prints as 0 (a blank cell read as "unknown")."""
    if isinstance(value, bool):
        return "yes" if value else "no"
    return "" if value is None else str(value)
