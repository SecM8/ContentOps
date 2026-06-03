# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""``contentops upstream`` group: catalog upstream-watchers (G3 + G4).

Two subcommands diff Microsoft's published catalog of Content Packages
(``check-marketplace``) and Alert Rule Templates (``check-templates``)
against a committed baseline manifest. Without ``--write`` they print
the diff; with ``--write`` they update the manifest in-place and
append a markdown row to ``docs/whats-new/<YYYY-MM-DD>.md`` when the
diff is non-empty. The scheduled
``.github/workflows/upstream-watchers.yml`` runs both with ``--write``
weekly and opens a PR via ``peter-evans/create-pull-request`` when
``git status --porcelain`` shows any change.
"""

from __future__ import annotations

import datetime as _dt
import sys
from pathlib import Path
from typing import Callable

import click
import httpx

from contentops.cli.commands._shared import _resolve_single_workspace_or_exit
from contentops.upstream.manifest import (
    ManifestDiff,
    compute_diff,
    load_manifest,
    write_manifest,
)
from contentops.upstream.whatsnew import render_markdown


DEFAULT_MARKETPLACE_MANIFEST = Path("manifests") / "upstream_marketplace.json"
DEFAULT_TEMPLATES_MANIFEST = Path("manifests") / "upstream_templates.json"
DEFAULT_SCHEMAS_MANIFEST = Path("tools") / "kql_strict" / "schemas.json"
DEFAULT_WHATSNEW_DIR = Path("docs") / "whats-new"
SCHEMAS_DATABASE_NAME = "SentinelDefender"


def _print_diff(label: str, diff: ManifestDiff) -> None:
    click.echo(f"\n{label}:")
    if diff.is_empty:
        click.echo("  (no changes)")
        return
    if diff.added:
        click.echo(f"  added ({len(diff.added)}):")
        for e in diff.added:
            v = f" v{e.get('version') or '?'}" if e.get("version") else ""
            click.echo(f"    + {e.get('name')}  {e.get('displayName')}{v}")
    if diff.changed:
        click.echo(f"  changed ({len(diff.changed)}):")
        for old, new in diff.changed:
            click.echo(
                f"    ~ {new.get('name')}  "
                f"{old.get('version') or '?'} -> {new.get('version') or '?'}"
            )
    if diff.removed:
        click.echo(f"  removed ({len(diff.removed)}):")
        for e in diff.removed:
            click.echo(f"    - {e.get('name')}  {e.get('displayName')}")


def _maybe_write_whatsnew(
    diffs_by_source: dict[str, ManifestDiff],
    *,
    out_dir: Path,
    date: str,
) -> Path | None:
    """Write the WHATSNEW markdown when any diff is non-empty.

    Returns the written path or None when every diff was empty.
    """
    if all(d.is_empty for d in diffs_by_source.values()):
        return None
    body = render_markdown(date, diffs_by_source)
    out_dir.mkdir(parents=True, exist_ok=True)
    target = out_dir / f"{date}.md"
    target.write_text(body, encoding="utf-8")
    return target


def _run_watcher(
    *,
    source_label: str,
    fetch_fn: Callable[..., list[dict]],
    manifest_path: Path,
    write: bool,
    whatsnew_dir: Path,
) -> int:
    """Shared body for both ``check-marketplace`` and ``check-templates``.

    Returns the process exit code (always 0 on success — workflow looks
    for `git status --porcelain` to decide whether to open a PR).
    """
    from contentops.providers.sentinel_arm import SentinelArmProvider

    provider = SentinelArmProvider.from_env()
    try:
        new_entries = fetch_fn(provider)
    finally:
        provider.close()

    old_entries = load_manifest(manifest_path)
    diff = compute_diff(old_entries, new_entries)
    _print_diff(source_label, diff)

    if not write:
        return 0

    if diff.is_empty:
        click.echo(f"\n{source_label}: no changes; manifest unchanged.")
        return 0

    write_manifest(manifest_path, new_entries)
    click.echo(f"\n{source_label}: wrote {manifest_path}")

    target = _maybe_write_whatsnew(
        {source_label: diff},
        out_dir=whatsnew_dir,
        date=_dt.date.today().isoformat(),
    )
    if target:
        click.echo(f"{source_label}: wrote {target}")
    return 0


# ---------------------------------------------------------------------------
# Schemas (F1.1) — different on-disk shape than marketplace/templates
# ---------------------------------------------------------------------------


def _load_schemas_tables(path: Path) -> list[dict]:
    """Read the `tables` list out of a schemas.json baseline.

    Returns an empty list when the file is missing OR empty OR shaped
    differently from what the wrapper expects. The wrapper itself
    gracefully degrades in the same cases, so a partial read won't
    break the lint pipeline.
    """
    if not path.exists():
        return []
    import json as _json
    text = path.read_text(encoding="utf-8")
    if not text.strip():
        return []
    data = _json.loads(text)
    if not isinstance(data, dict):
        raise ValueError(f"{path}: top-level JSON is not an object")
    tables = data.get("tables") or []
    if not isinstance(tables, list):
        raise ValueError(f"{path}: 'tables' is not a list")
    return tables


def _write_schemas_manifest(
    path: Path, *,
    database: str,
    tables: list[dict],
) -> None:
    """Serialise tables to schemas.json in the wrapper-friendly shape.

    Wraps the tables list with ``schema_version``+``database`` so the C#
    wrapper at ``tools/kql_strict/Program.cs`` can read it directly to
    build ``DatabaseSymbol(database, tables)``.
    """
    import json as _json
    sorted_tables = sorted(tables, key=lambda t: str(t.get("name") or ""))
    payload = {
        "schema_version": 1,
        "database": database,
        "tables": sorted_tables,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        _json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


@click.group("upstream")
def upstream_group() -> None:
    """Upstream-catalog watchers (G3 + G4 + F1.1).

    Diff Microsoft's Sentinel catalog of Content Packages, Alert Rule
    Templates, and Log Analytics workspace table schemas against the
    committed baselines. Weekly schedule runs marketplace+templates;
    a separate nightly schedule runs schemas.
    """


@upstream_group.command("check-marketplace")
@click.option(
    "--write", "write_changes", is_flag=True, default=False,
    help="Write the updated manifest + WHATSNEW row instead of dry-running.",
)
@click.option(
    "--manifest", "manifest_path",
    type=click.Path(path_type=Path), default=DEFAULT_MARKETPLACE_MANIFEST,
    show_default=True,
    help="Manifest path. Override for tests / alt baselines.",
)
@click.option(
    "--out", "whatsnew_dir",
    type=click.Path(path_type=Path), default=DEFAULT_WHATSNEW_DIR,
    show_default=True,
    help="Directory for WHATSNEW markdown files (one per day).",
)
@click.option(
    "--role",
    type=click.Choice(["prod", "integration", "dev", "test"]),
    default=None,
    help="Workspace role to query (sets PIPELINE_WORKSPACE_NAME). "
         "Single-workspace tenants pick implicitly.",
)
@click.option(
    "--workspace", "workspace_name",
    default=None,
    help="Workspace name override (mutex with --role).",
)
def check_marketplace_cmd(
    write_changes: bool,
    manifest_path: Path,
    whatsnew_dir: Path,
    role: str | None,
    workspace_name: str | None,
) -> None:
    """Diff `contentPackages` against the committed manifest (closes G3)."""
    from contentops.upstream.marketplace import fetch_packages
    _resolve_single_workspace_or_exit(role, workspace_name)
    sys.exit(_run_watcher(
        source_label="Content Packages",
        fetch_fn=fetch_packages,
        manifest_path=manifest_path,
        write=write_changes,
        whatsnew_dir=whatsnew_dir,
    ))


@upstream_group.command("check-templates")
@click.option(
    "--write", "write_changes", is_flag=True, default=False,
    help="Write the updated manifest + WHATSNEW row instead of dry-running.",
)
@click.option(
    "--manifest", "manifest_path",
    type=click.Path(path_type=Path), default=DEFAULT_TEMPLATES_MANIFEST,
    show_default=True,
)
@click.option(
    "--out", "whatsnew_dir",
    type=click.Path(path_type=Path), default=DEFAULT_WHATSNEW_DIR,
    show_default=True,
)
@click.option(
    "--role",
    type=click.Choice(["prod", "integration", "dev", "test"]),
    default=None,
)
@click.option(
    "--workspace", "workspace_name", default=None,
)
def check_templates_cmd(
    write_changes: bool,
    manifest_path: Path,
    whatsnew_dir: Path,
    role: str | None,
    workspace_name: str | None,
) -> None:
    """Diff `alertRuleTemplates` against the committed manifest (closes G4)."""
    from contentops.upstream.templates import fetch_templates
    _resolve_single_workspace_or_exit(role, workspace_name)
    sys.exit(_run_watcher(
        source_label="Alert Rule Templates",
        fetch_fn=fetch_templates,
        manifest_path=manifest_path,
        write=write_changes,
        whatsnew_dir=whatsnew_dir,
    ))


@upstream_group.command("check-schemas")
@click.option(
    "--write", "write_changes", is_flag=True, default=False,
    help="Write the updated schemas.json + WHATSNEW row instead of dry-running.",
)
@click.option(
    "--schemas", "schemas_path",
    type=click.Path(path_type=Path), default=DEFAULT_SCHEMAS_MANIFEST,
    show_default=True,
    help="Schemas baseline path read by the kql_strict wrapper.",
)
@click.option(
    "--out", "whatsnew_dir",
    type=click.Path(path_type=Path), default=DEFAULT_WHATSNEW_DIR,
    show_default=True,
)
@click.option(
    "--workspace-id", "workspace_id",
    envvar="PIPELINE_WORKSPACE_ID",
    default=None,
    help="LA workspace ID (GUID). Defaults to the PIPELINE_WORKSPACE_ID "
         "env var; required either way.",
)
@click.option(
    "--database", "database_name",
    default=SCHEMAS_DATABASE_NAME, show_default=True,
    help="Database name written into schemas.json; the C# wrapper "
         "uses it to construct the Kusto.Language DatabaseSymbol.",
)
def check_schemas_cmd(
    write_changes: bool,
    schemas_path: Path,
    whatsnew_dir: Path,
    workspace_id: str | None,
    database_name: str,
) -> None:
    """Diff LA workspace table schemas against the kql_strict baseline (F1.1).

    Hits the Log Analytics Query API metadata endpoint
    (`/v1/workspaces/<id>/metadata`) which returns every connected
    table -- including the Defender XDR pseudo-tables surfaced via the
    M365 Defender connector. A single fetch covers both halves of the
    schema surface.

    Respects ``config/lint_strict.yml``: a no-op when
    ``sentinel.enabled: false`` OR ``mode: off``.
    """
    from contentops.lint.strict_config import load_lint_strict_config

    config, info = load_lint_strict_config()
    if info:
        click.echo(f"info: {info}", err=True)
    if config.mode == "off":
        click.echo(
            "check-schemas: lint_strict mode=off; refresh skipped.",
            err=True,
        )
        sys.exit(0)
    if not config.sentinel_enabled:
        click.echo(
            "check-schemas: sentinel.enabled=false in config/lint_strict.yml; "
            "refresh skipped.",
            err=True,
        )
        sys.exit(0)

    from contentops.upstream.schemas import fetch_schemas
    from contentops.utils.auth import get_credential
    from contentops.workspace_kql import (
        LA_SCOPE, WorkspaceKqlError, resolve_workspace_id,
    )

    try:
        cred = get_credential()
    except Exception as exc:
        click.echo(f"error: credential acquisition failed: {exc}", err=True)
        sys.exit(1)

    if not workspace_id:
        try:
            workspace_id = resolve_workspace_id(role="prod", credential=cred)
        except WorkspaceKqlError as exc:
            click.echo(f"error: {exc}", err=True)
            sys.exit(1)

    try:
        token = cred.get_token(LA_SCOPE).token
    except Exception as exc:
        click.echo(f"error: token acquisition failed: {exc}", err=True)
        sys.exit(1)

    try:
        new_tables = fetch_schemas(workspace_id=workspace_id, token=token)
    except WorkspaceKqlError as exc:
        click.echo(f"error: {exc}", err=True)
        sys.exit(1)
    except httpx.HTTPError as exc:
        click.echo(f"error: LA metadata fetch failed: {exc}", err=True)
        sys.exit(1)

    # Drop operator scratch / test tables (config.schema_exclude_tables) so
    # they never reach the committed, publicly-mirrored schemas.json.
    from contentops.upstream.schemas import filter_excluded_tables
    new_tables, excluded = filter_excluded_tables(
        new_tables, config.schema_exclude_tables,
    )
    if excluded:
        click.echo(
            f"excluded {len(excluded)} table(s) per "
            f"config/lint_strict.yml schema_exclude_tables: "
            f"{', '.join(sorted(excluded))}",
            err=True,
        )

    old_tables = _load_schemas_tables(schemas_path)
    diff = compute_diff(old_tables, new_tables)

    label = "KQL workspace schemas"
    _print_diff(label, diff)

    if not write_changes:
        sys.exit(0)

    if diff.is_empty:
        click.echo(f"\n{label}: no changes; {schemas_path} unchanged.")
        sys.exit(0)

    _write_schemas_manifest(
        schemas_path, database=database_name, tables=new_tables,
    )
    click.echo(f"\n{label}: wrote {schemas_path}")

    import datetime as _dt2
    today = _dt2.date.today().isoformat()
    target = whatsnew_dir / f"{today}-schemas.md"
    body = render_markdown(today, {label: diff})
    whatsnew_dir.mkdir(parents=True, exist_ok=True)
    target.write_text(body, encoding="utf-8")
    click.echo(f"{label}: wrote {target}")
    sys.exit(0)


DEFAULT_DEFENDER_SCHEMAS_MANIFEST = Path("tools") / "kql_strict" / "schemas_defender.json"


@upstream_group.command("check-defender-schema")
@click.option(
    "--write", "write_changes", is_flag=True, default=False,
    help="Write the updated schemas_defender.json + WHATSNEW row instead of dry-running.",
)
@click.option(
    "--schemas", "schemas_path",
    type=click.Path(path_type=Path), default=DEFAULT_DEFENDER_SCHEMAS_MANIFEST,
    show_default=True,
    help="Defender schemas baseline path read by the kql_strict wrapper.",
)
@click.option(
    "--out", "whatsnew_dir",
    type=click.Path(path_type=Path), default=DEFAULT_WHATSNEW_DIR,
    show_default=True,
)
@click.option(
    "--database", "database_name",
    default=SCHEMAS_DATABASE_NAME, show_default=True,
)
def check_defender_schema_cmd(
    write_changes: bool,
    schemas_path: Path,
    whatsnew_dir: Path,
    database_name: str,
) -> None:
    """Refresh schemas_defender.json from Graph Advanced Hunting (F1.1 follow-up).

    For each table name already in ``schemas_defender.json`` (the
    vendored file is its own discovery anchor), runs
    ``<table> | getschema | project ColumnName, ColumnType``
    via ``POST /v1.0/security/runHuntingQuery`` and replaces the
    table's column list with the refreshed result. Tables that
    return 404 (table not in this tenant's Defender entitlement)
    keep their existing baseline columns -- the refresh never
    silently drops a vendored table.

    Required Graph permission: ``ThreatHunting.Read.All``
    (application scope; manual admin consent on the App
    Registration -- see docs/operations/authentication-setup.md).

    Respects ``config/lint_strict.yml``: a no-op when
    ``defender.enabled: false`` OR ``mode: off``.
    """
    from contentops.lint.strict_config import load_lint_strict_config

    config, info = load_lint_strict_config()
    if info:
        click.echo(f"info: {info}", err=True)
    if config.mode == "off":
        click.echo(
            "check-defender-schema: lint_strict mode=off; refresh skipped.",
            err=True,
        )
        sys.exit(0)
    if not config.defender_enabled:
        click.echo(
            "check-defender-schema: defender.enabled=false in "
            "config/lint_strict.yml; refresh skipped.",
            err=True,
        )
        sys.exit(0)

    from contentops.upstream.defender_schema import (
        DefenderSchemaError,
        fetch_defender_schemas,
    )
    from contentops.utils.auth import get_credential

    if not schemas_path.exists():
        click.echo(
            f"error: {schemas_path} not found. The Defender baseline must "
            "exist in-tree before refresh can run (the file IS the seed "
            "list). Add new tables by hand first; then refresh.",
            err=True,
        )
        sys.exit(1)

    old_tables = _load_schemas_tables(schemas_path)
    if not old_tables:
        click.echo(
            f"error: {schemas_path} carries no tables to refresh.",
            err=True,
        )
        sys.exit(1)
    seed_names = [str(t.get("name") or "") for t in old_tables if t.get("name")]

    try:
        credential = get_credential()
    except Exception as exc:
        click.echo(f"error: credential acquisition failed: {exc}", err=True)
        sys.exit(1)

    try:
        refreshed, skipped = fetch_defender_schemas(
            seed_names, credential=credential,
        )
    except DefenderSchemaError as exc:
        click.echo(f"error: {exc}", err=True)
        sys.exit(1)

    # Preserve baseline columns for tables Graph couldn't fetch
    # (e.g. tenant entitlement gap).
    by_name = {t["name"]: t for t in old_tables}
    merged: list[dict] = []
    for entry in refreshed:
        merged.append(entry)
    for name in skipped:
        if name in by_name:
            merged.append(by_name[name])
            click.echo(
                f"check-defender-schema: kept baseline columns for "
                f"{name!r} (Graph 404; tenant entitlement gap).",
                err=True,
            )

    diff = compute_diff(old_tables, merged)
    label = "Defender XDR schemas"
    _print_diff(label, diff)

    if not write_changes:
        sys.exit(0)

    if diff.is_empty:
        click.echo(f"\n{label}: no changes; {schemas_path} unchanged.")
        sys.exit(0)

    _write_schemas_manifest(
        schemas_path, database=database_name, tables=merged,
    )
    click.echo(f"\n{label}: wrote {schemas_path}")

    import datetime as _dt3
    today = _dt3.date.today().isoformat()
    target = whatsnew_dir / f"{today}-defender-schemas.md"
    body = render_markdown(today, {label: diff})
    whatsnew_dir.mkdir(parents=True, exist_ok=True)
    target.write_text(body, encoding="utf-8")
    click.echo(f"{label}: wrote {target}")
    sys.exit(0)


@upstream_group.command("pre-pr-refresh")
@click.option(
    "--sentinel-schemas", "sentinel_schemas_path",
    type=click.Path(path_type=Path), default=DEFAULT_SCHEMAS_MANIFEST,
    show_default=True,
)
@click.option(
    "--defender-schemas", "defender_schemas_path",
    type=click.Path(path_type=Path), default=DEFAULT_DEFENDER_SCHEMAS_MANIFEST,
    show_default=True,
)
@click.option(
    "--workspace-id", "workspace_id",
    envvar="PIPELINE_WORKSPACE_ID", default=None,
)
def pre_pr_refresh_cmd(
    sentinel_schemas_path: Path,
    defender_schemas_path: Path,
    workspace_id: str | None,
) -> None:
    """One-shot pre-PR refresh: runs both check-schemas commands when allowed.

    Single entry point used by ``validate.yml`` so the workflow YAML
    doesn't have to read ``config/lint_strict.yml`` itself. Behaviour:

      * ``mode: off``                  -> exit 0; both refreshes skipped.
      * ``refresh_on_pr: false``       -> exit 0; both refreshes skipped.
      * ``sentinel.enabled: false``    -> Sentinel refresh skipped; Defender still runs.
      * ``defender.enabled: false``    -> Defender refresh skipped; Sentinel still runs.

    Best-effort: a failure on one side never stops the other, and
    overall exit is always 0 so a transient Graph / LA hiccup can't
    block unrelated PRs.
    """
    from contentops.lint.strict_config import load_lint_strict_config

    config, info = load_lint_strict_config()
    if info:
        click.echo(f"info: {info}", err=True)
    if config.mode == "off":
        click.echo(
            "pre-pr-refresh: lint_strict mode=off; both refreshes skipped.",
            err=True,
        )
        sys.exit(0)
    if not config.refresh_on_pr:
        click.echo(
            "pre-pr-refresh: refresh_on_pr=false; both refreshes skipped.",
            err=True,
        )
        sys.exit(0)

    # Sentinel side --------------------------------------------------------
    if not config.sentinel_enabled:
        click.echo(
            "pre-pr-refresh: sentinel.enabled=false; Sentinel refresh skipped.",
            err=True,
        )
    else:
        from contentops.upstream.schemas import fetch_schemas
        from contentops.utils.auth import get_credential
        from contentops.workspace_kql import (
            LA_SCOPE, WorkspaceKqlError, resolve_workspace_id,
        )
        try:
            cred = get_credential()
            if not workspace_id:
                workspace_id = resolve_workspace_id(
                    role="prod", credential=cred,
                )
            token = cred.get_token(LA_SCOPE).token
            new_tables = fetch_schemas(workspace_id=workspace_id, token=token)
            _write_schemas_manifest(
                sentinel_schemas_path,
                database=SCHEMAS_DATABASE_NAME,
                tables=new_tables,
            )
            click.echo(
                f"pre-pr-refresh: refreshed {sentinel_schemas_path} "
                f"({len(new_tables)} tables).",
                err=True,
            )
        except (WorkspaceKqlError, httpx.HTTPError, Exception) as exc:
            click.echo(
                f"pre-pr-refresh: Sentinel refresh failed ({exc}); "
                "lint will use the committed baseline.",
                err=True,
            )

    # Defender side --------------------------------------------------------
    if not config.defender_enabled:
        click.echo(
            "pre-pr-refresh: defender.enabled=false; Defender refresh skipped.",
            err=True,
        )
    elif not defender_schemas_path.exists():
        click.echo(
            f"pre-pr-refresh: {defender_schemas_path} not found; "
            "Defender refresh skipped (no seed list).",
            err=True,
        )
    else:
        from contentops.upstream.defender_schema import (
            DefenderSchemaError, fetch_defender_schemas,
        )
        from contentops.utils.auth import get_credential
        try:
            old_tables = _load_schemas_tables(defender_schemas_path)
            seed_names = [str(t.get("name") or "") for t in old_tables if t.get("name")]
            credential = get_credential()
            refreshed, skipped = fetch_defender_schemas(
                seed_names, credential=credential,
            )
            by_name = {t["name"]: t for t in old_tables}
            merged: list[dict] = list(refreshed)
            for name in skipped:
                if name in by_name:
                    merged.append(by_name[name])
            _write_schemas_manifest(
                defender_schemas_path,
                database=SCHEMAS_DATABASE_NAME,
                tables=merged,
            )
            click.echo(
                f"pre-pr-refresh: refreshed {defender_schemas_path} "
                f"({len(merged)} tables, {len(skipped)} preserved from baseline).",
                err=True,
            )
        except (DefenderSchemaError, Exception) as exc:
            click.echo(
                f"pre-pr-refresh: Defender refresh failed ({exc}); "
                "lint will use the committed baseline.",
                err=True,
            )

    sys.exit(0)


__all__ = [
    "upstream_group",
    "check_marketplace_cmd",
    "check_templates_cmd",
    "check_schemas_cmd",
    "check_defender_schema_cmd",
    "pre_pr_refresh_cmd",
    "DEFAULT_MARKETPLACE_MANIFEST",
    "DEFAULT_TEMPLATES_MANIFEST",
    "DEFAULT_SCHEMAS_MANIFEST",
    "DEFAULT_DEFENDER_SCHEMAS_MANIFEST",
    "DEFAULT_WHATSNEW_DIR",
    "SCHEMAS_DATABASE_NAME",
]
