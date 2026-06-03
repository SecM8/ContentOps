# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""``contentops silent-rules`` command (F4)."""

from __future__ import annotations

import sys
from pathlib import Path

import click


@click.command("silent-rules")
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
         "the workspace ID from. Ignored when --workspace-id is given.",
)
@click.option(
    "--since", "since_days", type=click.IntRange(min=1, max=365), default=30,
    help="Lookback window in days (default 30).",
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
    workspace_id: str | None, role: str,
    since_days: int, output_format: str, out: Path | None,
) -> None:
    """List rules that haven't fired in the lookback window (F4).

    \b
    Closes G7. Surfaces SecurityAlert + SecurityIncident counts
    per rule displayName. Rules with alerts_30d == 0 are silent
    candidates - could be (a) tuned out by an upstream change,
    (b) waiting for an attack pattern that hasn't recurred,
    (c) broken (KQL evaluates to zero rows). The pipeline can't
    distinguish, but it surfaces the candidates.

    Workspace selection: auto-derives the LA workspace GUID from
    config/tenant.yml's --role entry. Pass --workspace-id to override
    (or set PIPELINE_WORKSPACE_ID env var for the legacy code path).
    """
    import csv as _csv
    import io as _io
    import json as _json
    from contentops.utils.auth import get_credential
    from contentops.workspace_kql import (
        LA_SCOPE, WorkspaceKqlError, query, resolve_workspace_id,
        silent_rules_query,
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

    rows = result.rows
    if output_format == "json":
        rendered = _json.dumps(rows, indent=2, default=str) + "\n"
    elif output_format == "csv":
        buf = _io.StringIO()
        writer = _csv.writer(buf, lineterminator="\n")
        cols = result.column_names or (list(rows[0].keys()) if rows else [])
        writer.writerow(cols)
        for r in rows:
            writer.writerow([r.get(c) for c in cols])
        rendered = buf.getvalue()
    else:  # table
        if not rows:
            rendered = f"(no rules with telemetry in the last {since_days}d)\n"
        else:
            cols = result.column_names or list(rows[0].keys())
            widths = {c: max(len(c), max(
                (len(str(r.get(c, "") or "")) for r in rows), default=0,
            )) for c in cols}
            lines = [" ".join(c.ljust(widths[c]) for c in cols)]
            lines.append(" ".join("-" * widths[c] for c in cols))
            for r in rows:
                lines.append(" ".join(
                    str(r.get(c, "") or "").ljust(widths[c]) for c in cols
                ))
            rendered = "\n".join(lines) + "\n"

    if out is not None:
        out.write_text(rendered, encoding="utf-8")
        click.echo(f"wrote {len(rows)} row(s) to {out}", err=True)
    else:
        sys.stdout.write(rendered)
        sys.stdout.flush()
