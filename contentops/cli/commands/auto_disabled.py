# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""``contentops auto-disabled-rules`` command (NVISO Part 7).

Surfaces alert rules that Sentinel itself has disabled — distinct from
``silent-rules``, which finds rules that simply produced no alerts.
A disabled rule means the platform stepped in (consecutive query
failures, ingest schema break, deprecated table reference); a silent
rule may just be waiting for the right behaviour to trigger.

Prerequisite: ``SentinelHealth`` diagnostic data collection must be
enabled on the workspace. When it isn't, the SentinelHealth branch of
the union returns zero rows silently — no way to differentiate "all
rules healthy" from "diagnostic disabled" without a side check. The
``--require-data`` flag exits non-zero when the query returns no rows,
which gives CI a way to fail loud if the diagnostic was turned off.
"""

from __future__ import annotations

import sys
from pathlib import Path

import click


@click.command("auto-disabled-rules")
@click.option(
    "--workspace-id", "workspace_id",
    envvar="PIPELINE_WORKSPACE_ID",
    default=None,
    help="Log Analytics workspace ID (GUID). Defaults to auto-derive from tenant.yml.",
)
@click.option(
    "--role",
    type=click.Choice(["prod", "integration", "dev", "test"]),
    default="prod", show_default=True,
    help="Tenant role to resolve the workspace from. Ignored when --workspace-id is given.",
)
@click.option(
    "--since", "since_days", type=click.IntRange(min=1, max=365), default=7, show_default=True,
    help="Lookback window in days. Shorter than silent-rules (30d) because "
         "auto-disable is a sharper signal -- a stale 'Disabled' event from "
         "weeks ago is usually already known.",
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
@click.option(
    "--require-data/--no-require-data", default=False, show_default=True,
    help="Exit non-zero when the query returns zero rows. Use in CI to catch "
         "the case where SentinelHealth diagnostic was disabled, hiding "
         "auto-disable signals. Default is permissive (zero rows is fine).",
)
def auto_disabled_rules_cmd(
    workspace_id: str | None, role: str,
    since_days: int, output_format: str, out: Path | None,
    require_data: bool,
) -> None:
    """List Sentinel-side disabled rules + recent query failures (NVISO Part 7)."""
    import csv as _csv
    import io as _io
    import json as _json

    from contentops.utils.auth import get_credential
    from contentops.workspace_kql import (
        LA_SCOPE, WorkspaceKqlError, auto_disabled_query, query,
        resolve_workspace_id,
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
            auto_disabled_query(since_days=since_days),
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
            rendered = (
                f"(no auto-disabled rules / query failures in the last "
                f"{since_days}d)\n"
                f"\n"
                f"Note: SentinelHealth diagnostic data collection must be "
                f"enabled on the workspace for the Disabled / Failure signal "
                f"to appear here. See "
                f"https://learn.microsoft.com/en-us/azure/sentinel/health-audit\n"
            )
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

    if require_data and not rows:
        click.echo(
            "error: --require-data is set and the query returned zero rows. "
            "Verify SentinelHealth diagnostic is enabled on the workspace.",
            err=True,
        )
        sys.exit(2)


__all__ = ["auto_disabled_rules_cmd"]
