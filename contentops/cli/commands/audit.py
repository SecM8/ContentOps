# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""``audit verify``, ``audit head``, and ``audit query <subcommand>`` (F18)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from contentops.audit import head_summary, verify_chain


@click.group("audit")
def audit_group() -> None:
    """Audit-trail commands."""


@audit_group.command("verify")
@click.option(
    "--root",
    type=click.Path(path_type=Path),
    default=Path("."),
    help="Repository root containing the `audit/` directory.",
)
@click.option(
    "--require-min-files",
    type=click.IntRange(min=0),
    default=0,
    show_default=True,
    help=(
        "Fail (exit 1) when fewer than N audit files are present. Default 0 "
        "(no floor) so fresh checkouts / e2e fixtures with an empty or absent "
        "audit/ still verify cleanly. CI's weekly chain-integrity gate passes "
        "--require-min-files 1 so a wiped or deleted trail can't false-green."
    ),
)
def audit_verify_cmd(root: Path, require_min_files: int) -> None:
    """Verify hash-chain integrity of `audit/*.jsonl`.

    Exits 0 when all present audit files verify with no breaks; 1 when any
    chain break is found, or when ``--require-min-files N`` is set and fewer
    than N files are present (so the weekly workflow treats a wiped/missing
    trail as a hard failure while local and e2e runs stay flexible).
    """
    result = verify_chain(root)
    click.echo(
        f"audit chain: {result.files_checked} file(s), "
        f"{result.records_verified} record(s) verified, "
        f"{len(result.breaks)} break(s)"
    )
    # Opt-in floor: only the weekly workflow passes --require-min-files, so a
    # wiped/missing trail fails there, while fresh checkouts and e2e fixtures
    # (empty or absent audit/) keep verifying cleanly by default.
    if require_min_files and result.files_checked < require_min_files:
        click.echo(
            f"error: audit chain has {result.files_checked} file(s) but "
            f"--require-min-files={require_min_files} — a wiped or missing "
            "trail must not pass.",
            err=True,
        )
        sys.exit(1)
    for b in result.breaks:
        click.echo(
            f"  {b.file}:{b.line_number} {b.reason} "
            f"expected_prev={b.expected_prev_hash[:12]} "
            f"actual_prev={b.actual_prev_hash[:12]}"
        )
    if result.breaks:
        sys.exit(1)


@audit_group.command("head")
@click.option(
    "--root",
    type=click.Path(path_type=Path),
    default=Path("."),
    help="Repository root containing the `audit/` directory.",
)
@click.option(
    "--out",
    type=click.Path(path_type=Path),
    default=None,
    help="Write the JSON summary to this path instead of stdout.",
)
def audit_head_cmd(root: Path, out: Path | None) -> None:
    """Emit the audit-chain head summary as JSON (for attestation).

    Prints {head_hash, tail_timestamp, files_checked, records_verified,
    chain_breaks, verified}. The deploy workflow writes this to
    audit-head.json and attests it with GitHub Artifact Attestations so a
    third party can verify (via `gh attestation verify audit-head.json
    --owner KustoKing`) that a given CI run produced this chain head.

    The audit trail is artifact-only (gitignored), so the head describes
    THIS run's records (provenance), not a cumulative ledger -- see
    SECURITY.md for the boundary.
    """
    payload = head_summary(root)
    text = json.dumps(payload, indent=2, sort_keys=False) + "\n"
    if out is None:
        sys.stdout.write(text)
        sys.stdout.flush()
    else:
        out.write_text(text, encoding="utf-8")
        click.echo(f"wrote audit head summary to {out}", err=True)


# ---------------------------------------------------------------------------
# audit query <subcommand> — F18
# ---------------------------------------------------------------------------


@audit_group.group("query")
def audit_query_group() -> None:
    """Forensic / compliance queries over the audit chain.

    Surfaces the canonical "who/when/what" questions from
    docs/reference/audit-trail.md as named subcommands so SMs and
    compliance auditors don't need jq.
    """


_DEFAULT_AUDIT_DIR = Path("audit")
_FORMATS = click.Choice(["table", "json", "csv"])

# Shared --workspace option applied to every ``audit query`` subcommand.
# Cross-phase review-2 Seam C: in a multi-workspace tenant, an auditor
# scoping ``failures`` or ``timeline`` to one workspace shouldn't have
# to grep the rendered output -- the filter sits at the query layer.
_WORKSPACE_OPTION = click.option(
    "--workspace", "workspace",
    default=None,
    help="Filter rows to records whose AuditRecord.workspace matches "
         "this exact name. Pre-Phase-4 records (workspace=None) are "
         "excluded when this flag is set; omit for the un-filtered "
         "view.",
)


def _emit(rows, output_format: str, out: Path | None) -> None:
    """Render `rows` and either print or write."""
    from contentops.audit_query import render_csv, render_json, render_table
    renderer = {
        "table": render_table, "json": render_json, "csv": render_csv,
    }[output_format]
    text = renderer(rows)
    if out is None:
        sys.stdout.write(text)
        sys.stdout.flush()
    else:
        out.write_text(text, encoding="utf-8")
        click.echo(f"wrote {len(list(rows))} row(s) to {out}", err=True)


@audit_query_group.command("latest")
@click.argument("asset_id")
@click.option(
    "--audit-dir", type=click.Path(path_type=Path),
    default=_DEFAULT_AUDIT_DIR,
)
@click.option("--format", "output_format", type=_FORMATS, default="table")
@click.option(
    "--out", type=click.Path(path_type=Path), default=None,
    help="Write to this file instead of stdout.",
)
@_WORKSPACE_OPTION
def audit_query_latest(
    asset_id: str, audit_dir: Path, output_format: str,
    out: Path | None, workspace: str | None,
) -> None:
    """Latest record for ASSET_ID across the chain."""
    from contentops.audit_query import filter_by_workspace, query_latest
    rows = filter_by_workspace(query_latest(audit_dir, asset_id), workspace)
    _emit(rows, output_format, out)


@audit_query_group.command("failures")
@click.option("--since", "since_spec", default=None,
              help="Duration ('1h'/'7d') or ISO 8601 timestamp.")
@click.option(
    "--audit-dir", type=click.Path(path_type=Path),
    default=_DEFAULT_AUDIT_DIR,
)
@click.option("--format", "output_format", type=_FORMATS, default="table")
@click.option(
    "--out", type=click.Path(path_type=Path), default=None,
    help="Write to this file instead of stdout.",
)
@_WORKSPACE_OPTION
def audit_query_failures(
    since_spec: str | None, audit_dir: Path,
    output_format: str, out: Path | None, workspace: str | None,
) -> None:
    """All records with status=failed, optionally bounded by --since."""
    from contentops.audit_filter import AuditFilterError
    from contentops.audit_query import filter_by_workspace, query_failures
    try:
        rows = filter_by_workspace(
            query_failures(audit_dir, since_spec), workspace,
        )
    except AuditFilterError as exc:
        click.echo(f"error: {exc}", err=True)
        sys.exit(2)
    _emit(rows, output_format, out)


@audit_query_group.command("by-actor")
@click.argument("actor")
@click.option("--since", "since_spec", default=None,
              help="Duration ('1h'/'7d') or ISO 8601 timestamp.")
@click.option(
    "--audit-dir", type=click.Path(path_type=Path),
    default=_DEFAULT_AUDIT_DIR,
)
@click.option("--format", "output_format", type=_FORMATS, default="table")
@click.option(
    "--out", type=click.Path(path_type=Path), default=None,
    help="Write to this file instead of stdout.",
)
@_WORKSPACE_OPTION
def audit_query_by_actor(
    actor: str, since_spec: str | None, audit_dir: Path,
    output_format: str, out: Path | None, workspace: str | None,
) -> None:
    """Every record by ACTOR (GITHUB_ACTOR / USER / USERNAME field)."""
    from contentops.audit_filter import AuditFilterError
    from contentops.audit_query import filter_by_workspace, query_by_actor
    try:
        rows = filter_by_workspace(
            query_by_actor(audit_dir, actor, since_spec), workspace,
        )
    except AuditFilterError as exc:
        click.echo(f"error: {exc}", err=True)
        sys.exit(2)
    _emit(rows, output_format, out)


@audit_query_group.command("rollbacks")
@click.option("--since", "since_spec", default=None,
              help="Duration ('1h'/'7d') or ISO 8601 timestamp.")
@click.option(
    "--audit-dir", type=click.Path(path_type=Path),
    default=_DEFAULT_AUDIT_DIR,
)
@click.option("--format", "output_format", type=_FORMATS, default="table")
@click.option(
    "--out", type=click.Path(path_type=Path), default=None,
    help="Write to this file instead of stdout.",
)
@_WORKSPACE_OPTION
def audit_query_rollbacks(
    since_spec: str | None, audit_dir: Path,
    output_format: str, out: Path | None, workspace: str | None,
) -> None:
    """Records produced by `contentops rollback` (message starts with 'rollback to ')."""
    from contentops.audit_filter import AuditFilterError
    from contentops.audit_query import filter_by_workspace, query_rollbacks
    try:
        rows = filter_by_workspace(
            query_rollbacks(audit_dir, since_spec), workspace,
        )
    except AuditFilterError as exc:
        click.echo(f"error: {exc}", err=True)
        sys.exit(2)
    _emit(rows, output_format, out)


@audit_query_group.command("timeline")
@click.argument("asset_id")
@click.option(
    "--audit-dir", type=click.Path(path_type=Path),
    default=_DEFAULT_AUDIT_DIR,
)
@click.option("--format", "output_format", type=_FORMATS, default="table")
@click.option(
    "--out", type=click.Path(path_type=Path), default=None,
    help="Write to this file instead of stdout.",
)
@_WORKSPACE_OPTION
def audit_query_timeline(
    asset_id: str, audit_dir: Path, output_format: str,
    out: Path | None, workspace: str | None,
) -> None:
    """Every record for ASSET_ID, oldest first."""
    from contentops.audit_query import filter_by_workspace, query_timeline
    rows = filter_by_workspace(
        query_timeline(audit_dir, asset_id), workspace,
    )
    _emit(rows, output_format, out)
