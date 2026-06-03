# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Forensic / compliance queries over `audit/*.jsonl`.

Companion to ``contentops.audit.writer``: the writer produces the
chain, this module reads it. Pure functions; the CLI command
group ``contentops audit query <subcommand>`` is a thin wrapper.

Mirrors the canonical jq one-liners documented in
`docs/reference/audit-trail.md` so SMs / compliance auditors can
ask the standard questions without writing jq.
"""

from __future__ import annotations

import csv
import io
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from contentops.audit_filter import iter_records, parse_since


@dataclass
class QueryRow:
    """One row across all the query subcommands. Same fields, varies
    in which are populated per subcommand."""
    timestamp: str
    asset: str
    id: str
    action: str
    status: str
    sha: str
    actor: str
    workflow_run: str | None = None
    message: str | None = None
    # Workspace + snippet_digest fields. ``None`` for pre-schema records on
    # disk and for tenant-scoped Defender records. Surfaced here so
    # ``audit query --workspace <name>`` can filter rows in
    # multi-workspace tenants (cross-phase review-2 Seam C).
    workspace: str | None = None


def _row_from(rec: dict) -> QueryRow:
    return QueryRow(
        timestamp=str(rec.get("timestamp") or ""),
        asset=str(rec.get("asset") or ""),
        id=str(rec.get("id") or ""),
        action=str(rec.get("action") or ""),
        status=str(rec.get("status") or ""),
        sha=str(rec.get("sha") or ""),
        actor=str(rec.get("actor") or ""),
        workflow_run=(str(rec["workflow_run"]) if rec.get("workflow_run") else None),
        message=(str(rec["message"]) if rec.get("message") else None),
        workspace=(str(rec["workspace"]) if rec.get("workspace") else None),
    )


def filter_by_workspace(
    rows: Iterable[QueryRow], workspace: str | None,
) -> list[QueryRow]:
    """Filter ``rows`` to those whose ``workspace`` field matches.

    Pass-through when ``workspace`` is None / empty. The match is an
    exact string compare; pre-Phase-4 records (``workspace=None``)
    are excluded when a filter is applied -- if you genuinely want
    those records, omit the flag. Cross-phase review-2 Seam C.
    """
    if not workspace:
        return list(rows)
    return [r for r in rows if r.workspace == workspace]


def _audit_files(audit_dir: Path) -> list[Path]:
    if not audit_dir.is_dir():
        return []
    return sorted(audit_dir.glob("*.jsonl"))


def _within_since(rec: dict, since: datetime | None) -> bool:
    if since is None:
        return True
    raw = rec.get("timestamp")
    if not isinstance(raw, str) or not raw:
        return False
    try:
        normalised = raw.replace("Z", "+00:00") if raw.endswith("Z") else raw
        ts = datetime.fromisoformat(normalised)
    except ValueError:
        return False
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return ts.astimezone(timezone.utc) >= since


# ---------------------------------------------------------------------------
# Subcommand implementations — each returns a list[QueryRow]
# ---------------------------------------------------------------------------


def query_latest(audit_dir: Path, asset_id: str) -> list[QueryRow]:
    """Latest record for ``asset_id`` (across all files).

    Returns a single-row list (or empty if no records).
    """
    latest: QueryRow | None = None
    latest_ts: str = ""
    for rec in iter_records(_audit_files(audit_dir)):
        if str(rec.get("id") or "") != asset_id:
            continue
        ts = str(rec.get("timestamp") or "")
        # Lexicographic compare works for the "%Y-%m-%dT%H:%M:%S.%fZ"
        # format the writer emits — same prefix, same length.
        if ts > latest_ts:
            latest_ts = ts
            latest = _row_from(rec)
    return [latest] if latest else []


def query_failures(audit_dir: Path, since_spec: str | None = None) -> list[QueryRow]:
    """All records with status=failed, optionally bounded by --since."""
    since = parse_since(since_spec) if since_spec else None
    rows = []
    for rec in iter_records(_audit_files(audit_dir)):
        if rec.get("status") != "failed":
            continue
        if not _within_since(rec, since):
            continue
        rows.append(_row_from(rec))
    rows.sort(key=lambda r: r.timestamp)
    return rows


def query_by_actor(
    audit_dir: Path, actor: str, since_spec: str | None = None,
) -> list[QueryRow]:
    """Every record by ``actor``, optionally since a window."""
    since = parse_since(since_spec) if since_spec else None
    rows = []
    for rec in iter_records(_audit_files(audit_dir)):
        if str(rec.get("actor") or "") != actor:
            continue
        if not _within_since(rec, since):
            continue
        rows.append(_row_from(rec))
    rows.sort(key=lambda r: r.timestamp)
    return rows


def query_rollbacks(
    audit_dir: Path, since_spec: str | None = None,
) -> list[QueryRow]:
    """Records produced by `contentops rollback` (their `message` carries
    the canonical 'rollback to <sha>' marker)."""
    since = parse_since(since_spec) if since_spec else None
    rows = []
    for rec in iter_records(_audit_files(audit_dir)):
        msg = str(rec.get("message") or "")
        if not msg.startswith("rollback to "):
            continue
        if not _within_since(rec, since):
            continue
        rows.append(_row_from(rec))
    rows.sort(key=lambda r: r.timestamp)
    return rows


def query_timeline(audit_dir: Path, asset_id: str) -> list[QueryRow]:
    """Every record for ``asset_id``, oldest first."""
    rows = []
    for rec in iter_records(_audit_files(audit_dir)):
        if str(rec.get("id") or "") != asset_id:
            continue
        rows.append(_row_from(rec))
    rows.sort(key=lambda r: r.timestamp)
    return rows


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

# Standard column order used by table + csv renderers. Wider columns
# (message) come last so a narrow terminal still shows the meaningful
# fields.
_TABLE_COLS = ("timestamp", "asset", "id", "action", "status", "actor",
               "sha", "workflow_run", "workspace", "message")


def render_table(rows: Iterable[QueryRow]) -> str:
    """Plain-text table; column widths sized to content."""
    rows_list = list(rows)
    if not rows_list:
        return "(no records)\n"
    widths = {c: max(len(c), 0) for c in _TABLE_COLS}
    for r in rows_list:
        for c in _TABLE_COLS:
            v = str(getattr(r, c) or "")
            widths[c] = max(widths[c], len(v))
    lines: list[str] = []
    lines.append(" ".join(c.ljust(widths[c]) for c in _TABLE_COLS))
    lines.append(" ".join("-" * widths[c] for c in _TABLE_COLS))
    for r in rows_list:
        lines.append(" ".join(
            str(getattr(r, c) or "").ljust(widths[c]) for c in _TABLE_COLS
        ))
    return "\n".join(lines) + "\n"


def render_json(rows: Iterable[QueryRow]) -> str:
    return json.dumps([asdict(r) for r in rows], indent=2) + "\n"


def render_csv(rows: Iterable[QueryRow]) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(_TABLE_COLS)
    for r in rows:
        writer.writerow([str(getattr(r, c) or "") for c in _TABLE_COLS])
    return buf.getvalue()


__all__ = [
    "QueryRow",
    "query_latest",
    "query_failures",
    "query_by_actor",
    "query_rollbacks",
    "query_timeline",
    "render_table",
    "render_json",
    "render_csv",
]
