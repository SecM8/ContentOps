# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Structured JSON report for `contentops apply` outcomes.

Companion to the human-readable summary table the existing
``apply_cmd`` prints. The same data, but as JSON the workflow
step (or downstream tooling) can consume without parsing the
table or re-grepping audit/*.jsonl.

The report is written *after* the audit chain is appended so
each per-asset entry can carry an ``audit_pointer`` (relative
path + 1-indexed line number) into the chained record.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from contentops.core.handler import LoadedAsset
from contentops.core.result import ActionResult, PlanAction


@dataclass
class AssetResult:
    """One row in the JSON report — mirrors the human summary table."""
    asset: str
    id: str
    action: str
    status: str
    verified: bool | None = None
    audit_pointer: str | None = None
    detail: str | None = None
    error: str | None = None


@dataclass
class Totals:
    total: int = 0
    success: int = 0
    failed: int = 0
    skipped: int = 0
    verified: int = 0
    unverified: int = 0


@dataclass
class ApplyReport:
    """Top-level JSON document written by ``apply --json-report``.

    All timestamps are UTC ISO 8601 with microsecond precision so
    they sort lexicographically.
    """
    tenant: str
    started_at: str
    finished_at: str
    duration_s: float
    sha: str
    actor: str
    workflow_run: str | None
    dry_run: bool
    results: list[AssetResult] = field(default_factory=list)
    totals: Totals = field(default_factory=Totals)


# ---------------------------------------------------------------------------
# Building
# ---------------------------------------------------------------------------


def _classify(result: ActionResult) -> str:
    """Bucket an ``ActionResult`` into success/failed/skipped.

    Mirrors the audit-record status mapping in
    ``contentops.cli.commands.apply_support._build_audit_record`` so the report
    and the audit chain agree on every per-asset row.
    """
    if result.is_failure:
        return "failed"
    if result.action is PlanAction.SKIP:
        return "skipped"
    return "success"


def _result_to_row(la: LoadedAsset, result: ActionResult) -> AssetResult:
    return AssetResult(
        asset=la.envelope.asset.value,
        id=la.envelope.id,
        action=result.action.value,
        status=_classify(result),
        verified=result.verified,
        detail=(result.detail or None),
        error=(result.error or None),
    )


def build_report(
    *,
    tenant: str,
    started_at: datetime,
    finished_at: datetime,
    sha: str,
    actor: str,
    workflow_run: str | None,
    dry_run: bool,
    pairs: Iterable[tuple],  # (la, result) or (la, result, ws_name, snippet_digest)
    audit_path: Path | None = None,
    audit_first_line: int | None = None,
) -> ApplyReport:
    """Materialise the in-memory report.

    ``pairs`` is the same ``(LoadedAsset, ActionResult)`` list the
    audit writer consumes. ``audit_path`` is the absolute path of
    the JSONL the audit writer just appended; ``audit_first_line``
    is the 1-indexed line number where this batch's records start
    (i.e. ``existing_lines + 1`` at the moment the writer was
    called). When both are present, every result row gets an
    ``audit_pointer = "<relative path>#L<line>"`` so downstream
    tooling can jump straight to the chained record.
    """
    pairs_list = list(pairs)
    rows: list[AssetResult] = []
    totals = Totals(total=len(pairs_list))
    for offset, pair in enumerate(pairs_list):
        # Tolerate both the legacy 2-tuple shape (la, result) used by
        # older callers / tests and the 4-tuple shape
        # (la, result, ws_name, snippet_digest) the apply_cmd now
        # produces. Only la and result are used here.
        la, result = pair[0], pair[1]
        row = _result_to_row(la, result)
        if audit_path is not None and audit_first_line is not None:
            line = audit_first_line + offset
            try:
                rel = audit_path.relative_to(Path.cwd())
            except ValueError:
                rel = audit_path
            # Use forward slashes so the pointer is portable across
            # OSes; Path on Windows produces backslashes by default.
            row.audit_pointer = f"{rel.as_posix()}#L{line}"
        rows.append(row)
        if row.status == "success":
            totals.success += 1
        elif row.status == "failed":
            totals.failed += 1
        elif row.status == "skipped":
            totals.skipped += 1
        if row.verified is True:
            totals.verified += 1
        elif row.verified is False:
            totals.unverified += 1
    return ApplyReport(
        tenant=tenant,
        started_at=_iso(started_at),
        finished_at=_iso(finished_at),
        duration_s=round((finished_at - started_at).total_seconds(), 3),
        sha=sha,
        actor=actor,
        workflow_run=workflow_run,
        dry_run=dry_run,
        results=rows,
        totals=totals,
    )


def _iso(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------


def to_json(report: ApplyReport) -> str:
    """Render the report as a stable, indent-2 JSON string.

    ``sort_keys=True`` so snapshots diff deterministically across runs
    — without it ``asdict`` ordering depends on dataclass definition
    order and changes whenever a field is added or reordered. All
    callers parse via ``json.loads`` so the visual reordering doesn't
    break any consumer.
    """
    payload = asdict(report)
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def write_report(report: ApplyReport, dest: Path | str) -> Path:
    """Write the report to ``dest`` (or stdout marker ``"-"``).

    Returns the resolved Path on disk write, or ``Path("-")`` when
    rendering to stdout (caller handles the actual stdout write so
    the writer doesn't fight the existing stdout stream).
    """
    if str(dest) == "-":
        return Path("-")
    target = Path(dest)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(to_json(report), encoding="utf-8")
    return target


__all__ = [
    "AssetResult",
    "Totals",
    "ApplyReport",
    "build_report",
    "to_json",
    "write_report",
]
