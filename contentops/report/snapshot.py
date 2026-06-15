# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""JSON snapshot for the detection inventory report.

The HTML / Markdown renderers produce human-readable output; this
module emits a structured JSON that the next-run can DIFF against
to compute week-over-week deltas. Committed to ``reports/latest.json``
(replaced each run) and ``reports/<YYYY-MM-DD>.json`` (dated, so
history accumulates).

Schema is intentionally narrow — only the fields a delta computation
needs (rule_id, status, severity, techniques, MITRE coverage levels).
Wider data the HTML report consumes (display name, runbook URL,
owner) is NOT included to keep the snapshot diff-friendly: a CFO
caring "+3 rules this week" doesn't care that one of them got its
title re-cased.

Pure functions; no network / no git.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path

from contentops.report.assemble import ReportRow, ReportSummary

logger = logging.getLogger(__name__)


SCHEMA_VERSION = 1


def render_snapshot(rows: list[ReportRow], summary: ReportSummary) -> str:
    """Render the JSON snapshot for a report run.

    Stable shape — additive only. ``schema_version`` bumps if any
    field changes meaning. Sorted keys + indent=2 so the committed
    diff is reviewable.
    """
    payload = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": summary.generated_at,
        "summary": {
            "total": summary.total,
            "production": summary.production,
            "experimental": summary.experimental,
            "deprecated": summary.deprecated,
            "coverage_tactics_covered": summary.coverage_tactics_covered,
            "coverage_tactics_total": summary.coverage_tactics_total,
            "coverage_techniques_covered": summary.coverage_covered,
            "coverage_techniques_total": summary.coverage_total,
            "coverage_sub_techniques_covered":
                summary.coverage_sub_techniques_covered,
            "coverage_sub_techniques_total":
                summary.coverage_sub_techniques_total,
        },
        "rules": sorted(
            [
                {
                    "rule_id": r.rule_id,
                    "status": r.status,
                    "severity": r.severity,
                    "asset_kind": r.asset_kind,
                    "techniques": list(r.techniques),
                    "tactics": list(r.tactics),
                    **({"alerts_30d": r.alerts_30d} if r.alerts_30d is not None else {}),
                    **({"fp_rate": r.fp_rate} if r.fp_rate is not None else {}),
                    **({"effectiveness_score": r.effectiveness_score} if r.effectiveness_score is not None else {}),
                }
                for r in rows
            ],
            key=lambda r: r["rule_id"],
        ),
    }
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


@dataclass(frozen=True)
class ReportDelta:
    """Aggregate week-over-week delta vs a previous snapshot.

    All counts are signed (positive = added, negative = removed).
    Empty / zero deltas are valid and render as "no change" in the
    UI rather than being suppressed entirely — explicit nothing-
    changed is better than silent absence.
    """

    previous_date: str           # ISO-8601 date (YYYY-MM-DD)
    total_delta: int
    production_delta: int
    experimental_delta: int
    deprecated_delta: int
    new_rule_ids: tuple[str, ...] = field(default_factory=tuple)
    removed_rule_ids: tuple[str, ...] = field(default_factory=tuple)
    new_techniques: tuple[str, ...] = field(default_factory=tuple)
    new_sub_techniques: tuple[str, ...] = field(default_factory=tuple)
    coverage_techniques_delta: int = 0
    coverage_sub_techniques_delta: int = 0


def load_snapshot(path: Path) -> dict | None:
    """Load a previously-written snapshot JSON. Returns None when the
    file is missing or unparseable — delta computation degrades to
    "no comparison available" rather than crashing the report run.
    """
    if not path.is_file():
        return None
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        logger.debug("could not parse snapshot %s: %s", path, exc)
        return None
    if not isinstance(raw, dict):
        return None
    if raw.get("schema_version") != SCHEMA_VERSION:
        # Future-proofing: if we bump the schema, we still want a
        # best-effort diff against the older snapshot rather than
        # silently dropping it. Today there's only v1 so we just
        # accept any dict that has the expected keys.
        logger.debug(
            "snapshot schema mismatch (got %r, expected %r); proceeding",
            raw.get("schema_version"), SCHEMA_VERSION,
        )
    return raw


def find_previous_snapshot(
    reports_dir: Path, today_iso: str,
) -> Path | None:
    """Return the most-recent dated snapshot strictly older than today.

    ``reports/<YYYY-MM-DD>.json`` is the dated form; ``reports/latest.json``
    is the always-current alias and NEVER selected as "previous"
    (it would be today's report comparing to itself, yielding all
    zeros). Falls back to None when no dated snapshots exist yet —
    fresh repo on first run, or before any report cron has fired.
    """
    if not reports_dir.is_dir():
        return None
    candidates: list[Path] = []
    for p in reports_dir.glob("*.json"):
        # Skip latest.json and badge.json
        if p.stem in ("latest", "badge"):
            continue
        # Must look like a date stem (YYYY-MM-DD), and strictly older.
        stem = p.stem
        if len(stem) != 10 or stem[4] != "-" or stem[7] != "-":
            continue
        if stem >= today_iso:
            continue
        candidates.append(p)
    if not candidates:
        return None
    candidates.sort()  # lex sort == chronological for ISO dates
    return candidates[-1]


def prune_dated_snapshots(reports_dir: Path, retention_days: int) -> int:
    """Delete dated report snapshots older than ``retention_days``.

    The report run writes dated copies ``reports/<YYYY-MM-DD>.{html,json}``
    alongside the rolling ``latest.*``. On a deployment fork that durably
    commits ``reports/`` this history grows one entry per run; this prune
    bounds it to the retention window so the repo doesn't grow without
    limit. Returns the number of files removed.

    Only files whose **stem is a valid ISO date** (``YYYY-MM-DD``) and
    strictly older than ``today - retention_days`` are eligible — so
    ``latest.*``, ``badge.json``, ``unified.html`` and any other non-dated
    artefact are never touched (same stem guard as
    :func:`find_previous_snapshot`). A ``retention_days <= 0`` disables
    pruning entirely (keep everything). Missing directory is a no-op.

    Mirrors :func:`contentops.alerts.ledger.prune_daily_files`. Pure
    filesystem; no git — the caller's workflow stages the deletions.
    """
    if retention_days <= 0 or not reports_dir.is_dir():
        return 0
    from datetime import date as _date, timedelta as _td
    cutoff = _date.today() - _td(days=retention_days)
    removed = 0
    for f in reports_dir.iterdir():
        if not f.is_file():
            continue
        stem = f.stem
        # Same shape guard as find_previous_snapshot: a 10-char
        # YYYY-MM-DD stem. Excludes latest / badge / unified by construction.
        if len(stem) != 10 or stem[4] != "-" or stem[7] != "-":
            continue
        try:
            file_date = _date.fromisoformat(stem)
        except ValueError:
            continue
        if file_date < cutoff:
            try:
                f.unlink()
                removed += 1
            except OSError as exc:
                logger.debug("could not prune dated snapshot %s: %s", f, exc)
    return removed


def compute_delta(
    previous: dict, current_rows: list[ReportRow],
    current_summary: ReportSummary,
) -> ReportDelta:
    """Diff the current run against a previously-loaded snapshot.

    Identifies:

    * Rules added (rule_ids in current, not in previous)
    * Rules removed (rule_ids in previous, not in current)
    * Techniques newly covered (in current rule set, not in previous)
    * Sub-techniques newly covered
    * Counts delta per status

    ``previous`` is the dict from :func:`load_snapshot`; the function
    tolerates partial / older snapshots by treating missing fields
    as zero / empty.
    """
    prev_summary = previous.get("summary", {})
    prev_rules = previous.get("rules", []) or []
    prev_rule_ids: set[str] = {
        r["rule_id"] for r in prev_rules
        if isinstance(r, dict) and isinstance(r.get("rule_id"), str)
    }
    prev_techniques: set[str] = set()
    prev_sub_techniques: set[str] = set()
    for r in prev_rules:
        if not isinstance(r, dict):
            continue
        for t in r.get("techniques", []) or []:
            if not isinstance(t, str):
                continue
            parent = t.split(".", 1)[0]
            prev_techniques.add(parent)
            if "." in t:
                prev_sub_techniques.add(t)

    curr_rule_ids = {r.rule_id for r in current_rows}
    curr_techniques: set[str] = set()
    curr_sub_techniques: set[str] = set()
    for r in current_rows:
        for t in r.techniques:
            parent = t.split(".", 1)[0]
            curr_techniques.add(parent)
            if "." in t:
                curr_sub_techniques.add(t)

    # Pick a "previous_date" label — prefer the snapshot's generated_at
    # ISO date; fall back to "unknown" if it's malformed.
    prev_generated = previous.get("generated_at") or ""
    previous_date = prev_generated[:10] if len(prev_generated) >= 10 else "unknown"

    return ReportDelta(
        previous_date=previous_date,
        total_delta=current_summary.total - int(prev_summary.get("total", 0)),
        production_delta=(
            current_summary.production
            - int(prev_summary.get("production", 0))
        ),
        experimental_delta=(
            current_summary.experimental
            - int(prev_summary.get("experimental", 0))
        ),
        deprecated_delta=(
            current_summary.deprecated
            - int(prev_summary.get("deprecated", 0))
        ),
        new_rule_ids=tuple(sorted(curr_rule_ids - prev_rule_ids)),
        removed_rule_ids=tuple(sorted(prev_rule_ids - curr_rule_ids)),
        new_techniques=tuple(sorted(curr_techniques - prev_techniques)),
        new_sub_techniques=tuple(sorted(curr_sub_techniques - prev_sub_techniques)),
        coverage_techniques_delta=(
            current_summary.coverage_covered
            - int(prev_summary.get("coverage_techniques_covered", 0))
        ),
        coverage_sub_techniques_delta=(
            current_summary.coverage_sub_techniques_covered
            - int(prev_summary.get("coverage_sub_techniques_covered", 0))
        ),
    )


__all__ = [
    "SCHEMA_VERSION",
    "ReportDelta",
    "compute_delta",
    "find_previous_snapshot",
    "load_snapshot",
    "prune_dated_snapshots",
    "render_snapshot",
]
