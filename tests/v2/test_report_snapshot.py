# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for the JSON snapshot + week-over-week delta
(``contentops.report.snapshot``).

The snapshot is the *substrate* the next-run reads to compute the
delta phrase in the executive summary. Schema is intentionally
narrow; this test file pins the shape end-to-end (render -> load ->
diff) so an accidental change to the schema breaks loudly.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from contentops.report.assemble import ReportRow, ReportSummary
from contentops.report.snapshot import (
    SCHEMA_VERSION,
    compute_delta,
    find_previous_snapshot,
    load_snapshot,
    prune_dated_snapshots,
    render_snapshot,
)


def _row(rule_id: str, **over) -> ReportRow:
    base = dict(
        rule_id=rule_id, asset_kind="sentinel_analytic",
        path=f"detections/sentinel_analytic/{rule_id}.yml",
        title=f"Rule {rule_id}", status="production", severity="high",
        tactics=("Execution",), techniques=("T1059",),
        merge_date=None, deployment_date=None, last_review_date=None,
    )
    base.update(over)
    return ReportRow(**base)


def _summary(**over) -> ReportSummary:
    base = dict(
        total=1, production=1, experimental=0, deprecated=0,
        coverage_pct=20, coverage_covered=45, coverage_total=222,
        generated_at="2026-05-23T16:00:00Z",
        coverage_tactics_pct=73, coverage_tactics_covered=11,
        coverage_tactics_total=15,
        coverage_sub_techniques_pct=3, coverage_sub_techniques_covered=16,
        coverage_sub_techniques_total=475,
    )
    base.update(over)
    return ReportSummary(**base)


# ---------------------------------------------------------------------------
# render_snapshot
# ---------------------------------------------------------------------------


def test_render_snapshot_emits_schema_version_and_summary() -> None:
    rows = [_row("rule-a")]
    snap = json.loads(render_snapshot(rows, _summary()))
    assert snap["schema_version"] == SCHEMA_VERSION
    assert snap["summary"]["total"] == 1
    assert snap["summary"]["coverage_techniques_covered"] == 45
    assert snap["summary"]["coverage_sub_techniques_covered"] == 16
    assert snap["summary"]["coverage_tactics_covered"] == 11


def test_render_snapshot_includes_minimal_rule_fields() -> None:
    """The snapshot intentionally keeps only the fields a delta
    computation needs. Wider data (title / runbook / owner) stays
    out so the diff is stable against UI-only edits."""
    rows = [_row(
        "rule-a", techniques=("T1059", "T1059.001"),
        tactics=("Execution",),
    )]
    snap = json.loads(render_snapshot(rows, _summary()))
    rule = snap["rules"][0]
    assert rule["rule_id"] == "rule-a"
    assert rule["status"] == "production"
    assert rule["severity"] == "high"
    assert rule["techniques"] == ["T1059", "T1059.001"]
    # Title / runbook / owner are NOT in the snapshot (stable diff).
    assert "title" not in rule
    assert "runbook_url" not in rule
    assert "owner" not in rule


def test_render_snapshot_rules_sorted_by_id() -> None:
    """Deterministic sort so two runs with the same data produce
    byte-identical snapshots (good for git diffs)."""
    rows = [_row("rule-c"), _row("rule-a"), _row("rule-b")]
    snap = json.loads(render_snapshot(rows, _summary(total=3)))
    assert [r["rule_id"] for r in snap["rules"]] == ["rule-a", "rule-b", "rule-c"]


# ---------------------------------------------------------------------------
# load_snapshot
# ---------------------------------------------------------------------------


def test_load_snapshot_returns_dict_for_valid_file(tmp_path: Path) -> None:
    path = tmp_path / "s.json"
    path.write_text(json.dumps({
        "schema_version": SCHEMA_VERSION,
        "generated_at": "2026-05-16T06:00:00Z",
        "summary": {"total": 5},
        "rules": [],
    }), encoding="utf-8")
    snap = load_snapshot(path)
    assert snap is not None
    assert snap["summary"]["total"] == 5


def test_load_snapshot_missing_file_returns_none(tmp_path: Path) -> None:
    assert load_snapshot(tmp_path / "nope.json") is None


def test_load_snapshot_invalid_json_returns_none(tmp_path: Path) -> None:
    """A corrupt snapshot file degrades to 'no comparison available'
    rather than crashing the report run."""
    path = tmp_path / "bad.json"
    path.write_text("not json {", encoding="utf-8")
    assert load_snapshot(path) is None


# ---------------------------------------------------------------------------
# find_previous_snapshot
# ---------------------------------------------------------------------------


def test_find_previous_picks_most_recent_dated_snapshot(tmp_path: Path) -> None:
    """Most recent <YYYY-MM-DD>.json strictly older than today wins.
    latest.json and badge.json are excluded so the picker never
    selects today's own snapshot as 'previous'."""
    (tmp_path / "latest.json").write_text("{}", encoding="utf-8")
    (tmp_path / "badge.json").write_text("{}", encoding="utf-8")
    (tmp_path / "2026-05-10.json").write_text("{}", encoding="utf-8")
    (tmp_path / "2026-05-16.json").write_text("{}", encoding="utf-8")
    (tmp_path / "2026-05-23.json").write_text("{}", encoding="utf-8")
    chosen = find_previous_snapshot(tmp_path, today_iso="2026-05-23")
    assert chosen is not None
    assert chosen.name == "2026-05-16.json"


def test_find_previous_empty_dir_returns_none(tmp_path: Path) -> None:
    assert find_previous_snapshot(tmp_path, today_iso="2026-05-23") is None


def test_find_previous_only_today_returns_none(tmp_path: Path) -> None:
    """A dated snapshot from today itself doesn't count -- prevents
    comparing the just-generated snapshot to itself (all zeros)."""
    (tmp_path / "2026-05-23.json").write_text("{}", encoding="utf-8")
    assert find_previous_snapshot(tmp_path, today_iso="2026-05-23") is None


# ---------------------------------------------------------------------------
# compute_delta
# ---------------------------------------------------------------------------


def test_compute_delta_no_change() -> None:
    """When current == previous: zero deltas everywhere, no new/
    removed lists. UI renders 'no portfolio change'."""
    prev = json.loads(render_snapshot(
        [_row("rule-a")], _summary(total=1, generated_at="2026-05-16T06:00:00Z"),
    ))
    delta = compute_delta(prev, [_row("rule-a")], _summary(total=1))
    assert delta.previous_date == "2026-05-16"
    assert delta.total_delta == 0
    assert delta.new_rule_ids == ()
    assert delta.removed_rule_ids == ()
    assert delta.new_techniques == ()


def test_compute_delta_new_rule_added() -> None:
    prev = json.loads(render_snapshot(
        [_row("rule-a")], _summary(total=1),
    ))
    current_rows = [_row("rule-a"), _row("rule-b", techniques=("T1190",))]
    delta = compute_delta(prev, current_rows, _summary(total=2, coverage_covered=46))
    assert delta.total_delta == 1
    assert delta.new_rule_ids == ("rule-b",)
    assert delta.removed_rule_ids == ()
    assert delta.new_techniques == ("T1190",)
    assert delta.coverage_techniques_delta == 1


def test_compute_delta_rule_removed_and_technique_lost() -> None:
    prev = json.loads(render_snapshot(
        [_row("rule-a"), _row("rule-b", techniques=("T1190",))],
        _summary(total=2, coverage_covered=46),
    ))
    delta = compute_delta(prev, [_row("rule-a")], _summary(total=1, coverage_covered=45))
    assert delta.total_delta == -1
    assert delta.new_rule_ids == ()
    assert delta.removed_rule_ids == ("rule-b",)
    # T1190 is no longer in any rule -> it's in prev but not curr
    # (compute_delta lists "new techniques", not "removed" -- by design,
    # the CFO cares about growth)
    assert delta.new_techniques == ()
    assert delta.coverage_techniques_delta == -1


def test_compute_delta_sub_technique_independence() -> None:
    """Adding a sub-technique to an already-covered parent counts at
    the sub-technique level. T1059 was already covered; T1059.001
    is added -> 0 new techniques, 1 new sub-technique."""
    prev = json.loads(render_snapshot(
        [_row("rule-a", techniques=("T1059",))],
        _summary(total=1),
    ))
    current = [_row("rule-a", techniques=("T1059", "T1059.001"))]
    delta = compute_delta(prev, current, _summary(total=1, coverage_sub_techniques_covered=17))
    assert delta.new_techniques == ()
    assert delta.new_sub_techniques == ("T1059.001",)
    assert delta.coverage_sub_techniques_delta == 1


def test_compute_delta_tolerates_partial_previous() -> None:
    """A snapshot from an older / partial schema (missing fields)
    must not crash compute_delta -- missing fields default to 0."""
    prev = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": "2026-05-10T06:00:00Z",
        # No 'summary' key, no 'rules' key.
    }
    delta = compute_delta(prev, [_row("rule-a")], _summary(total=1))
    # current has 1 rule, previous "has" 0 -> +1
    assert delta.total_delta == 1
    assert delta.new_rule_ids == ("rule-a",)
    assert delta.previous_date == "2026-05-10"


# ---------------------------------------------------------------------------
# prune_dated_snapshots
# ---------------------------------------------------------------------------


def _dated(reports_dir: Path, days_ago: int, ext: str = "json") -> Path:
    """Write a dated snapshot file `<today - days_ago>.<ext>`."""
    from datetime import date, timedelta
    stamp = (date.today() - timedelta(days=days_ago)).isoformat()
    p = reports_dir / f"{stamp}.{ext}"
    p.write_text("{}", encoding="utf-8")
    return p


def test_prune_removes_only_files_older_than_retention(tmp_path: Path) -> None:
    """Dated snapshots strictly older than today-retention are deleted;
    fresher ones survive. Both .html and .json dated forms are eligible."""
    old_json = _dated(tmp_path, days_ago=400, ext="json")
    old_html = _dated(tmp_path, days_ago=400, ext="html")
    recent = _dated(tmp_path, days_ago=10, ext="json")
    removed = prune_dated_snapshots(tmp_path, retention_days=365)
    assert removed == 2
    assert not old_json.exists()
    assert not old_html.exists()
    assert recent.exists()


def test_prune_never_touches_non_dated_artefacts(tmp_path: Path) -> None:
    """latest.*, badge.json, unified.html have non-date stems and must
    survive pruning regardless of age."""
    for name in ("latest.json", "latest.html", "badge.json", "unified.html"):
        (tmp_path / name).write_text("{}", encoding="utf-8")
    _dated(tmp_path, days_ago=500)  # one ancient dated file to prune
    removed = prune_dated_snapshots(tmp_path, retention_days=90)
    assert removed == 1
    for name in ("latest.json", "latest.html", "badge.json", "unified.html"):
        assert (tmp_path / name).exists()


def test_prune_zero_retention_is_disabled(tmp_path: Path) -> None:
    """retention_days <= 0 means 'keep everything' (pruning disabled)."""
    _dated(tmp_path, days_ago=9999)
    assert prune_dated_snapshots(tmp_path, retention_days=0) == 0
    assert len(list(tmp_path.glob("*.json"))) == 1


def test_prune_missing_dir_is_noop(tmp_path: Path) -> None:
    assert prune_dated_snapshots(tmp_path / "nope", retention_days=365) == 0


def test_prune_ignores_malformed_date_stems(tmp_path: Path) -> None:
    """A 10-char stem that isn't a real date (e.g. 2026-13-99) is skipped,
    not crashed on."""
    (tmp_path / "2026-13-99.json").write_text("{}", encoding="utf-8")
    assert prune_dated_snapshots(tmp_path, retention_days=1) == 0
    assert (tmp_path / "2026-13-99.json").exists()
