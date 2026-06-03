# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for MITRE ATT&CK coverage report (M2)."""

from __future__ import annotations

from pathlib import Path

import yaml
from click.testing import CliRunner

from contentops.cli import cli
from contentops.coverage import (
    ALL_TACTICS,
    CoverageSummary,
    compute_coverage,
    coverage_summary,
    render_badge,
    render_json,
    render_markdown,
)


def _meta(
    *,
    severity: str = "high",
    tactics: list[str] | None = None,
    techniques: list[str] | None = None,
) -> dict:
    return {
        "owner": "blue@contoso.com",
        "runbookUrl": "https://wiki/runbook",
        "severity": severity,
        "tactics": tactics or ["InitialAccess"],
        "techniques": techniques or ["T1059"],
        "expectedAlertsPerDay": 1,
        "fpHandling": "n/a",
    }


def _envelope(
    *,
    rule_id: str,
    asset: str = "sentinel_analytic",
    metadata: dict | None = None,
    payload: dict | None = None,
) -> dict:
    env: dict = {
        "id": rule_id,
        "version": "1.0.0",
        "asset": asset,
        "status": "production",
        "payload": payload if payload is not None else {"query": "T | take 1"},
    }
    if metadata is not None:
        env["metadata"] = metadata
    return env


def _write(root: Path, name: str, body: dict) -> None:
    p = root / f"{name}.yml"
    p.write_text(yaml.safe_dump(body, sort_keys=False), encoding="utf-8")


def test_compute_coverage_buckets_by_tactic(tmp_path: Path) -> None:
    _write(tmp_path, "a", _envelope(
        rule_id="rule-a",
        metadata=_meta(severity="high", tactics=["InitialAccess"], techniques=["T1059"]),
    ))
    _write(tmp_path, "b", _envelope(
        rule_id="rule-b",
        metadata=_meta(severity="medium", tactics=["Execution"], techniques=["T1059.001"]),
    ))

    rep = compute_coverage(tmp_path)
    by = {tc.tactic: tc for tc in rep.tactics}
    assert by["InitialAccess"].detection_count == 1
    assert by["InitialAccess"].techniques == {"T1059": 1}
    assert by["InitialAccess"].by_severity["high"] == 1
    assert by["Execution"].detection_count == 1
    assert by["Execution"].techniques == {"T1059.001": 1}
    assert rep.total_detections == 2
    assert rep.total_with_mitre_data == 2


def test_compute_coverage_skips_envelopes_with_no_mitre_data_anywhere(tmp_path: Path) -> None:
    """Envelopes that have neither metadata-driven MITRE data nor
    payload-derived MITRE data are counted in total_detections but
    contribute zero to per-tactic buckets. (Previously this test
    asserted the metadata-only short-circuit; the extractor now
    falls back to the payload, so the contract is "data anywhere",
    not "metadata required".)"""
    _write(tmp_path, "loose1", _envelope(rule_id="loose-1"))
    _write(tmp_path, "loose2", _envelope(rule_id="loose-2"))
    _write(tmp_path, "covered", _envelope(
        rule_id="covered-1",
        metadata=_meta(),
    ))

    rep = compute_coverage(tmp_path)
    assert rep.total_detections == 3
    assert rep.total_with_mitre_data == 1
    by = {tc.tactic: tc for tc in rep.tactics}
    # No-MITRE envelopes contribute nothing to tactics.
    assert by["InitialAccess"].detection_count == 1


def test_compute_coverage_handles_multi_tactic_detection(tmp_path: Path) -> None:
    _write(tmp_path, "multi", _envelope(
        rule_id="multi-1",
        metadata=_meta(
            tactics=["InitialAccess", "Execution", "Persistence"],
            techniques=["T1059", "T1547"],
        ),
    ))

    rep = compute_coverage(tmp_path)
    by = {tc.tactic: tc for tc in rep.tactics}
    assert by["InitialAccess"].detection_count == 1
    assert by["Execution"].detection_count == 1
    assert by["Persistence"].detection_count == 1
    assert by["InitialAccess"].techniques == {"T1059": 1, "T1547": 1}
    assert rep.total_detections == 1
    assert rep.total_with_mitre_data == 1


def test_compute_coverage_skips_watchlist_and_other_non_detection(tmp_path: Path) -> None:
    _write(tmp_path, "wl", {
        "id": "wl-1",
        "version": "1.0.0",
        "asset": "sentinel_watchlist",
        "status": "production",
        "payload": {
            "displayName": "x",
            "provider": "Custom",
            "source": "Local file",
            "contentType": "text/csv",
            "itemsSearchKey": "k",
            "rawContent": "k\nv\n",
        },
    })
    _write(tmp_path, "det", _envelope(rule_id="det-1", metadata=_meta()))

    rep = compute_coverage(tmp_path)
    assert rep.total_detections == 1
    assert rep.total_with_mitre_data == 1


def test_render_markdown_contains_all_tactics_in_order(tmp_path: Path) -> None:
    rep = compute_coverage(tmp_path)
    md = render_markdown(rep)
    last = -1
    for tactic in ALL_TACTICS:
        idx = md.find(f"| {tactic} |")
        assert idx > last, f"tactic {tactic} not found in expected order"
        last = idx


def test_render_markdown_emoji_thresholds(tmp_path: Path) -> None:
    # 0 detections -> 🟥 (everywhere by default), then build inputs that
    # land each tactic at exactly 0/1/3/6 detections.
    # Reconnaissance -> 0
    # InitialAccess  -> 1 (orange)
    # Execution      -> 3 (yellow)
    # Persistence    -> 6 (green)
    _write(tmp_path, "ia1", _envelope(
        rule_id="ia-1", metadata=_meta(tactics=["InitialAccess"]),
    ))
    for i in range(3):
        _write(tmp_path, f"ex{i}", _envelope(
            rule_id=f"ex-{i}", metadata=_meta(tactics=["Execution"]),
        ))
    for i in range(6):
        _write(tmp_path, f"per{i}", _envelope(
            rule_id=f"per-{i}", metadata=_meta(tactics=["Persistence"]),
        ))

    rep = compute_coverage(tmp_path)
    md = render_markdown(rep)

    def row(tactic: str) -> str:
        for line in md.splitlines():
            if f"| {tactic} |" in line:
                return line
        raise AssertionError(f"tactic row not found: {tactic}")

    assert "🟥" in row("Reconnaissance")
    assert "🟧" in row("InitialAccess")
    assert "🟨" in row("Execution")
    assert "🟩" in row("Persistence")


def test_render_json_is_deterministic(tmp_path: Path) -> None:
    _write(tmp_path, "a", _envelope(
        rule_id="rule-a",
        metadata=_meta(tactics=["InitialAccess"], techniques=["T1059", "T1078"]),
    ))
    _write(tmp_path, "b", _envelope(
        rule_id="rule-b",
        metadata=_meta(tactics=["Execution"], techniques=["T1059.001"]),
    ))

    j1 = render_json(compute_coverage(tmp_path))
    j2 = render_json(compute_coverage(tmp_path))
    assert j1 == j2
    # And serializing twice yields the same bytes.
    assert j1.encode("utf-8") == j2.encode("utf-8")


def test_coverage_cli_writes_files(tmp_path: Path) -> None:
    detections = tmp_path / "detections"
    detections.mkdir()
    _write(detections, "a", _envelope(rule_id="rule-a", metadata=_meta()))

    out_md = tmp_path / "cov.md"
    out_json = tmp_path / "cov.json"

    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "coverage",
            "--path", str(detections),
            "--format", "both",
            "--out-md", str(out_md),
            "--out-json", str(out_json),
        ],
    )
    assert result.exit_code == 0, result.output
    assert out_md.exists()
    assert out_json.exists()
    assert "MITRE ATT&CK Coverage" in out_md.read_text(encoding="utf-8")
    assert '"total_detections": 1' in out_json.read_text(encoding="utf-8")


def test_compute_coverage_derives_from_defender_payload(tmp_path: Path) -> None:
    """Defender envelopes carry MITRE attribution in
    ``payload.detectionAction.alertTemplate.mitreTechniques`` /
    ``severity`` and typically have only ``metadata: {arm_name: ...}``.
    The extractor must populate the per-tactic buckets from the payload
    so the GitHub Action's coverage report doesn't show all zeros."""
    _write(tmp_path, "t1018", _envelope(
        rule_id="t1018-discovery",
        asset="defender_custom_detection",
        metadata={"arm_name": "12345"},   # collected-style skeleton
        payload={
            "displayName": "T1018 Remote System Discovery",
            "queryCondition": {"queryText": "DeviceProcessEvents | take 1"},
            "detectionAction": {
                "alertTemplate": {
                    "title": "Remote System Discovery",
                    "severity": "medium",
                    "category": "Discovery",
                    "mitreTechniques": ["T1018"],
                }
            },
        },
    ))

    rep = compute_coverage(tmp_path)
    assert rep.total_detections == 1
    assert rep.total_with_mitre_data == 1
    by = {tc.tactic: tc for tc in rep.tactics}
    # T1018 maps to Discovery via the curated MITRE map.
    assert by["Discovery"].detection_count == 1
    assert by["Discovery"].techniques == {"T1018": 1}
    assert by["Discovery"].by_severity["medium"] == 1


def test_compute_coverage_unions_metadata_with_payload(tmp_path: Path) -> None:
    """When an envelope has BOTH rich metadata and payload-derived
    MITRE data, the extractor unions them. Counts are strictly
    additive vs. metadata-only behaviour."""
    _write(tmp_path, "merged", _envelope(
        rule_id="merged-1",
        asset="sentinel_analytic",
        metadata=_meta(
            severity="high",
            tactics=["InitialAccess"],
            techniques=["T1190"],
        ),
        payload={
            "tactics": ["Execution"],
            "techniques": ["T1059"],
            "severity": "Low",
            "query": "T | take 1",
        },
    ))

    rep = compute_coverage(tmp_path)
    by = {tc.tactic: tc for tc in rep.tactics}
    # Both tactics get a hit (sourced from metadata + payload).
    assert by["InitialAccess"].detection_count == 1
    assert by["Execution"].detection_count == 1
    # Metadata severity wins on the merge.
    assert by["InitialAccess"].by_severity["high"] == 1
    assert by["Execution"].by_severity["high"] == 1


def test_coverage_handles_empty_detections_dir(tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    rep = compute_coverage(empty)
    assert rep.total_detections == 0
    assert rep.total_with_mitre_data == 0
    md = render_markdown(rep)
    for tactic in ALL_TACTICS:
        assert tactic in md
    # Render JSON works without errors and has all tactics with zero counts.
    js = render_json(rep)
    assert '"total_detections": 0' in js


# ---------------------------------------------------------------------------
# CoverageSummary + render_badge — headline % helper
# ---------------------------------------------------------------------------


def test_coverage_summary_empty_dir_is_zero(tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    s = coverage_summary(empty)
    assert s.covered == 0
    assert s.total > 0  # matrix is non-empty regardless
    assert s.pct == 0


def test_coverage_summary_counts_unique_parent_techniques(tmp_path: Path) -> None:
    """Three detections covering one parent + one sub-technique of the
    same parent should count as 1 covered (parent T1059). A second
    detection on T1190 brings the total to 2."""
    _write(tmp_path, "rule-a", _envelope(
        rule_id="rule-a",
        metadata=_meta(techniques=["T1059"]),
    ))
    _write(tmp_path, "rule-b", _envelope(
        rule_id="rule-b",
        metadata=_meta(techniques=["T1059.001"]),
    ))
    _write(tmp_path, "rule-c", _envelope(
        rule_id="rule-c",
        metadata=_meta(techniques=["T1190"]),
    ))
    s = coverage_summary(tmp_path)
    assert s.covered == 2  # T1059 (collapsed from .001 too), T1190


def test_coverage_summary_ignores_techniques_outside_matrix(tmp_path: Path) -> None:
    """A wildly-out-of-range technique ID (T9999) is ignored by the
    summary even though compute_coverage might still surface it as
    an orphan. The badge only ever scopes against the curated list."""
    _write(tmp_path, "rule-x", _envelope(
        rule_id="rule-x",
        metadata=_meta(techniques=["T9999"]),
    ))
    s = coverage_summary(tmp_path)
    assert s.covered == 0


def _summary(
    *,
    tech_covered: int, tech_total: int,
    sub_covered: int = 0, sub_total: int = 100,
    tactics_covered: int = 0, tactics_total: int = 15,
):
    """Build a CoverageSummary with the new three-level shape."""
    from contentops.coverage import CoverageLevel
    return CoverageSummary(
        tactics=CoverageLevel(covered=tactics_covered, total=tactics_total),
        techniques=CoverageLevel(covered=tech_covered, total=tech_total),
        sub_techniques=CoverageLevel(covered=sub_covered, total=sub_total),
    )


def test_render_badge_shape_matches_shields_endpoint_schema() -> None:
    """shields.io endpoint format requires schemaVersion=1, label,
    message, color. The badge URL is locked-in via README; the JSON
    keys must match exactly."""
    s = _summary(tech_covered=10, tech_total=70, sub_covered=5, sub_total=50)
    import json as _json
    payload = _json.loads(render_badge(s))
    assert payload["schemaVersion"] == 1
    assert payload["label"] == "ATT&CK coverage"
    # 10/70 = 14%; 5/50 = 10%
    assert "14% techniques" in payload["message"]
    assert "10% sub-techniques" in payload["message"]
    assert payload["color"] in {
        "red", "orange", "yellow", "yellowgreen", "brightgreen",
    }


def test_render_badge_color_thresholds() -> None:
    """Spot-check the colour band edges: a 0/x is red, 90/100 is
    brightgreen. Each band must be reachable so future operators
    looking at the badge can tell at-a-glance how the org is doing."""
    bands = {
        (0, 100): "red",       # 0%
        (19, 100): "red",      # 19% still red
        (20, 100): "orange",   # 20% flips to orange
        (40, 100): "yellow",
        (60, 100): "yellowgreen",
        (90, 100): "brightgreen",
    }
    import json as _json
    for (covered, total), expected in bands.items():
        payload = _json.loads(render_badge(
            _summary(tech_covered=covered, tech_total=total),
        ))
        assert payload["color"] == expected, (
            f"covered={covered}/{total}: expected {expected}, got {payload['color']}"
        )


def test_cli_coverage_out_badge_writes_endpoint_json(tmp_path: Path) -> None:
    """End-to-end: `contentops coverage --out-badge X` writes a
    parseable shields.io endpoint JSON and prints a one-line summary
    to stdout/err. PR #240 added the navigator command; this is the
    badge-side of the same wiring."""
    detections = tmp_path / "detections"
    detections.mkdir()
    _write(detections, "rule-a", _envelope(
        rule_id="rule-a",
        metadata=_meta(techniques=["T1059"]),
    ))
    badge_path = tmp_path / "coverage" / "badge.json"

    runner = CliRunner()
    result = runner.invoke(cli, [
        "coverage",
        "--path", str(detections),
        "--format", "markdown",
        "--out-md", str(tmp_path / "coverage.md"),
        "--out-badge", str(badge_path),
    ])
    assert result.exit_code == 0, result.output

    assert badge_path.exists(), "badge file was not written"
    import json as _json
    payload = _json.loads(badge_path.read_text(encoding="utf-8"))
    assert payload["schemaVersion"] == 1
    assert payload["label"] == "ATT&CK coverage"
    # Single covered T1059 against a ~222-item full matrix -> small %.
    assert "% techniques" in payload["message"]


def test_coverage_summary_three_levels_against_real_matrix(tmp_path: Path) -> None:
    """End-to-end pin against the bundled full ATT&CK matrix:

    * A rule covering T1059.001 contributes 1 to BOTH the technique
      level (parent T1059 covered) AND the sub-technique level.
    * A rule with only T1190 contributes 1 only to the technique
      level.
    * The Execution + InitialAccess tactics are covered.
    """
    _write(tmp_path, "rule-a", _envelope(
        rule_id="rule-a",
        metadata=_meta(
            tactics=["Execution"], techniques=["T1059.001"],
        ),
    ))
    _write(tmp_path, "rule-b", _envelope(
        rule_id="rule-b",
        metadata=_meta(
            tactics=["InitialAccess"], techniques=["T1190"],
        ),
    ))
    s = coverage_summary(tmp_path)
    # Tactics: 2 covered out of the 14 canonical Enterprise tactics.
    assert s.tactics.covered == 2
    assert s.tactics.total == 14
    # Techniques: 2 parents covered (T1059, T1190)
    assert s.techniques.covered == 2
    assert s.techniques.total > 200  # full matrix
    # Sub-techniques: 1 covered (T1059.001)
    assert s.sub_techniques.covered == 1
    assert s.sub_techniques.total > 400  # full matrix


def test_coverage_summary_backwards_compat_aliases(tmp_path: Path) -> None:
    """Pre-polish callers used .covered / .total / .pct on the
    summary as if it were a single-level number. Those properties
    must keep working (they forward to the technique level), or PR
    #253 portfolio footer + PR #255 report badge break."""
    _write(tmp_path, "rule-a", _envelope(
        rule_id="rule-a",
        metadata=_meta(techniques=["T1059"]),
    ))
    s = coverage_summary(tmp_path)
    assert s.covered == s.techniques.covered
    assert s.total == s.techniques.total
    assert s.pct == s.techniques.pct


# ---------------------------------------------------------------------------
# Status-aware coverage (production vs experimental)
# ---------------------------------------------------------------------------


def _status_envelope(rule_id: str, status: str, tactics: list[str]) -> dict:
    env = _envelope(rule_id=rule_id, metadata=_meta(tactics=tactics))
    env["status"] = status
    return env


def test_coverage_counts_production_separately(tmp_path: Path) -> None:
    _write(tmp_path, "prod", _status_envelope("r-prod", "production", ["Execution"]))
    _write(tmp_path, "exp", _status_envelope("r-exp", "experimental", ["Execution"]))
    report = compute_coverage(tmp_path)
    execu = next(tc for tc in report.tactics if tc.tactic == "Execution")
    assert execu.detection_count == 2
    assert execu.production_detection_count == 1
    assert report.total_detections == 2
    assert report.total_production_detections == 1


def test_tactic_covered_only_by_experimental_flags_zero_production(tmp_path: Path) -> None:
    _write(tmp_path, "exp", _status_envelope("r-exp", "experimental", ["Persistence"]))
    report = compute_coverage(tmp_path)
    pers = next(tc for tc in report.tactics if tc.tactic == "Persistence")
    assert pers.detection_count == 1 and pers.production_detection_count == 0
    # The heatmap row carries the ⚠️ "no production coverage" marker.
    row = next(l for l in render_markdown(report).splitlines() if "| Persistence |" in l)
    assert "⚠️" in row


def test_render_markdown_has_production_column_and_total(tmp_path: Path) -> None:
    _write(tmp_path, "prod", _status_envelope("r-prod", "production", ["Execution"]))
    md = render_markdown(compute_coverage(tmp_path))
    assert "# Production" in md
    assert "1 production," in md  # totals line


def test_render_json_includes_production_fields(tmp_path: Path) -> None:
    import json
    _write(tmp_path, "prod", _status_envelope("r-prod", "production", ["Execution"]))
    _write(tmp_path, "exp", _status_envelope("r-exp", "experimental", ["Execution"]))
    data = json.loads(render_json(compute_coverage(tmp_path)))
    assert data["total_production_detections"] == 1
    execu = next(t for t in data["tactics"] if t["tactic"] == "Execution")
    assert execu["production_detection_count"] == 1 and execu["detection_count"] == 2


def test_dev_prefix_production_rule_still_counts_as_production(tmp_path: Path) -> None:
    """The [DEV] displayName prefix is an intentional tuning marker on a
    real production rule — status drives the count, so it IS production."""
    env = _status_envelope("r-dev", "production", ["Execution"])
    env["payload"] = {"query": "T | take 1", "displayName": "[DEV] tuning in progress"}
    _write(tmp_path, "dev", env)
    report = compute_coverage(tmp_path)
    execu = next(tc for tc in report.tactics if tc.tactic == "Execution")
    assert execu.production_detection_count == 1
