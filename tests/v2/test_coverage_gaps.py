# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for `contentops coverage --gaps`.

Layered:
* Unit tests against `contentops.coverage.gaps` (loader, set-difference, render).
* CLI integration via `click.testing.CliRunner` (the --gaps flag wired to the
  existing `coverage` command).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from contentops.cli import cli
from contentops.coverage import compute_coverage
from contentops.coverage.gaps import (
    CURATED_LABEL,
    FULL_LABEL,
    GapsReport,
    TechniqueRef,
    compute_gaps,
    load_techniques,
    render_json,
    render_markdown,
)
from contentops.coverage.report import (
    CoverageReport,
    TacticCoverage,
)


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------


def test_load_default_techniques_returns_full_matrix() -> None:
    techs, source = load_techniques()  # default mode == "full"
    assert source == FULL_LABEL
    # Full matrix = 222 parents + 475 sub-techniques.
    assert len(techs) > 600, "full matrix should include sub-techniques"
    ids = {t.id for t in techs}
    assert {"T1078", "T1059", "T1486", "T1110"}.issubset(ids)
    # Sub-techniques (id with a dot) are merged in.
    assert any("." in i for i in ids), "full matrix must include sub-techniques"
    # The DefenseEvasion fix: it must be a tactic somewhere in the matrix.
    assert any("DefenseEvasion" in t.tactics for t in techs)


def test_load_curated_mode_returns_curated_subset() -> None:
    techs, source = load_techniques(mode="curated")
    assert source == CURATED_LABEL
    assert len(techs) > 30, "curated list should cover all 14 tactics"
    ids = {t.id for t in techs}
    assert {"T1078", "T1059", "T1486", "T1110"}.issubset(ids)


def test_load_custom_techniques_file(tmp_path: Path) -> None:
    custom = tmp_path / "tm.json"
    custom.write_text(json.dumps({
        "techniques": [
            {"id": "T9001", "name": "Tiny", "tactics": ["Execution"]},
        ],
    }), encoding="utf-8")
    techs, source = load_techniques(custom)
    assert source == "custom: tm.json"
    assert len(techs) == 1 and techs[0].id == "T9001"


# ---------------------------------------------------------------------------
# compute_gaps — minimal CoverageReport with one covered technique
# ---------------------------------------------------------------------------


def _coverage_with(tactic: str, technique_counts: dict[str, int]) -> CoverageReport:
    """Build a minimal CoverageReport that pretends one tactic has these techniques."""
    from contentops.coverage.report import ALL_TACTICS, SEVERITIES
    tactics = []
    for t in ALL_TACTICS:
        techs = technique_counts if t == tactic else {}
        tactics.append(TacticCoverage(
            tactic=t, detection_count=sum(techs.values()),
            techniques=dict(techs),
            by_severity={s: 0 for s in SEVERITIES},
        ))
    return CoverageReport(
        tactics=tactics,
        total_detections=sum(technique_counts.values()),
        total_with_mitre_data=sum(technique_counts.values()),
    )


def test_compute_gaps_marks_covered_tech_as_not_uncovered() -> None:
    techs = [
        TechniqueRef("T1059", "Command and Scripting Interpreter", ("Execution",)),
        TechniqueRef("T1106", "Native API", ("Execution",)),
    ]
    report = _coverage_with("Execution", {"T1059": 3})
    gaps = compute_gaps(report, techs)
    by_tactic = {tg.tactic: tg for tg in gaps.tactics}
    exec_tg = by_tactic["Execution"]
    assert exec_tg.total_in_tactic == 2
    assert exec_tg.covered_count == 1
    assert {t.id for t in exec_tg.uncovered} == {"T1106"}


def test_compute_gaps_subtechnique_covers_parent() -> None:
    """T1059.001 (PowerShell) on a detection counts as covering T1059 (parent)."""
    techs = [
        TechniqueRef("T1059", "Command and Scripting Interpreter", ("Execution",)),
    ]
    report = _coverage_with("Execution", {"T1059.001": 2})
    gaps = compute_gaps(report, techs)
    exec_tg = next(tg for tg in gaps.tactics if tg.tactic == "Execution")
    assert exec_tg.uncovered == [], (
        "sub-technique should imply parent coverage; got uncovered: "
        + str(exec_tg.uncovered)
    )


def test_compute_gaps_multi_tactic_technique_counted_per_tactic() -> None:
    """T1078 covers four tactics; coverage in one shouldn't suppress the others."""
    techs = [
        TechniqueRef(
            "T1078", "Valid Accounts",
            ("DefenseEvasion", "InitialAccess", "Persistence", "PrivilegeEscalation"),
        ),
    ]
    # Tag T1078 in one tactic only; the other three should count it as covered too
    # because the technique id is referenced anywhere.
    report = _coverage_with("InitialAccess", {"T1078": 1})
    gaps = compute_gaps(report, techs)
    for tg in gaps.tactics:
        if tg.tactic in {"DefenseEvasion", "InitialAccess", "Persistence", "PrivilegeEscalation"}:
            assert tg.total_in_tactic == 1
            assert tg.covered_count == 1
            assert tg.uncovered == []


def test_compute_gaps_unknown_tactic_in_techniques_is_skipped() -> None:
    """A technique tagged with a tactic the pipeline doesn't model is silently dropped."""
    techs = [
        TechniqueRef("TXXX", "Made Up", ("NotARealTactic",)),
        TechniqueRef("T1059", "Command and Scripting Interpreter", ("Execution",)),
    ]
    report = _coverage_with("Execution", {})
    gaps = compute_gaps(report, techs)
    # Only the well-typed one shows up in totals.
    assert gaps.total_techniques == 1


def test_compute_gaps_totals_sum_correctly() -> None:
    techs = [
        TechniqueRef("T1059", "x", ("Execution",)),
        TechniqueRef("T1106", "x", ("Execution",)),
        TechniqueRef("T1486", "x", ("Impact",)),
    ]
    report = _coverage_with("Execution", {"T1059": 1})
    gaps = compute_gaps(report, techs)
    assert gaps.total_techniques == 3
    assert gaps.total_uncovered == 2  # T1106 + T1486


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def test_render_markdown_omits_tactics_with_no_techniques_in_reference() -> None:
    techs = [TechniqueRef("T1486", "Data Encrypted for Impact", ("Impact",))]
    report = _coverage_with("Impact", {})
    gaps = compute_gaps(report, techs)
    gaps.techniques_source = "test"
    md = render_markdown(gaps)
    assert "Impact" in md
    # Tactics not present in the techniques list should be omitted from the table.
    assert "Reconnaissance" not in md.split("Impact")[1]


def test_render_markdown_includes_source_label() -> None:
    techs = [TechniqueRef("T1059", "x", ("Execution",))]
    report = _coverage_with("Execution", {})
    gaps = compute_gaps(report, techs)
    gaps.techniques_source = "custom: tm.json"
    md = render_markdown(gaps)
    assert "custom: tm.json" in md


def test_render_json_is_parseable() -> None:
    techs = [TechniqueRef("T1059", "Cmd", ("Execution",))]
    report = _coverage_with("Execution", {})
    gaps = compute_gaps(report, techs)
    gaps.techniques_source = "test-source"
    js = render_json(gaps)
    parsed = json.loads(js)
    assert parsed["techniques_source"] == "test-source"
    assert parsed["reference_count"] == 1
    assert parsed["total_techniques"] == 1
    assert parsed["total_uncovered"] == 1
    # Only Execution should appear (other tactics empty in the reference).
    assert {t["tactic"] for t in parsed["tactics"]} == {"Execution"}


# ---------------------------------------------------------------------------
# Curated-subset transparency (reference_count + scope note + CLI banner)
# ---------------------------------------------------------------------------


def test_compute_gaps_sets_reference_count_and_source() -> None:
    techs = [
        TechniqueRef("T1059", "x", ("Execution",)),
        TechniqueRef("T1486", "x", ("Impact",)),
    ]
    report = _coverage_with("Execution", {})
    gaps = compute_gaps(report, techs, source="bundled curated list")
    # reference_count counts distinct techniques, not the per-tactic fan-out.
    assert gaps.reference_count == 2
    assert gaps.techniques_source == "bundled curated list"


def test_render_markdown_curated_shows_subset_scope_note() -> None:
    techs = [TechniqueRef("T1059", "x", ("Execution",))]
    report = _coverage_with("Execution", {})
    gaps = compute_gaps(report, techs, source=CURATED_LABEL)
    md = render_markdown(gaps)
    assert "curated subset" in md.lower()
    assert "--techniques-file" in md


def test_render_markdown_full_shows_full_scope_note() -> None:
    techs = [TechniqueRef("T1059", "x", ("Execution",))]
    report = _coverage_with("Execution", {})
    gaps = compute_gaps(report, techs, source=FULL_LABEL)
    md = render_markdown(gaps)
    # Full mode: flags the large surface, points at the curated shortlist,
    # and must NOT mislabel itself as the curated subset.
    assert "full" in md.lower()
    assert "--matrix-mode curated" in md
    assert "curated subset" not in md.lower()


def test_render_markdown_groups_subtechniques_under_parent() -> None:
    techs = [
        TechniqueRef("T1059", "Command and Scripting Interpreter", ("Execution",)),
        TechniqueRef("T1059.001", "PowerShell", ("Execution",)),
        TechniqueRef("T1059.003", "Windows Command Shell", ("Execution",)),
    ]
    report = _coverage_with("Execution", {})  # nothing covered
    gaps = compute_gaps(report, techs, source=FULL_LABEL)
    md = render_markdown(gaps)
    # The two uncovered subs collapse under the parent as "(+2 sub)".
    assert "`T1059` Command and Scripting Interpreter (+2 sub)" in md


def test_render_markdown_custom_omits_subset_scope_note() -> None:
    """A custom --techniques-file is the operator's own reference, so the
    'this is only a subset' caveat must NOT be shown."""
    techs = [TechniqueRef("T1059", "x", ("Execution",))]
    report = _coverage_with("Execution", {})
    gaps = compute_gaps(report, techs, source="custom: tm.json")
    md = render_markdown(gaps)
    assert "curated subset" not in md.lower()


def test_cli_gaps_curated_mode_warns_about_subset(tmp_path: Path) -> None:
    """`--gaps --matrix-mode curated` must surface the curated-subset
    caveat (stderr, merged into output by CliRunner)."""
    detections = tmp_path / "detections"
    detections.mkdir()
    result = CliRunner().invoke(
        cli, ["coverage", "--gaps", "--matrix-mode", "curated",
              "--path", str(detections)],
    )
    assert result.exit_code == 0, result.output
    assert "curated subset" in result.output.lower()


def test_cli_gaps_full_default_notes_full_matrix(tmp_path: Path) -> None:
    """The default --gaps uses the full matrix and says so (not the
    curated-subset wording)."""
    detections = tmp_path / "detections"
    detections.mkdir()
    result = CliRunner().invoke(
        cli, ["coverage", "--gaps", "--path", str(detections)],
    )
    assert result.exit_code == 0, result.output
    assert "full mitre att&ck enterprise matrix" in result.output.lower()
    assert "curated subset" not in result.output.lower()


def test_cli_gaps_custom_file_does_not_warn_about_subset(tmp_path: Path) -> None:
    """A custom --techniques-file must NOT emit the subset banner, so a
    piped JSON report stays clean."""
    detections = tmp_path / "detections"
    detections.mkdir()
    tm = tmp_path / "tm.json"
    tm.write_text(json.dumps({
        "techniques": [{"id": "T1059", "name": "Cmd", "tactics": ["Execution"]}],
    }), encoding="utf-8")
    result = CliRunner().invoke(cli, [
        "coverage", "--gaps", "--path", str(detections),
        "--techniques-file", str(tm), "--format", "json",
    ])
    assert result.exit_code == 0, result.output
    assert "curated subset" not in result.output.lower()
    # Output stays parseable (no banner leaked onto stdout/merged stream).
    assert json.loads(result.output)["techniques_source"] == "custom: tm.json"


# ---------------------------------------------------------------------------
# CLI integration
# ---------------------------------------------------------------------------


def test_cli_gaps_prints_markdown_against_real_detections(tmp_path: Path) -> None:
    """End-to-end: --gaps on an empty detections tree returns 100% uncovered."""
    detections = tmp_path / "detections"
    detections.mkdir()
    runner = CliRunner()
    result = runner.invoke(
        cli, ["coverage", "--gaps", "--path", str(detections)],
    )
    assert result.exit_code == 0, result.output
    assert "MITRE ATT&CK Coverage Gaps" in result.output
    # Empty tree → every reference technique is uncovered → totals match.
    # (Don't hardcode the exact count — the bundled list may grow.)
    assert "uncovered of " in result.output


def test_cli_gaps_with_custom_techniques_file(tmp_path: Path) -> None:
    detections = tmp_path / "detections"
    detections.mkdir()
    tm = tmp_path / "tm.json"
    tm.write_text(json.dumps({
        "techniques": [
            {"id": "T1059", "name": "Cmd", "tactics": ["Execution"]},
            {"id": "T1486", "name": "Encrypt", "tactics": ["Impact"]},
        ],
    }), encoding="utf-8")
    runner = CliRunner()
    result = runner.invoke(cli, [
        "coverage", "--gaps",
        "--path", str(detections),
        "--techniques-file", str(tm),
        "--format", "json",
    ])
    assert result.exit_code == 0, result.output
    parsed = json.loads(result.output)
    assert parsed["techniques_source"] == "custom: tm.json"
    assert parsed["total_techniques"] == 2
    assert parsed["total_uncovered"] == 2


def test_cli_default_coverage_unchanged_by_gaps_flag_absent(tmp_path: Path) -> None:
    """Without --gaps, `coverage` still produces the heatmap."""
    detections = tmp_path / "detections"
    detections.mkdir()
    runner = CliRunner()
    result = runner.invoke(cli, ["coverage", "--path", str(detections)])
    assert result.exit_code == 0, result.output
    assert "MITRE ATT&CK Coverage" in result.output
    assert "Coverage Gaps" not in result.output


def test_cli_gaps_writes_to_out_md(tmp_path: Path) -> None:
    detections = tmp_path / "detections"
    detections.mkdir()
    out = tmp_path / "gaps.md"
    runner = CliRunner()
    result = runner.invoke(cli, [
        "coverage", "--gaps",
        "--path", str(detections),
        "--out-md", str(out),
    ])
    assert result.exit_code == 0, result.output
    assert out.exists()
    body = out.read_text(encoding="utf-8")
    assert "MITRE ATT&CK Coverage Gaps" in body
