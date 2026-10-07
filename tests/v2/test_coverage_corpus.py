# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""One corpus, one scope, one answer: every coverage surface agrees.

Regression tests for the external review's coverage findings (C1-C9 and
the revoked-id gap), driven by the shared ``coverage_corpus`` fixture in
``tests/v2/conftest.py`` -- one rule per finding.
"""

from __future__ import annotations

import json

from click.testing import CliRunner

from contentops.cli import cli
from contentops.coverage import (
    CoverageScope,
    compute_coverage,
    coverage_summary,
    load_corpus,
)
from contentops.coverage.gaps import compute_gaps, load_techniques


def _by_tactic(report):
    return {tc.tactic: tc for tc in report.tactics}


def test_default_scope_counts_enabled_production_detections_only(coverage_corpus) -> None:
    corpus = load_corpus(coverage_corpus)
    assert len(corpus.entries) == 12  # nothing silently skipped (C6)
    assert not corpus.load_errors
    in_scope = {e.id for e in corpus.in_scope()}
    assert "r4-disabled" not in in_scope         # C4
    assert "r5-hunting" not in in_scope          # C5
    assert "r10-experimental" not in in_scope
    assert corpus.excluded_counts() == {"disabled": 1, "hunting": 1, "non_production": 1}


def test_badge_numbers(coverage_corpus, coverage_corpus_expected) -> None:
    summary = coverage_summary(coverage_corpus)
    corpus = load_corpus(coverage_corpus)
    covered = corpus.covered()
    assert covered.techniques == coverage_corpus_expected.parents
    assert covered.sub_techniques == coverage_corpus_expected.subs   # C1
    assert covered.tactics == coverage_corpus_expected.tactics
    assert summary.techniques.covered == len(coverage_corpus_expected.parents)
    assert summary.sub_techniques.covered == 1
    assert summary.tactics.covered == len(coverage_corpus_expected.tactics)
    assert summary.detections_in_scope == coverage_corpus_expected.in_scope
    assert summary.scope_label.startswith("enabled production detections")


def test_heatmap_lists_techniques_only_under_their_own_tactics(coverage_corpus) -> None:
    by = _by_tactic(compute_coverage(coverage_corpus))
    # C2: T1059 (Execution) never under InitialAccess; T1190 never under Execution.
    assert by["InitialAccess"].detection_count == 3           # r2, r6b, r8
    assert set(by["InitialAccess"].techniques) == {"T1190", "T1566", "T1078"}
    assert set(by["Execution"].techniques) == {"T1059"}
    # C8: Defender T1078 only under its category, not all four of its tactics.
    assert by["PrivilegeEscalation"].detection_count == 0
    # C3: T1018 is not a Persistence technique; the rule still counts there.
    assert by["Persistence"].detection_count == 1 and by["Persistence"].techniques == {}
    # Tactic-less rule gets its tactics from its technique (T1046 -> Discovery).
    assert set(by["Discovery"].techniques) == {"T1046", "T1082", "T1087"}
    # C1 + revoked remap.
    assert set(by["CredentialAccess"].techniques) == {"T1110", "T1110.003"}
    assert set(by["DefenseEvasion"].techniques) == {"T1685"}
    # C6: tags from partial / strict-failing metadata survive.
    assert set(by["Exfiltration"].techniques) == {"T1041"}
    # C4 / C5 / non-production contribute nothing.
    assert by["Impact"].detection_count == 0
    assert by["LateralMovement"].detection_count == 0


def test_diagnostics_report_every_data_quality_problem(coverage_corpus) -> None:
    report = compute_coverage(coverage_corpus)
    diag = report.diagnostics
    assert ("r7-messy-ids", "T10") in diag.invalid_ids
    assert ("r7-messy-ids", "bogus") in diag.invalid_ids
    assert diag.unknown_ids == ("T9999",)
    assert ("T1562", "T1685") in diag.remapped_ids
    assert ("T1562.001", "T1685") in diag.remapped_ids
    assert diag.outside_tactics == ("T1018",)
    assert {rule for rule, _ in diag.metadata_errors} == {
        "r6-partial-metadata", "r6b-bad-reference",
    }
    # Messy-but-valid ids are normalised, never kept as junk keys (C7).
    keys = {t for tc in report.tactics for t in tc.techniques}
    assert not {" T1082", "t1087"} & keys
    assert report.techniques_without_tactic == ("T9999",)


def test_gaps_and_badge_agree(coverage_corpus, coverage_corpus_expected) -> None:
    report = compute_coverage(coverage_corpus)
    techniques, label = load_techniques()
    gaps = compute_gaps(report, techniques, source=label)
    summary = coverage_summary(coverage_corpus)
    # C9: distinct counts with the badge's denominators.
    assert gaps.techniques_covered == summary.techniques.covered
    assert gaps.techniques_total == summary.techniques.total
    assert gaps.sub_techniques_covered == summary.sub_techniques.covered
    assert gaps.sub_techniques_total == summary.sub_techniques.total
    assert gaps.reference_count == summary.techniques.total + summary.sub_techniques.total
    # C3: T1018 sits on a rule whose tactic it doesn't belong to, but it is
    # covered -- so it is not a Discovery gap.
    discovery = next(t for t in gaps.tactics if t.tactic == "Discovery")
    assert "T1018" not in {t.id for t in discovery.uncovered}
    assert "T1046" not in {t.id for t in discovery.uncovered}


def test_scope_flags_widen_the_count(coverage_corpus, coverage_corpus_expected) -> None:
    base = len(coverage_corpus_expected.parents)
    with_np = coverage_summary(
        coverage_corpus, scope=CoverageScope.from_flags(include_non_production=True),
    )
    assert with_np.techniques.covered == base + 1      # T1003; disabled T1486 never counts
    with_hunting = coverage_summary(
        coverage_corpus, scope=CoverageScope.from_flags(include_hunting=True),
    )
    assert with_hunting.techniques.covered == base + 1  # T1021


def test_cli_badge_written_in_every_mode(coverage_corpus, tmp_path) -> None:
    runner = CliRunner()
    expected = None
    for mode in ([], ["--gaps"], ["--by-source"], ["--d3fend"]):
        badge = tmp_path / f"badge{len(mode)}{'-'.join(mode)}.json"
        result = runner.invoke(cli, [
            "coverage", "--path", str(coverage_corpus), *mode, "--out-badge", str(badge),
        ])
        assert result.exit_code == 0, result.output
        message = json.loads(badge.read_text(encoding="utf-8"))["message"]
        expected = expected or message
        assert message == expected, mode


def test_cli_by_source_format_both_does_not_overwrite_the_heatmap(
    coverage_corpus, tmp_path, monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()
    result = runner.invoke(cli, [
        "coverage", "--path", str(coverage_corpus), "--by-source", "--format", "both",
    ])
    assert result.exit_code == 0, result.output
    assert (tmp_path / "coverage-by-source.md").is_file()
    assert (tmp_path / "coverage-by-source.json").is_file()
    assert not (tmp_path / "coverage.md").exists()


def test_cli_heatmap_states_scope_and_flags_change_it(coverage_corpus) -> None:
    runner = CliRunner()
    default = runner.invoke(cli, ["coverage", "--path", str(coverage_corpus)])
    assert default.exit_code == 0, default.output
    assert "enabled production detections (hunting queries excluded)" in default.output
    widened = runner.invoke(cli, [
        "coverage", "--path", str(coverage_corpus),
        "--include-non-production", "--include-hunting",
    ])
    assert widened.exit_code == 0, widened.output
    assert "enabled detections of any status (hunting queries included)" in widened.output
    assert "# Production" in widened.output


def test_malformed_values_render_inert_in_markdown(tmp_path) -> None:
    """A hostile technique value is reported as an inert code span."""
    import yaml

    from contentops.coverage import render_markdown

    root = tmp_path / "detections" / "sentinel_analytic"
    root.mkdir(parents=True)
    (root / "evil.yml").write_text(yaml.safe_dump({
        "id": "evil", "version": "1.0.0", "asset": "sentinel_analytic",
        "status": "production",
        "payload": {"displayName": "x", "query": "T | take 1", "tactics": ["Execution"],
                    "techniques": ["T1059", "`|<img src=x onerror=alert(1)>\n# pwn"]},
    }), encoding="utf-8")
    md = render_markdown(compute_coverage(tmp_path / "detections"))
    line = next(l for l in md.splitlines() if "Malformed technique values" in l)
    assert "`'/<img src=x onerror=alert(1)> # pwn`" in line
    assert "\n# pwn" not in md


def test_inventory_report_matches_the_badge(coverage_corpus, coverage_corpus_expected) -> None:
    from contentops.report import assemble_report

    rows, summary = assemble_report(coverage_corpus)
    badge = coverage_summary(coverage_corpus)
    assert summary.coverage_covered == badge.techniques.covered == len(coverage_corpus_expected.parents)
    assert summary.coverage_sub_techniques_covered == badge.sub_techniques.covered
    assert summary.coverage_tactics_covered == badge.tactics.covered
    assert summary.in_scope_detections == coverage_corpus_expected.in_scope
    assert summary.attack_version == badge.attack_version
    # Every detection gets a row; only in-scope rows count.
    assert len(rows) == 12
    assert sum(r.in_coverage_scope for r in rows) == coverage_corpus_expected.in_scope
    by_id = {r.rule_id: r for r in rows}
    assert by_id["r9-revoked"].techniques == ("T1685",)
    assert by_id["r1-subtechniques"].techniques == ("T1110", "T1110.003")
