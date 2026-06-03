# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for ``contentops disable --pattern`` (S.1, closes gap G18).

The single-rule ``contentops disable <id>`` path is covered by older
tests; this file pins the cohort behaviour: glob pattern matching, the
``--yes`` confirmation gate, the deterministic-order dry-run output,
and the mutually-exclusive validation between the positional argument
and the flag.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner

from contentops.cli import cli


def _write_rule(
    detections: Path, *,
    rule_id: str,
    status: str = "production",
    cohort: str | None = None,
) -> None:
    """Write a minimal sentinel_analytic envelope to disk."""
    p = detections / "sentinel_analytic"
    p.mkdir(parents=True, exist_ok=True)
    cohort_line = f"  cohort: {cohort}\n" if cohort else ""
    (p / f"{rule_id}.yml").write_text(
        f"""\
id: {rule_id}
version: 0.1.0
asset: sentinel_analytic
status: {status}
metadata:
  owner: secops@example.com
  runbookUrl: https://runbooks.example.com/x
  severity: low
  tactics: [Execution]
  techniques: [T1059]
  expectedAlertsPerDay: 1
  fpHandling: Triage manually.
{cohort_line}payload:
  displayName: {rule_id}
  severity: Low
  query: |
    SecurityEvent | where TimeGenerated > ago(1h)
""",
        encoding="utf-8",
    )


def test_pattern_dry_run_lists_matches_and_exits_clean(tmp_path: Path) -> None:
    """Without ``--yes``, ``--pattern`` should list matches and exit
    without mutating any YAML."""
    detections = tmp_path / "detections"
    for rid in ("o365-rule-a", "o365-rule-b", "aad-rule-c"):
        _write_rule(detections, rule_id=rid)

    result = CliRunner().invoke(cli, [
        "disable", "--pattern", "o365-*", "--path", str(detections),
    ])
    assert result.exit_code == 0, result.output
    # Both o365 rules are listed.
    assert "o365-rule-a" in result.output
    assert "o365-rule-b" in result.output
    # Non-matching rule is NOT listed.
    assert "aad-rule-c" not in result.output
    # The "would disable 2 rule(s)" header is present.
    assert "would disable 2 rule(s)" in result.output
    # And the prompt to pass --yes.
    assert "Pass --yes to proceed." in result.output
    # Crucially, nothing was mutated — all three rules still have
    # `status: production` on disk.
    for rid in ("o365-rule-a", "o365-rule-b", "aad-rule-c"):
        text = (detections / "sentinel_analytic" / f"{rid}.yml").read_text()
        assert "status: production" in text
        assert "status: deprecated" not in text


def test_pattern_with_yes_mutates_matching_yamls(tmp_path: Path) -> None:
    """``--pattern ... --yes`` rewrites status to deprecated for every
    matching rule, leaves non-matches alone."""
    detections = tmp_path / "detections"
    for rid in ("o365-rule-a", "o365-rule-b", "aad-rule-c"):
        _write_rule(detections, rule_id=rid)

    result = CliRunner().invoke(cli, [
        "disable", "--pattern", "o365-*", "--yes",
        "--reason", "M365 maintenance window",
        "--path", str(detections),
    ])
    assert result.exit_code == 0, result.output
    # Both o365 rules deprecated; reason recorded on each.
    for rid in ("o365-rule-a", "o365-rule-b"):
        text = (detections / "sentinel_analytic" / f"{rid}.yml").read_text()
        assert "status: deprecated" in text
        assert "M365 maintenance window" in text
    # Non-matching aad rule untouched.
    aad_text = (detections / "sentinel_analytic" / "aad-rule-c.yml").read_text()
    assert "status: production" in aad_text
    assert "status: deprecated" not in aad_text
    # Summary line at end.
    assert "Cohort disable complete: 2 rule(s) deprecated" in result.output


def test_pattern_with_no_matches_errors_cleanly(tmp_path: Path) -> None:
    """A pattern that matches zero rules exits non-zero with a clear
    message — operators shouldn't silently succeed on a typo."""
    detections = tmp_path / "detections"
    _write_rule(detections, rule_id="aad-rule-c")

    result = CliRunner().invoke(cli, [
        "disable", "--pattern", "o365-*", "--path", str(detections),
    ])
    assert result.exit_code == 1
    assert "no rules matched --pattern 'o365-*'" in result.output


def test_pattern_already_deprecated_rules_are_skipped(tmp_path: Path) -> None:
    """If a matched rule is already ``status: deprecated``, the cohort
    apply counts it under ``skipped`` rather than rewriting it."""
    detections = tmp_path / "detections"
    _write_rule(detections, rule_id="o365-rule-a", status="production")
    _write_rule(detections, rule_id="o365-rule-b", status="deprecated")

    result = CliRunner().invoke(cli, [
        "disable", "--pattern", "o365-*", "--yes",
        "--path", str(detections),
    ])
    assert result.exit_code == 0, result.output
    assert "Cohort disable complete: 1 rule(s) deprecated, 1 already deprecated" in result.output


def test_rule_id_and_pattern_are_mutually_exclusive(tmp_path: Path) -> None:
    """Passing both the positional arg and ``--pattern`` should fail
    with a UsageError, not a silent merge."""
    detections = tmp_path / "detections"
    _write_rule(detections, rule_id="o365-rule-a")

    result = CliRunner().invoke(cli, [
        "disable", "o365-rule-a", "--pattern", "o365-*",
        "--path", str(detections),
    ])
    assert result.exit_code == 2  # Click UsageError exit code
    assert "mutually exclusive" in result.output


def test_three_way_mutex_rejects_pattern_plus_cohort(tmp_path: Path) -> None:
    """The new --cohort selector is in the same mutex as rule_id + --pattern."""
    detections = tmp_path / "detections"
    _write_rule(detections, rule_id="o365-rule-a", cohort="o365")

    result = CliRunner().invoke(cli, [
        "disable", "--pattern", "o365-*", "--cohort", "o365",
        "--path", str(detections),
    ])
    assert result.exit_code == 2
    assert "mutually exclusive" in result.output


def test_neither_rule_id_nor_pattern_errors(tmp_path: Path) -> None:
    """Calling ``disable`` with no rule_id, no --pattern, no --cohort
    must error instead of doing nothing silently."""
    detections = tmp_path / "detections"
    _write_rule(detections, rule_id="o365-rule-a")

    result = CliRunner().invoke(cli, [
        "disable", "--path", str(detections),
    ])
    assert result.exit_code == 2
    assert "exactly one" in result.output


# ---------------------------------------------------------------------------
# --cohort selector — parallel to portfolio --cohort, matches metadata.cohort
# ---------------------------------------------------------------------------


def test_cohort_dry_run_lists_matches_only(tmp_path: Path) -> None:
    detections = tmp_path / "detections"
    _write_rule(detections, rule_id="rule-a", cohort="o365")
    _write_rule(detections, rule_id="rule-b", cohort="o365")
    _write_rule(detections, rule_id="rule-c", cohort="aad")
    _write_rule(detections, rule_id="rule-d")  # no cohort

    result = CliRunner().invoke(cli, [
        "disable", "--cohort", "o365", "--path", str(detections),
    ])
    assert result.exit_code == 0, result.output
    assert "rule-a" in result.output
    assert "rule-b" in result.output
    assert "rule-c" not in result.output
    assert "rule-d" not in result.output
    assert "would disable 2 rule(s)" in result.output
    # No mutation in dry-run.
    for rid in ("rule-a", "rule-b", "rule-c", "rule-d"):
        text = (detections / "sentinel_analytic" / f"{rid}.yml").read_text()
        assert "status: deprecated" not in text


def test_cohort_with_yes_mutates_matching_rules(tmp_path: Path) -> None:
    detections = tmp_path / "detections"
    _write_rule(detections, rule_id="rule-a", cohort="o365")
    _write_rule(detections, rule_id="rule-b", cohort="o365")
    _write_rule(detections, rule_id="rule-c", cohort="aad")

    result = CliRunner().invoke(cli, [
        "disable", "--cohort", "o365", "--yes",
        "--reason", "M365 maintenance",
        "--path", str(detections),
    ])
    assert result.exit_code == 0, result.output
    for rid in ("rule-a", "rule-b"):
        text = (detections / "sentinel_analytic" / f"{rid}.yml").read_text()
        assert "status: deprecated" in text
        assert "M365 maintenance" in text
    aad_text = (detections / "sentinel_analytic" / "rule-c.yml").read_text()
    assert "status: production" in aad_text
    assert "Cohort disable complete: 2 rule(s) deprecated" in result.output


def test_cohort_no_matches_errors_cleanly(tmp_path: Path) -> None:
    detections = tmp_path / "detections"
    _write_rule(detections, rule_id="rule-a", cohort="aad")

    result = CliRunner().invoke(cli, [
        "disable", "--cohort", "o365", "--path", str(detections),
    ])
    assert result.exit_code == 1
    assert "no rules matched --cohort 'o365'" in result.output


def test_dry_run_output_is_sorted(tmp_path: Path) -> None:
    """The dry-run listing is sorted by envelope id so reviewer diffs
    don't reorder run-to-run."""
    detections = tmp_path / "detections"
    for rid in ("o365-zebra", "o365-alpha", "o365-mid"):
        _write_rule(detections, rule_id=rid)

    result = CliRunner().invoke(cli, [
        "disable", "--pattern", "o365-*", "--path", str(detections),
    ])
    assert result.exit_code == 0
    # alpha appears before mid appears before zebra in the output.
    alpha_pos = result.output.index("o365-alpha")
    mid_pos = result.output.index("o365-mid")
    zebra_pos = result.output.index("o365-zebra")
    assert alpha_pos < mid_pos < zebra_pos, (
        f"expected alphabetical order; got "
        f"alpha={alpha_pos} mid={mid_pos} zebra={zebra_pos}"
    )


def test_single_rule_path_still_works(tmp_path: Path) -> None:
    """Regression: the original ``contentops disable <id>`` path
    continues to behave exactly as before."""
    detections = tmp_path / "detections"
    _write_rule(detections, rule_id="my-rule")

    result = CliRunner().invoke(cli, [
        "disable", "my-rule", "--path", str(detections),
    ])
    assert result.exit_code == 0
    text = (detections / "sentinel_analytic" / "my-rule.yml").read_text()
    assert "status: deprecated" in text
