# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for ``contentops enable`` (G18 round-trip).

The companion file ``test_disable_pattern.py`` covers the disable side;
this one pins the inverse:

* single-rule un-deprecate + --to override
* cohort selectors (--pattern and --cohort)
* warn-and-skip when a matched rule isn't actually deprecated
* the disable-marker strip + enable-marker append
* mutex validation matches disable
* end-to-end round-trip: disable then enable returns to a clean shape
"""

from __future__ import annotations

from datetime import date
from pathlib import Path

import pytest
from click.testing import CliRunner

from contentops.cli import cli


def _write_rule(
    detections: Path, *,
    rule_id: str,
    status: str = "deprecated",
    cohort: str | None = None,
    trailing: str = "",
) -> Path:
    """Write a minimal sentinel_analytic envelope.

    ``trailing`` lets a test seed the disable marker (or a manual one)
    after the payload to exercise the strip logic.
    """
    p = detections / "sentinel_analytic"
    p.mkdir(parents=True, exist_ok=True)
    cohort_line = f"  cohort: {cohort}\n" if cohort else ""
    target = p / f"{rule_id}.yml"
    target.write_text(
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
{trailing}""",
        encoding="utf-8",
    )
    return target


# ---------------------------------------------------------------------------
# single-rule path
# ---------------------------------------------------------------------------


def test_single_rule_defaults_to_experimental(tmp_path: Path) -> None:
    detections = tmp_path / "detections"
    target = _write_rule(
        detections, rule_id="rule-x", status="deprecated",
        trailing='disableReason: "M365 maintenance"\n',
    )

    result = CliRunner().invoke(cli, [
        "enable", "rule-x", "--path", str(detections),
    ])
    assert result.exit_code == 0, result.output

    text = target.read_text(encoding="utf-8")
    assert "status: experimental" in text
    assert "status: deprecated" not in text
    # Disable marker stripped.
    assert "disableReason" not in text
    # Enable marker appended (no --reason -> comment form).
    assert "# re-enabled by contentops enable on " in text


def test_single_rule_to_production_stamps_and_is_gate_compliant(tmp_path: Path) -> None:
    """Direct restore to production: one command, smooth — but it carries
    the promotion stamp + forcedPromotion marker so production-promotion-
    check passes (no flip-to-experimental-then-promote dance)."""
    import importlib.util

    import yaml

    detections = tmp_path / "detections"
    target = _write_rule(detections, rule_id="rule-x", status="deprecated")

    result = CliRunner().invoke(cli, [
        "enable", "rule-x", "--to", "production",
        "--path", str(detections),
    ])
    assert result.exit_code == 0, result.output
    text = target.read_text(encoding="utf-8")
    assert "status: production" in text
    # Stamped so the hard gate (production-promotion-check) accepts it.
    assert "promotedAt:" in text
    assert "promotedBy:" in text
    assert "forcedPromotion: true" in text

    # Gate-compliance proof: the detect_production_promotions stamp check
    # (the script production-promotion-check.yml runs) accepts this stamp.
    import sys
    script = Path(__file__).parents[2] / "scripts" / "detect_production_promotions.py"
    spec = importlib.util.spec_from_file_location("detect_prod_promo", script)
    mod = importlib.util.module_from_spec(spec)
    # Register before exec so the script's @dataclass can resolve its own
    # module globals (dataclasses reads sys.modules[cls.__module__]).
    sys.modules["detect_prod_promo"] = mod
    spec.loader.exec_module(mod)
    doc = yaml.safe_load(text)
    _, _, _, stamp_ok = mod._stamp_from_envelope(
        doc, today=date.today(), max_stamp_age_days=30,
    )
    assert stamp_ok is True


def test_enable_to_experimental_does_not_stamp(tmp_path: Path) -> None:
    """The default experimental restore must NOT write a promotion stamp —
    only --to production does."""
    detections = tmp_path / "detections"
    target = _write_rule(detections, rule_id="rule-x", status="deprecated")

    result = CliRunner().invoke(cli, [
        "enable", "rule-x", "--path", str(detections),
    ])
    assert result.exit_code == 0, result.output
    text = target.read_text(encoding="utf-8")
    assert "status: experimental" in text
    assert "promotedAt:" not in text
    assert "forcedPromotion" not in text


def test_enable_writes_audit_record(tmp_path: Path, monkeypatch) -> None:
    """enable now writes an audit record (it previously wrote none, unlike
    disable). The conftest chdir's to tmp_path, so the chain lands there."""
    import json

    detections = tmp_path / "detections"
    _write_rule(detections, rule_id="rule-x", status="deprecated")

    result = CliRunner().invoke(cli, [
        "enable", "rule-x", "--to", "production",
        "--path", str(detections),
    ])
    assert result.exit_code == 0, result.output

    audit_dir = tmp_path / "audit"
    files = list(audit_dir.glob("*.jsonl")) if audit_dir.exists() else []
    assert files, "enable must write an audit record"
    records = [
        json.loads(line)
        for f in files
        for line in f.read_text(encoding="utf-8").splitlines() if line.strip()
    ]
    enable_recs = [r for r in records if r.get("action") == "enable" and r.get("id") == "rule-x"]
    assert enable_recs, f"no enable audit record found: {records}"


def test_single_rule_already_active_is_skipped(tmp_path: Path) -> None:
    """A rule that isn't deprecated must be warned-and-skipped, not error."""
    detections = tmp_path / "detections"
    target = _write_rule(detections, rule_id="rule-x", status="production")

    result = CliRunner().invoke(cli, [
        "enable", "rule-x", "--path", str(detections),
    ])
    assert result.exit_code == 0, result.output
    assert "not deprecated" in result.output
    # YAML untouched (no enable marker added).
    text = target.read_text(encoding="utf-8")
    assert "status: production" in text
    assert "# re-enabled" not in text


def test_reason_records_enable_reason_field(tmp_path: Path) -> None:
    detections = tmp_path / "detections"
    target = _write_rule(detections, rule_id="rule-x", status="deprecated")

    result = CliRunner().invoke(cli, [
        "enable", "rule-x", "--reason", "maintenance complete",
        "--path", str(detections),
    ])
    assert result.exit_code == 0, result.output
    text = target.read_text(encoding="utf-8")
    assert 'enableReason: "maintenance complete"' in text
    # When --reason is given, the comment form is NOT appended.
    assert "# re-enabled by contentops enable" not in text


def test_disable_comment_marker_is_stripped(tmp_path: Path) -> None:
    """When disable wrote the comment form (no --reason), enable strips it."""
    detections = tmp_path / "detections"
    target = _write_rule(
        detections, rule_id="rule-x", status="deprecated",
        trailing="# disabled by contentops disable on 2026-05-01\n",
    )

    result = CliRunner().invoke(cli, [
        "enable", "rule-x", "--path", str(detections),
    ])
    assert result.exit_code == 0, result.output
    text = target.read_text(encoding="utf-8")
    assert "# disabled by contentops disable" not in text


# ---------------------------------------------------------------------------
# cohort selectors
# ---------------------------------------------------------------------------


def test_pattern_dry_run_lists_matches(tmp_path: Path) -> None:
    detections = tmp_path / "detections"
    _write_rule(detections, rule_id="o365-rule-a", status="deprecated")
    _write_rule(detections, rule_id="o365-rule-b", status="deprecated")
    _write_rule(detections, rule_id="aad-rule-c", status="deprecated")

    result = CliRunner().invoke(cli, [
        "enable", "--pattern", "o365-*", "--path", str(detections),
    ])
    assert result.exit_code == 0, result.output
    assert "would re-enable up to 2 rule(s) -> status: experimental" in result.output
    assert "o365-rule-a" in result.output
    assert "o365-rule-b" in result.output
    assert "aad-rule-c" not in result.output
    # No mutation in dry-run.
    for rid in ("o365-rule-a", "o365-rule-b"):
        text = (detections / "sentinel_analytic" / f"{rid}.yml").read_text()
        assert "status: deprecated" in text


def test_pattern_with_yes_mutates_matching_rules(tmp_path: Path) -> None:
    detections = tmp_path / "detections"
    _write_rule(detections, rule_id="o365-rule-a", status="deprecated")
    _write_rule(detections, rule_id="o365-rule-b", status="deprecated")
    _write_rule(detections, rule_id="aad-rule-c", status="deprecated")

    result = CliRunner().invoke(cli, [
        "enable", "--pattern", "o365-*", "--yes",
        "--path", str(detections),
    ])
    assert result.exit_code == 0, result.output
    for rid in ("o365-rule-a", "o365-rule-b"):
        text = (detections / "sentinel_analytic" / f"{rid}.yml").read_text()
        assert "status: experimental" in text
    aad_text = (detections / "sentinel_analytic" / "aad-rule-c.yml").read_text()
    assert "status: deprecated" in aad_text  # untouched
    assert (
        "Cohort enable complete: 2 rule(s) restored to experimental, 0 skipped"
        in result.output
    )


def test_cohort_selector_filters_by_metadata_cohort(tmp_path: Path) -> None:
    detections = tmp_path / "detections"
    _write_rule(detections, rule_id="rule-a", status="deprecated", cohort="o365")
    _write_rule(detections, rule_id="rule-b", status="deprecated", cohort="o365")
    _write_rule(detections, rule_id="rule-c", status="deprecated", cohort="aad")

    result = CliRunner().invoke(cli, [
        "enable", "--cohort", "o365", "--yes",
        "--path", str(detections),
    ])
    assert result.exit_code == 0, result.output
    for rid in ("rule-a", "rule-b"):
        text = (detections / "sentinel_analytic" / f"{rid}.yml").read_text()
        assert "status: experimental" in text
    aad_text = (detections / "sentinel_analytic" / "rule-c.yml").read_text()
    assert "status: deprecated" in aad_text


def test_cohort_path_counts_already_active_as_skipped(tmp_path: Path) -> None:
    detections = tmp_path / "detections"
    _write_rule(detections, rule_id="rule-a", status="deprecated", cohort="o365")
    _write_rule(detections, rule_id="rule-b", status="production", cohort="o365")

    result = CliRunner().invoke(cli, [
        "enable", "--cohort", "o365", "--yes",
        "--path", str(detections),
    ])
    assert result.exit_code == 0, result.output
    assert (
        "Cohort enable complete: 1 rule(s) restored to experimental, 1 skipped"
        in result.output
    )


def test_no_matches_errors_cleanly(tmp_path: Path) -> None:
    detections = tmp_path / "detections"
    _write_rule(detections, rule_id="rule-a", status="deprecated", cohort="aad")

    result = CliRunner().invoke(cli, [
        "enable", "--cohort", "o365", "--path", str(detections),
    ])
    assert result.exit_code == 1
    assert "no rules matched --cohort 'o365'" in result.output


# ---------------------------------------------------------------------------
# mutex validation
# ---------------------------------------------------------------------------


def test_rule_id_and_pattern_mutex(tmp_path: Path) -> None:
    detections = tmp_path / "detections"
    _write_rule(detections, rule_id="rule-x", status="deprecated")
    result = CliRunner().invoke(cli, [
        "enable", "rule-x", "--pattern", "rule-*",
        "--path", str(detections),
    ])
    assert result.exit_code == 2
    assert "mutually exclusive" in result.output


def test_three_way_mutex(tmp_path: Path) -> None:
    detections = tmp_path / "detections"
    _write_rule(detections, rule_id="rule-x", status="deprecated", cohort="o365")
    result = CliRunner().invoke(cli, [
        "enable", "--pattern", "rule-*", "--cohort", "o365",
        "--path", str(detections),
    ])
    assert result.exit_code == 2
    assert "mutually exclusive" in result.output


def test_no_selector_errors(tmp_path: Path) -> None:
    detections = tmp_path / "detections"
    _write_rule(detections, rule_id="rule-x")
    result = CliRunner().invoke(cli, [
        "enable", "--path", str(detections),
    ])
    assert result.exit_code == 2
    assert "exactly one" in result.output


def test_to_must_be_known_status(tmp_path: Path) -> None:
    detections = tmp_path / "detections"
    _write_rule(detections, rule_id="rule-x", status="deprecated")
    result = CliRunner().invoke(cli, [
        "enable", "rule-x", "--to", "bogus",
        "--path", str(detections),
    ])
    assert result.exit_code == 2  # Click choice validation


# ---------------------------------------------------------------------------
# round-trip
# ---------------------------------------------------------------------------


def test_disable_then_enable_round_trip(tmp_path: Path) -> None:
    """End-to-end: disable a cohort with --reason, then enable the same
    cohort without --reason; assert status returns to experimental,
    disableReason is gone, and the YAML carries a fresh enable marker."""
    detections = tmp_path / "detections"
    # Seed two production rules in the same cohort.
    from .test_disable_pattern import _write_rule as _write_active_rule
    for rid in ("o365-rule-a", "o365-rule-b"):
        _write_active_rule(
            detections, rule_id=rid, status="production", cohort="o365",
        )

    # 1) Disable the cohort with a reason.
    result = CliRunner().invoke(cli, [
        "disable", "--cohort", "o365", "--yes",
        "--reason", "M365 maintenance",
        "--path", str(detections),
    ])
    assert result.exit_code == 0, result.output
    for rid in ("o365-rule-a", "o365-rule-b"):
        text = (detections / "sentinel_analytic" / f"{rid}.yml").read_text()
        assert "status: deprecated" in text
        assert "M365 maintenance" in text

    # 2) Enable the same cohort.
    result = CliRunner().invoke(cli, [
        "enable", "--cohort", "o365", "--yes",
        "--path", str(detections),
    ])
    assert result.exit_code == 0, result.output
    for rid in ("o365-rule-a", "o365-rule-b"):
        text = (detections / "sentinel_analytic" / f"{rid}.yml").read_text()
        assert "status: experimental" in text
        assert "disableReason" not in text
        assert "# re-enabled by contentops enable on " in text
