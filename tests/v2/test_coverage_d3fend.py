# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for the MITRE D3FEND coverage report (contentops.coverage.d3fend)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner
from pydantic import ValidationError

from contentops.cli import cli
from contentops.core.metadata import RuleMetadata
from contentops.coverage.d3fend import (
    compute_d3fend_report,
    covered_d3fend_ids,
    load_d3fend_techniques,
    render_json,
    render_markdown,
)


# ---------------------------------------------------------------------------
# RuleMetadata field + validator
# ---------------------------------------------------------------------------


def _base_meta(**overrides):
    base = dict(
        owner="x@example.com",
        runbookUrl="https://example.com/r",
        severity="medium",
        tactics=["Execution"],
        techniques=["T1059"],
        expectedAlertsPerDay=0,
        fpHandling="placeholder",
    )
    base.update(overrides)
    return base


def test_metadata_defaults_defensive_techniques_to_empty() -> None:
    """Existing envelopes must round-trip without setting the new field."""
    meta = RuleMetadata(**_base_meta())
    assert meta.defensiveTechniques == []


def test_metadata_accepts_well_formed_d3fend_ids() -> None:
    meta = RuleMetadata(**_base_meta(defensiveTechniques=["D3-NTA", "D3-PSA"]))
    assert meta.defensiveTechniques == ["D3-NTA", "D3-PSA"]


def test_metadata_rejects_malformed_d3fend_id() -> None:
    with pytest.raises(ValidationError) as exc:
        RuleMetadata(**_base_meta(defensiveTechniques=["d3-nta"]))
    assert "D3-XXX" in str(exc.value)


def test_metadata_rejects_attack_id_in_defensive_field() -> None:
    """T-prefix is for the ATT&CK techniques field; D-prefix only here."""
    with pytest.raises(ValidationError):
        RuleMetadata(**_base_meta(defensiveTechniques=["T1059"]))


# ---------------------------------------------------------------------------
# load_d3fend_techniques — bundled list
# ---------------------------------------------------------------------------


def test_bundled_d3fend_list_loads() -> None:
    techniques, label = load_d3fend_techniques()
    assert techniques, "bundled D3FEND list should not be empty"
    # Sample a couple of canonical entries the curated list ships with.
    ids = {t.id for t in techniques}
    assert "D3-NTA" in ids
    assert "D3-PSA" in ids
    assert "MITRE D3FEND" in label or "d3fend" in label.lower()


def test_d3fend_techniques_carry_canonical_tactics() -> None:
    techniques, _ = load_d3fend_techniques()
    tactics_seen = {t for tech in techniques for t in tech.tactics}
    # The bundled list spans at least Detect + Harden + Isolate.
    assert "Detect" in tactics_seen
    assert "Harden" in tactics_seen


def test_load_custom_d3fend_file(tmp_path: Path) -> None:
    payload = {
        "schema_version": "1.0",
        "source": "test-fixture",
        "techniques": [
            {"id": "D3-FOO", "name": "Foo technique", "tactics": ["Detect"]},
        ],
    }
    target = tmp_path / "d3fend.json"
    target.write_text(json.dumps(payload), encoding="utf-8")
    techniques, label = load_d3fend_techniques(target)
    assert [t.id for t in techniques] == ["D3-FOO"]
    assert label == "test-fixture"


# ---------------------------------------------------------------------------
# compute_d3fend_report
# ---------------------------------------------------------------------------


def _fake_detections(tmp_path: Path, *envelopes: dict) -> Path:
    """Materialise minimal envelope YAMLs into a temp detections dir."""
    import yaml

    root = tmp_path / "detections" / "sentinel_analytic"
    root.mkdir(parents=True)
    for i, env in enumerate(envelopes):
        (root / f"rule-{i}.yml").write_text(yaml.safe_dump(env), encoding="utf-8")
    return tmp_path / "detections"


def test_covered_ids_reads_envelope_metadata(tmp_path: Path) -> None:
    detections = _fake_detections(
        tmp_path,
        {
            "id": "rule-a",
            "version": "0.1.0",
            "asset": "sentinel_analytic",
            "status": "experimental",
            "metadata": _base_meta(defensiveTechniques=["D3-NTA"]),
            "payload": {"query": "T", "displayName": "Rule A", "queryFrequency": "PT5M",
                        "queryPeriod": "PT5M", "triggerOperator": "GreaterThan",
                        "triggerThreshold": 0, "severity": "Medium", "enabled": True,
                        "tactics": [], "subTechniques": []},
        },
        {
            "id": "rule-b",
            "version": "0.1.0",
            "asset": "sentinel_analytic",
            "status": "experimental",
            "metadata": _base_meta(defensiveTechniques=["D3-PSA"]),
            "payload": {"query": "T", "displayName": "Rule B", "queryFrequency": "PT5M",
                        "queryPeriod": "PT5M", "triggerOperator": "GreaterThan",
                        "triggerThreshold": 0, "severity": "Medium", "enabled": True,
                        "tactics": [], "subTechniques": []},
        },
    )
    covered = covered_d3fend_ids(detections)
    assert covered == {"D3-NTA", "D3-PSA"}


def test_compute_report_separates_covered_and_uncovered(tmp_path: Path) -> None:
    detections = _fake_detections(
        tmp_path,
        {
            "id": "rule-a",
            "version": "0.1.0",
            "asset": "sentinel_analytic",
            "status": "experimental",
            "metadata": _base_meta(defensiveTechniques=["D3-NTA"]),
            "payload": {"query": "T", "displayName": "Rule A", "queryFrequency": "PT5M",
                        "queryPeriod": "PT5M", "triggerOperator": "GreaterThan",
                        "triggerThreshold": 0, "severity": "Medium", "enabled": True,
                        "tactics": [], "subTechniques": []},
        },
    )
    techniques, label = load_d3fend_techniques()
    report = compute_d3fend_report(detections, techniques, source_label=label)
    assert report.total_covered >= 1
    assert report.total_uncovered == report.total_techniques - report.total_covered
    # D3-NTA should appear in the Detect tactic's covered list.
    detect = next(b for b in report.tactics if b.tactic == "Detect")
    covered_ids = {c.id for c in detect.covered}
    assert "D3-NTA" in covered_ids


def test_render_markdown_emits_section_headers() -> None:
    techniques, label = load_d3fend_techniques()
    # Empty detections: every technique uncovered.
    report = compute_d3fend_report(Path("nonexistent"), techniques, source_label=label)
    md = render_markdown(report)
    assert "# MITRE D3FEND coverage" in md
    assert "Detect" in md
    assert md.endswith("\n")


def test_render_json_round_trips() -> None:
    techniques, label = load_d3fend_techniques()
    report = compute_d3fend_report(Path("nonexistent"), techniques, source_label=label)
    js = json.loads(render_json(report))
    assert js["total_techniques"] == report.total_techniques
    assert isinstance(js["tactics"], list)
    assert all("tactic" in t for t in js["tactics"])


# ---------------------------------------------------------------------------
# CLI surface
# ---------------------------------------------------------------------------


def test_cli_coverage_d3fend_renders(tmp_path: Path) -> None:
    detections = _fake_detections(
        tmp_path,
        {
            "id": "rule-a",
            "version": "0.1.0",
            "asset": "sentinel_analytic",
            "status": "experimental",
            "metadata": _base_meta(defensiveTechniques=["D3-NTA"]),
            "payload": {"query": "T", "displayName": "Rule A", "queryFrequency": "PT5M",
                        "queryPeriod": "PT5M", "triggerOperator": "GreaterThan",
                        "triggerThreshold": 0, "severity": "Medium", "enabled": True,
                        "tactics": [], "subTechniques": []},
        },
    )
    runner = CliRunner()
    result = runner.invoke(
        cli, ["coverage", "--path", str(detections), "--d3fend", "--format", "markdown"],
    )
    assert result.exit_code == 0, result.output
    assert "D3FEND" in result.output
    assert "D3-NTA" in result.output
