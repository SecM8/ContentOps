# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for YAML I/O utilities."""

from __future__ import annotations

from pathlib import Path

from contentops.utils.yaml_io import (
    discover_rules,
    is_template_path,
    load_rule,
    to_defender_body,
    to_sentinel_body,
)

FIXTURES = Path(__file__).parent / "fixtures"


class TestLoadRule:
    def test_load_sentinel_rule(self) -> None:
        pipeline_fields, payload = load_rule(FIXTURES / "sentinel_scheduled.yml")
        assert pipeline_fields["id"] == "sentinel-test-scheduled-001"
        assert pipeline_fields["platform"] == "sentinel"
        assert payload["kind"] == "Scheduled"
        assert payload["displayName"] == "Test Scheduled Rule"

    def test_load_defender_rule(self) -> None:
        pipeline_fields, payload = load_rule(FIXTURES / "defender_rule.yml")
        assert pipeline_fields["id"] == "defender-test-rule-001"
        assert pipeline_fields["platform"] == "defender"
        assert payload["displayName"] == "Test Defender Rule"


class TestToSentinelBody:
    def test_extracts_kind(self) -> None:
        payload = {
            "kind": "Scheduled",
            "displayName": "Test",
            "severity": "High",
            "query": "test",
        }
        body = to_sentinel_body(payload)
        assert body["kind"] == "Scheduled"
        assert "kind" not in body["properties"]
        assert body["properties"]["displayName"] == "Test"

    def test_does_not_mutate_original(self) -> None:
        payload = {"kind": "NRT", "displayName": "Test", "query": "test"}
        to_sentinel_body(payload)
        assert "kind" in payload


class TestToDefenderBody:
    def test_passthrough(self) -> None:
        payload = {"displayName": "Test", "isEnabled": True}
        body = to_defender_body(payload)
        assert body is payload


class TestIsTemplatePath:
    def test_template_path(self) -> None:
        assert is_template_path(Path("detections/templates/foo.yml"))

    def test_non_template_path(self) -> None:
        assert not is_template_path(Path("detections/sentinel/foo.yml"))


class TestDiscoverRules:
    def test_discovers_real_rules(self, tmp_path: Path) -> None:
        sentinel_dir = tmp_path / "sentinel"
        sentinel_dir.mkdir()
        (sentinel_dir / "rule1.yml").write_text("id: test")

        defender_dir = tmp_path / "defender"
        defender_dir.mkdir()
        (defender_dir / "rule2.yml").write_text("id: test2")

        templates_dir = tmp_path / "templates"
        templates_dir.mkdir()
        (templates_dir / "tmpl.yml").write_text("id: template")

        rules = discover_rules(tmp_path)
        assert len(rules) == 2
        names = {p.name for p in rules}
        assert names == {"rule1.yml", "rule2.yml"}

    def test_skips_templates_in_sentinel(self, tmp_path: Path) -> None:
        nested = tmp_path / "sentinel" / "templates"
        nested.mkdir(parents=True)
        (nested / "rule.yml").write_text("id: test")

        rules = discover_rules(tmp_path)
        assert len(rules) == 0
