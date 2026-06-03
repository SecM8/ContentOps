# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for Pydantic models."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from contentops.models import (
    DefenderPayload,
    RuleEnvelope,
    SentinelNRTPayload,
    SentinelScheduledPayload,
    validate_defender_payload,
    validate_sentinel_payload,
)

FIXTURES = Path(__file__).parent / "fixtures"


class TestRuleEnvelope:
    def test_valid_envelope(self) -> None:
        envelope = RuleEnvelope(
            id="sentinel-test-001",
            version="1.0.0",
            platform="sentinel",
            status="production",
        )
        assert envelope.id == "sentinel-test-001"
        assert envelope.platform.value == "sentinel"

    def test_invalid_id_uppercase(self) -> None:
        with pytest.raises(ValueError):
            RuleEnvelope(
                id="Sentinel-Test-001",
                version="1.0.0",
                platform="sentinel",
                status="production",
            )

    def test_invalid_platform(self) -> None:
        with pytest.raises(ValueError):
            RuleEnvelope(
                id="test-001",
                version="1.0.0",
                platform="splunk",
                status="production",
            )

    def test_invalid_status(self) -> None:
        with pytest.raises(ValueError):
            RuleEnvelope(
                id="test-001",
                version="1.0.0",
                platform="sentinel",
                status="draft",
            )


class TestSentinelScheduled:
    def test_valid_scheduled_from_fixture(self) -> None:
        raw = yaml.safe_load((FIXTURES / "sentinel_scheduled.yml").read_text())
        payload = raw["sentinel"]
        model = validate_sentinel_payload(payload)
        assert isinstance(model, SentinelScheduledPayload)
        assert model.displayName == "Test Scheduled Rule"
        assert model.severity.value == "High"

    def test_missing_query_frequency(self) -> None:
        with pytest.raises(ValueError):
            SentinelScheduledPayload(
                kind="Scheduled",
                displayName="Test",
                severity="High",
                query="test",
                queryPeriod="PT1H",
                triggerOperator="GreaterThan",
                triggerThreshold=0,
            )

    def test_entity_mappings_max_ten(self) -> None:
        """The cap was 5 until 2026-05-18 when adopter test surfaced a
        real production-deployed rule with 6 entityMappings. Microsoft's
        2025-07-01-preview ARM contract allows up to 10. Boundary at 11
        is over the cap. See tests/v2/test_entity_mappings_cap.py for
        the comprehensive boundary tests."""
        eleven_mappings = [
            {"entityType": "IP", "fieldMappings": [{"identifier": "Address", "columnName": f"col{i}"}]}
            for i in range(11)
        ]
        with pytest.raises(ValueError):
            SentinelScheduledPayload(
                kind="Scheduled",
                displayName="Test",
                severity="High",
                query="test",
                queryFrequency="PT5M",
                queryPeriod="PT1H",
                triggerOperator="GreaterThan",
                triggerThreshold=0,
                entityMappings=eleven_mappings,
            )

    def test_selected_matching_requires_groupby(self) -> None:
        with pytest.raises(ValueError, match="groupBy"):
            SentinelScheduledPayload(
                kind="Scheduled",
                displayName="Test",
                severity="High",
                query="test",
                queryFrequency="PT5M",
                queryPeriod="PT1H",
                triggerOperator="GreaterThan",
                triggerThreshold=0,
                incidentConfiguration={
                    "createIncident": True,
                    "groupingConfiguration": {
                        "enabled": True,
                        "matchingMethod": "Selected",
                        "groupByEntities": [],
                    },
                },
            )

    def test_negative_threshold_rejected(self) -> None:
        with pytest.raises(ValueError):
            SentinelScheduledPayload(
                kind="Scheduled",
                displayName="Test",
                severity="High",
                query="test",
                queryFrequency="PT5M",
                queryPeriod="PT1H",
                triggerOperator="GreaterThan",
                triggerThreshold=-1,
            )


class TestSentinelNRT:
    def test_valid_nrt_from_fixture(self) -> None:
        raw = yaml.safe_load((FIXTURES / "sentinel_nrt.yml").read_text())
        payload = raw["sentinel"]
        model = validate_sentinel_payload(payload)
        assert isinstance(model, SentinelNRTPayload)
        assert model.kind == "NRT"

    def test_nrt_rejects_scheduled_fields(self) -> None:
        with pytest.raises(ValueError, match="NRT rules must not have"):
            SentinelNRTPayload(
                kind="NRT",
                displayName="Test",
                severity="Medium",
                query="test",
                queryFrequency="PT5M",
            )


class TestDefender:
    def test_valid_defender_from_fixture(self) -> None:
        raw = yaml.safe_load((FIXTURES / "defender_rule.yml").read_text())
        payload = raw["defender"]
        model = validate_defender_payload(payload)
        assert isinstance(model, DefenderPayload)
        assert model.displayName == "Test Defender Rule"

    def test_missing_impacted_assets(self) -> None:
        with pytest.raises(ValueError):
            DefenderPayload(
                displayName="Test",
                isEnabled=True,
                queryCondition={"queryText": "test"},
                schedule={"period": "1H"},
                detectionAction={
                    "alertTemplate": {
                        "title": "Test",
                        "severity": "medium",
                        "impactedAssets": [],
                    },
                },
            )

    def test_invalid_schedule_period(self) -> None:
        with pytest.raises(ValueError):
            DefenderPayload(
                displayName="Test",
                isEnabled=True,
                queryCondition={"queryText": "test"},
                schedule={"period": "2H"},
                detectionAction={
                    "alertTemplate": {
                        "title": "Test",
                        "severity": "medium",
                        "impactedAssets": [
                            {"@odata.type": "#microsoft.graph.security.impactedDeviceAsset", "identifier": "deviceId"}
                        ],
                    },
                },
            )

    def test_invalid_severity(self) -> None:
        with pytest.raises(ValueError):
            DefenderPayload(
                displayName="Test",
                isEnabled=True,
                queryCondition={"queryText": "test"},
                schedule={"period": "1H"},
                detectionAction={
                    "alertTemplate": {
                        "title": "Test",
                        "severity": "critical",
                        "impactedAssets": [
                            {"@odata.type": "#microsoft.graph.security.impactedDeviceAsset", "identifier": "deviceId"}
                        ],
                    },
                },
            )
