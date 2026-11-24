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

    # --- entities: impactedAssets is deprecated in favour of entityMappings ---

    def test_entity_mappings_without_impacted_assets_is_valid(self) -> None:
        """A rule built with entity mapping only carries an empty impactedAssets."""
        validate_defender_payload(_defender_payload())

    def test_rule_without_any_entity_is_rejected(self) -> None:
        template = _alert_template(entityMappings={"hosts": [], "accounts": [], "ips": []})
        with pytest.raises(ValueError, match="impactedAssets or entityMappings"):
            validate_defender_payload(_defender_payload(alert_template=template))

    def test_entity_mapping_with_only_blank_columns_is_rejected(self) -> None:
        """The service returns unused mapping columns as empty strings."""
        template = _alert_template(
            entityMappings={"hosts": [{"deviceIdColumn": "", "nameColumn": ""}]},
        )
        with pytest.raises(ValueError, match="impactedAssets or entityMappings"):
            validate_defender_payload(_defender_payload(alert_template=template))

    def test_blank_columns_with_an_odata_annotation_are_rejected(self) -> None:
        """An ``@odata.type`` annotation is not a query column: a mapping
        whose columns are all blank identifies no entity, whatever
        annotation it carries."""
        template = _alert_template(entityMappings={"hosts": [{
            "@odata.type": "#microsoft.graph.security.hostEntityMapping",
            "deviceIdColumn": "", "nameColumn": "",
        }]})
        with pytest.raises(ValueError, match="impactedAssets or entityMappings"):
            validate_defender_payload(_defender_payload(alert_template=template))

    def test_filled_column_with_an_odata_annotation_is_valid(self) -> None:
        template = _alert_template(entityMappings={"hosts": [{
            "@odata.type": "#microsoft.graph.security.hostEntityMapping",
            "deviceIdColumn": "DeviceId",
        }]})
        validate_defender_payload(_defender_payload(alert_template=template))

    def test_filled_mapping_property_that_is_not_an_annotation_still_counts(self) -> None:
        """Only OData annotations are set aside. A mapping property the
        service adds later still identifies an entity whatever it is
        called, so a new property cannot fail validation for every rule
        that uses it."""
        template = _alert_template(entityMappings={"hosts": [{
            "deviceIdColumn": "", "identifierAddedLater": "DeviceId",
        }]})
        validate_defender_payload(_defender_payload(alert_template=template))

    def test_rule_with_neither_entity_property_is_rejected(self) -> None:
        template = {"title": "Test", "severity": "medium"}
        with pytest.raises(ValueError, match="impactedAssets or entityMappings"):
            validate_defender_payload(_defender_payload(alert_template=template))

    # --- schedule: period is deprecated in favour of frequency / lookback ---

    @pytest.mark.parametrize(
        "schedule",
        [
            {"frequency": "PT5M", "lookback": "PT1H"},
            {"frequency": "P14D", "lookback": "P14D"},
            {"frequency": "PT30M", "lookback": "PT47H59M"},
            {"frequency": "PT1H", "lookback": "P14D"},
            {"frequency": "PT23H", "lookback": "P14D"},
            {"frequency": "P1D", "lookback": "P30D"},
            {"frequency": "P1D", "lookback": "P1D"},
            {"frequency": "PT1H"},
            {"frequency": "PT0S"},
            {"frequency": "PT0S", "lookback": None},
            {"frequency": "P1DT12H", "lookback": "P2DT6H"},
            # null means "not set", exactly like an absent key.
            {"period": "1H", "frequency": None},
            {"frequency": "PT1H", "lookback": None},
            # A legacy period with a lookback inside the limits.
            {"period": "1H"},
            {"period": "0"},
            {"period": "0", "lookback": None},
            {"period": "1H", "lookback": "PT4H"},
            {"period": "24H", "lookback": "P30D"},
        ],
    )
    def test_schedule_within_service_limits_is_valid(self, schedule: dict) -> None:
        validate_defender_payload(_defender_payload(schedule=schedule))

    @pytest.mark.parametrize(
        ("schedule", "message"),
        [
            ({"frequency": "PT4M", "lookback": "PT1H"}, "frequency must be between 5 minutes and 14 days"),
            ({"frequency": "PT1M", "lookback": "PT30H"}, "frequency must be between 5 minutes and 14 days"),
            ({"frequency": "P15D", "lookback": "P30D"}, "frequency must be between 5 minutes and 14 days"),
            ({"frequency": "PT30M", "lookback": "P2D"}, "lookback must be less than 48 hours"),
            ({"frequency": "PT1H", "lookback": "P15D"}, "lookback must be at most 14 days"),
            ({"frequency": "P1D", "lookback": "P31D"}, "lookback must be at most 30 days"),
            ({"frequency": "P2D", "lookback": "P1D"}, "lookback must be at least the frequency"),
            ({"frequency": "PT0S", "lookback": "PT1H"}, "lookback is not supported for continuous"),
            ({"frequency": "1H"}, "frequency must be an ISO 8601 duration"),
            ({"frequency": "PT1H", "lookback": "4H"}, "lookback must be an ISO 8601 duration"),
            # A "T" must be followed by at least one time component.
            ({"frequency": "P1DT"}, "frequency must be an ISO 8601 duration"),
            ({"frequency": "P2WT"}, "frequency must be an ISO 8601 duration"),
            ({"frequency": "PT"}, "frequency must be an ISO 8601 duration"),
            ({"frequency": "PT1H", "lookback": "P1DT"}, "lookback must be an ISO 8601 duration"),
            # A blank string is a value, and not a duration. It is not read
            # as "not set", so it never falls back to the legacy period.
            ({"period": "1H", "frequency": ""}, "frequency must be an ISO 8601 duration"),
            ({"period": "1H", "frequency": "   "}, "frequency must be an ISO 8601 duration"),
            ({"frequency": "PT1H", "lookback": ""}, "lookback must be an ISO 8601 duration"),
            ({"frequency": "PT1H", "lookback": "  "}, "lookback must be an ISO 8601 duration"),
            # The lookback limits hold whichever key states the frequency.
            ({"period": "1H", "lookback": "P15D"}, "lookback must be at most 14 days"),
            ({"period": "24H", "lookback": "P31D"}, "lookback must be at most 30 days"),
            ({"period": "3H", "lookback": "PT1H"}, "lookback must be at least the frequency"),
            ({"period": "0", "lookback": "PT1H"}, "lookback is not supported for continuous"),
            ({"period": "1H", "lookback": "4H"}, "lookback must be an ISO 8601 duration"),
            # Graph rejects weeks (`P1W` is not an Edm.Duration; checked against a
            # tenant), so a rule written in weeks would pass here and fail at deploy.
            ({"frequency": "P2W", "lookback": "P14D"}, "frequency in weeks is not accepted by Graph; write P14D"),
            ({"frequency": "P1D", "lookback": "P1W"}, "lookback in weeks is not accepted by Graph; write P7D"),
            # The week form stands alone: weeks are not combined with other units.
            ({"frequency": "P1W1D"}, "frequency must be an ISO 8601 duration"),
            ({"frequency": "P1WT1H"}, "frequency must be an ISO 8601 duration"),
            ({"frequency": "PT1H", "lookback": "P1W1D"}, "lookback must be an ISO 8601 duration"),
            # The value is checked exactly as it would be sent: no padding
            # around it and plain digits only.
            ({"frequency": " PT1H"}, "frequency must be an ISO 8601 duration"),
            ({"frequency": "PT1H "}, "frequency must be an ISO 8601 duration"),
            ({"frequency": "PT1H\n"}, "frequency must be an ISO 8601 duration"),
            ({"frequency": "PT1H", "lookback": " PT4H"}, "lookback must be an ISO 8601 duration"),
            ({"frequency": "PT١H"}, "frequency must be an ISO 8601 duration"),
            # A number too large to be a duration is a validation error, not a crash.
            ({"frequency": "P" + "9" * 30 + "D"}, "frequency must be an ISO 8601 duration"),
            ({"frequency": "PT1H", "lookback": "PT" + "9" * 30 + "H"}, "lookback must be an ISO 8601 duration"),
        ],
    )
    def test_schedule_outside_service_limits_is_rejected(self, schedule: dict, message: str) -> None:
        with pytest.raises(ValueError, match=message):
            validate_defender_payload(_defender_payload(schedule=schedule))

    def test_unexpected_period_is_accepted_when_frequency_is_set(self) -> None:
        """period is a deprecated echo of frequency; frequency decides."""
        schedule = {"period": "15M", "frequency": "PT15M", "lookback": "PT1H"}
        validate_defender_payload(_defender_payload(schedule=schedule))

    def test_schedule_without_period_or_frequency_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="schedule requires frequency"):
            validate_defender_payload(_defender_payload(schedule={}))

    # --- properties the model does not know about ---

    def test_unknown_top_level_property_is_ignored(self) -> None:
        payload = _defender_payload()
        payload["propertyAddedByTheService"] = "value"
        validate_defender_payload(payload)

    def test_unknown_query_condition_property_is_ignored(self) -> None:
        payload = _defender_payload()
        payload["queryCondition"]["propertyAddedByTheService"] = "value"
        validate_defender_payload(payload)

    def test_missing_display_name_is_still_rejected(self) -> None:
        payload = _defender_payload()
        del payload["displayName"]
        with pytest.raises(ValueError, match="displayName"):
            validate_defender_payload(payload)


def _alert_template(**overrides: object) -> dict:
    """Alert template as the service returns it for an entity-mapping-only rule."""
    template: dict = {
        "title": "Test",
        "severity": "medium",
        "impactedAssets": [],
        "entityMappings": {
            "hosts": [],
            "accounts": [],
            "ips": [{"addressColumn": "IPAddress", "scopeColumn": ""}],
        },
    }
    template.update(overrides)
    return template


def _defender_payload(
    *, schedule: dict | None = None, alert_template: dict | None = None,
) -> dict:
    """Minimal Defender payload; ``schedule`` / ``alert_template`` replace the defaults."""
    return {
        "displayName": "Test",
        "status": "enabled",
        "queryCondition": {"queryText": "SigninLogs | take 1"},
        "schedule": {"frequency": "PT1H", "lookback": "PT4H"} if schedule is None else schedule,
        "detectionAction": {
            "alertTemplate": _alert_template() if alert_template is None else alert_template,
        },
    }
