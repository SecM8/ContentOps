# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the additional Sentinel alert rule kinds.

Covers ``MicrosoftSecurityIncidentCreation``, ``Fusion``,
``MLBehaviorAnalytics`` and ``ThreatIntelligence``. The Scheduled and
NRT kinds already have coverage in tests/test_models.py and
tests/v2/test_apply_verify_analytic.py.
"""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from contentops.config import SentinelConfig
from contentops.core.asset import Asset
from contentops.core.envelope import EnvelopeV2
from contentops.core.handler import LoadedAsset
from contentops.core.result import PlanAction
from contentops.handlers.sentinel_analytic import SentinelAnalyticHandler
from contentops.models import (
    SentinelFusionPayload,
    SentinelMLBehaviorAnalyticsPayload,
    SentinelMicrosoftSecurityIncidentCreationPayload,
    SentinelThreatIntelligencePayload,
    validate_sentinel_payload,
)
from contentops.providers import sentinel_arm
from contentops.providers.sentinel_arm import SentinelArmProvider


# ---------------------------------------------------------------------------
# Pydantic model validation
# ---------------------------------------------------------------------------


class TestMicrosoftSecurityIncidentCreation:
    def test_valid_minimal(self) -> None:
        payload = {
            "kind": "MicrosoftSecurityIncidentCreation",
            "displayName": "MDC alerts -> incidents",
            "productFilter": "Azure Security Center",
        }
        model = validate_sentinel_payload(payload)
        assert isinstance(model, SentinelMicrosoftSecurityIncidentCreationPayload)
        assert model.enabled is True

    def test_severities_filter_typed(self) -> None:
        payload = {
            "kind": "MicrosoftSecurityIncidentCreation",
            "displayName": "MDC high only",
            "productFilter": "Azure Security Center",
            "severitiesFilter": ["High", "Medium"],
        }
        model = SentinelMicrosoftSecurityIncidentCreationPayload(**payload)
        assert [s.value for s in model.severitiesFilter or []] == ["High", "Medium"]

    def test_unknown_product_rejected(self) -> None:
        with pytest.raises(ValueError):
            SentinelMicrosoftSecurityIncidentCreationPayload(
                kind="MicrosoftSecurityIncidentCreation",
                displayName="Bogus",
                productFilter="Splunk",  # type: ignore[arg-type]
            )

    def test_rebranded_product_name_rejected(self) -> None:
        # ARM still validates against the legacy product names even at
        # api-version 2025-09-01 — this test pins the limitation so a
        # well-meaning future contributor can't add the rebranded name
        # and silently break every prod deploy.
        with pytest.raises(ValueError):
            SentinelMicrosoftSecurityIncidentCreationPayload(
                kind="MicrosoftSecurityIncidentCreation",
                displayName="Rebranded",
                productFilter="Microsoft Defender for Cloud",  # type: ignore[arg-type]
            )

    def test_overlapping_filters_rejected(self) -> None:
        with pytest.raises(ValueError, match="overlap"):
            SentinelMicrosoftSecurityIncidentCreationPayload(
                kind="MicrosoftSecurityIncidentCreation",
                displayName="Overlap",
                productFilter="Azure Security Center",
                displayNamesFilter=["Suspicious activity"],
                displayNamesExcludeFilter=["Suspicious activity"],
            )


class TestFusion:
    def test_valid_minimal(self) -> None:
        payload = {
            "kind": "Fusion",
            "alertRuleTemplateName": "f71aba3d-28fb-450b-b192-4e76a83015c8",
        }
        model = validate_sentinel_payload(payload)
        assert isinstance(model, SentinelFusionPayload)
        assert model.enabled is True

    def test_source_settings_round_trip(self) -> None:
        payload = {
            "kind": "Fusion",
            "alertRuleTemplateName": "f71aba3d-28fb-450b-b192-4e76a83015c8",
            "enabled": True,
            "sourceSettings": [
                {
                    "sourceName": "Anomaly",
                    "enabled": True,
                    "sourceSubTypes": [
                        {"sourceSubTypeName": "AnomalousAccessToCloudResources",
                         "enabled": False, "severityFilters": {"filters": []}}
                    ],
                }
            ],
        }
        model = SentinelFusionPayload(**payload)
        assert model.sourceSettings is not None
        assert model.sourceSettings[0].sourceSubTypes[0].enabled is False

    def test_template_required(self) -> None:
        with pytest.raises(ValueError):
            SentinelFusionPayload(kind="Fusion")  # type: ignore[call-arg]


class TestMLBehaviorAnalytics:
    def test_valid_minimal(self) -> None:
        payload = {
            "kind": "MLBehaviorAnalytics",
            "alertRuleTemplateName": "fa118b98-de46-4e94-87f9-8e6d5060b60b",
        }
        model = validate_sentinel_payload(payload)
        assert isinstance(model, SentinelMLBehaviorAnalyticsPayload)

    def test_template_required(self) -> None:
        with pytest.raises(ValueError):
            SentinelMLBehaviorAnalyticsPayload(kind="MLBehaviorAnalytics")  # type: ignore[call-arg]


class TestThreatIntelligence:
    def test_valid_minimal(self) -> None:
        payload = {
            "kind": "ThreatIntelligence",
            "alertRuleTemplateName": "a1cf9c9b-2273-4664-a868-f60a23ed1d20",
        }
        model = validate_sentinel_payload(payload)
        assert isinstance(model, SentinelThreatIntelligencePayload)


def test_dispatcher_lists_all_known_kinds() -> None:
    with pytest.raises(ValueError, match="MicrosoftSecurityIncidentCreation"):
        validate_sentinel_payload({"kind": "Bogus"})


# ---------------------------------------------------------------------------
# Handler apply — happy path verification with kind-aware hashing
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    monkeypatch.setattr(sentinel_arm.time, "sleep", lambda *_: None)


def _client_with(transport: httpx.MockTransport) -> SentinelArmProvider:
    cfg = SentinelConfig(subscriptionId="sub", resourceGroup="rg", workspaceName="ws")
    c = SentinelArmProvider(cfg, token="t")
    c._client.close()
    c._client = httpx.Client(
        base_url="https://management.azure.com", transport=transport,
        headers={"Authorization": "Bearer t"},
    )
    return c


def _loaded(payload: dict) -> LoadedAsset:
    env = EnvelopeV2(
        id="rule-1", version="0.1.0",
        asset=Asset.SENTINEL_ANALYTIC, status="production",
    )
    return LoadedAsset(path=Path("test.yml"), envelope=env, payload=dict(payload))


def _msi_payload() -> dict:
    return {
        "kind": "MicrosoftSecurityIncidentCreation",
        "displayName": "MDC alerts -> incidents",
        "productFilter": "Azure Security Center",
        "severitiesFilter": ["High"],
        "enabled": True,
    }


def _msi_remote() -> dict:
    return {
        "name": "rule-1",
        "kind": "MicrosoftSecurityIncidentCreation",
        "etag": 'W/"abc"',
        "properties": {
            "displayName": "MDC alerts -> incidents",
            "productFilter": "Azure Security Center",
            "severitiesFilter": ["High"],
            "displayNamesFilter": None,
            "displayNamesExcludeFilter": None,
            "enabled": True,
            "lastModifiedUtc": "2024-01-01T00:00:00Z",
        },
    }


def test_msi_apply_verifies_hash() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(200, json=_msi_remote())
        return httpx.Response(200, json=_msi_remote())

    client = _client_with(httpx.MockTransport(handler))
    h = SentinelAnalyticHandler(lambda: client)
    result = h.apply(_loaded(_msi_payload()))

    assert result.status == "success"
    assert result.action is PlanAction.UPDATE
    assert result.verified is True


def _fusion_payload() -> dict:
    return {
        "kind": "Fusion",
        "alertRuleTemplateName": "f71aba3d-28fb-450b-b192-4e76a83015c8",
        "enabled": True,
    }


def _fusion_remote() -> dict:
    return {
        "name": "rule-1",
        "kind": "Fusion",
        "etag": 'W/"abc"',
        "properties": {
            "alertRuleTemplateName": "f71aba3d-28fb-450b-b192-4e76a83015c8",
            "enabled": True,
            # ARM frequently echoes back a sourceSettings overlay we didn't send.
            # The hash projection ignores it because Fusion is enable-only.
            "sourceSettings": [
                {"sourceName": "Anomaly", "enabled": True, "sourceSubTypes": []}
            ],
            "lastModifiedUtc": "2024-01-01T00:00:00Z",
        },
    }


def test_fusion_apply_verifies_hash_ignoring_source_settings_echo() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_fusion_remote())

    client = _client_with(httpx.MockTransport(handler))
    h = SentinelAnalyticHandler(lambda: client)
    result = h.apply(_loaded(_fusion_payload()))

    assert result.status == "success"
    assert result.verified is True


def test_mlba_apply_verifies_hash() -> None:
    payload = {
        "kind": "MLBehaviorAnalytics",
        "alertRuleTemplateName": "fa118b98-de46-4e94-87f9-8e6d5060b60b",
        "enabled": True,
    }
    remote = {
        "name": "rule-1",
        "kind": "MLBehaviorAnalytics",
        "etag": 'W/"abc"',
        "properties": {
            "alertRuleTemplateName": "fa118b98-de46-4e94-87f9-8e6d5060b60b",
            "enabled": True,
            "lastModifiedUtc": "2024-01-01T00:00:00Z",
        },
    }

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=remote)

    client = _client_with(httpx.MockTransport(handler))
    h = SentinelAnalyticHandler(lambda: client)
    result = h.apply(_loaded(payload))

    assert result.status == "success"
    assert result.verified is True


def test_threat_intel_apply_verifies_hash() -> None:
    payload = {
        "kind": "ThreatIntelligence",
        "alertRuleTemplateName": "a1cf9c9b-2273-4664-a868-f60a23ed1d20",
        "enabled": True,
    }
    remote = {
        "name": "rule-1",
        "kind": "ThreatIntelligence",
        "etag": 'W/"abc"',
        "properties": {
            "alertRuleTemplateName": "a1cf9c9b-2273-4664-a868-f60a23ed1d20",
            "enabled": True,
        },
    }

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=remote)

    client = _client_with(httpx.MockTransport(handler))
    h = SentinelAnalyticHandler(lambda: client)
    result = h.apply(_loaded(payload))

    assert result.status == "success"
    assert result.verified is True


# ---------------------------------------------------------------------------
# Templated-rule displayName strip (O.1 — ARM 400 "Read-only" guard)
# ---------------------------------------------------------------------------


def _captured_put_body_handler(captured: list[dict]):
    """MockTransport handler that records the PUT body for templated tests.

    Returns the request body back as the GET / PUT response, with a
    fabricated etag so the post-apply verify step can run. The captured
    list collects every PUT body the handler saw.
    """
    import json as _json

    def _handler(request: httpx.Request) -> httpx.Response:
        if request.method == "PUT":
            body = _json.loads(request.content.decode())
            captured.append(body)
            # Echo back the body as the response, with a synthetic etag.
            echo = {
                "name": "rule-1",
                "kind": body.get("kind"),
                "etag": 'W/"echoed"',
                "properties": {
                    **(body.get("properties") or {}),
                    "lastModifiedUtc": "2024-01-01T00:00:00Z",
                },
            }
            return httpx.Response(200, json=echo)
        # GET (pre-PUT etag fetch + post-PUT verify): return 404 on first
        # call so the create path runs; we don't track call count here
        # because the apply code already handles "existing is None" cleanly.
        return httpx.Response(404)

    return _handler


def test_fusion_apply_keeps_only_allowlist_in_put_body() -> None:
    """Fusion rules: ARM rejects most of the body as read-only — peels
    back fields one at a time (displayName, then description, then…).
    The apply path narrows the PUT body to the allowlist
    {alertRuleTemplateName, enabled, sourceSettings,
    scenarioExclusionPatterns}. Discovered 2026-05-15 against the
    `advanced-multistage-attack-detection` prod-collected envelope.

    The payload shape here mirrors what `collect --role prod` actually
    writes today for a Microsoft-shipped Fusion rule.
    """
    full_fusion_payload = {
        "kind": "Fusion",
        "displayName": "Advanced Multistage Attack Detection",  # rejected
        "description": "Microsoft Sentinel uses Fusion …",       # rejected
        "alertRuleTemplateName": "f71aba3d-28fb-450b-b192-4e76a83015c8",  # required
        "tactics": ["Collection", "Execution"],                  # rejected
        "severity": "High",                                       # rejected
        "techniques": [],                                         # rejected
        "subTechniques": [],                                      # rejected
        "sourceSettings": [
            {"enabled": True, "sourceName": "Anomalies", "sourceSubTypes": None},
        ],                                                        # operator-editable
        "scenarioExclusionPatterns": [],                         # operator-editable
        "enabled": True,                                          # operator toggle
    }
    captured: list[dict] = []
    client = _client_with(httpx.MockTransport(_captured_put_body_handler(captured)))
    h = SentinelAnalyticHandler(lambda: client)
    result = h.apply(_loaded(full_fusion_payload))

    assert result.status == "success", (
        f"expected success, got {result.status} / {result.detail}"
    )
    assert len(captured) == 1, "expected exactly one PUT"
    put_properties = captured[0].get("properties") or {}
    # Only the allowlist survives. The hash projection
    # _TEMPLATED_HASHED_FIELDS already ignores everything outside
    # alertRuleTemplateName + enabled, so post-apply verify is OK.
    assert set(put_properties.keys()) == {
        "alertRuleTemplateName",
        "enabled",
        "sourceSettings",
        "scenarioExclusionPatterns",
    }, (
        f"Fusion PUT body must contain only the allowlist; got "
        f"properties={sorted(put_properties.keys())}"
    )
    assert put_properties["alertRuleTemplateName"].startswith("f71aba3d")


def test_mlba_apply_keeps_only_allowlist_in_put_body() -> None:
    """MLBehaviorAnalytics rules are enable-only — the body must reduce
    to {alertRuleTemplateName, enabled}. Any other field the operator
    pastes in by mistake gets stripped before PUT."""
    payload = {
        "kind": "MLBehaviorAnalytics",
        "displayName": "Anomalous SSH Login Detection",  # rejected
        "description": "Detects anomalous SSH...",       # rejected
        "alertRuleTemplateName": "fa118b98-de46-4e94-87f9-8e6d5060b60b",
        "tactics": ["InitialAccess"],                     # rejected
        "enabled": True,
    }
    captured: list[dict] = []
    client = _client_with(httpx.MockTransport(_captured_put_body_handler(captured)))
    h = SentinelAnalyticHandler(lambda: client)
    result = h.apply(_loaded(payload))

    assert result.status == "success", (
        f"expected success, got {result.status} / {result.detail}"
    )
    put_properties = captured[0].get("properties") or {}
    assert set(put_properties.keys()) == {"alertRuleTemplateName", "enabled"}


def test_threat_intelligence_apply_preserves_displayname() -> None:
    """ThreatIntelligence rules REQUIRE displayName (ARM 400 "Required
    property 'displayName' not found" otherwise). The apply path must
    NOT strip the body for this kind. Regression guard for the O.1 v1
    behaviour that broke `preview-microsoft-threat-intelligence-analytics`
    on 2026-05-15."""
    payload = {
        "kind": "ThreatIntelligence",
        "alertRuleTemplateName": "0dd422ee-e6af-4204-b219-f59ac172e4c6",
        "displayName": "(Preview) Microsoft Threat Intelligence Analytics",
        "description": "Generates an alert when a TI indicator matches…",
        "severity": "Medium",
        "tactics": ["Persistence", "LateralMovement"],
        "techniques": [],
        "subTechniques": [],
        "enabled": True,
    }
    captured: list[dict] = []
    client = _client_with(httpx.MockTransport(_captured_put_body_handler(captured)))
    h = SentinelAnalyticHandler(lambda: client)
    result = h.apply(_loaded(payload))

    assert result.status == "success", (
        f"expected success, got {result.status} / {result.detail}"
    )
    put_properties = captured[0].get("properties") or {}
    # ARM requires displayName for TI rules — must survive the strip.
    assert put_properties.get("displayName") == (
        "(Preview) Microsoft Threat Intelligence Analytics"
    )
    assert put_properties.get("description", "").startswith("Generates an alert")
    assert put_properties["alertRuleTemplateName"].startswith("0dd422ee")


def test_scheduled_with_template_binding_strips_displayname() -> None:
    """A Scheduled-kind rule that carries alertRuleTemplateName is still
    template-bound — ARM's displayName-read-only rule applies regardless
    of kind. This is the case that hit `aa-azure-vm-run-command-...` on
    2026-05-15."""
    payload = {
        "kind": "Scheduled",
        "displayName": "Template-bound Scheduled rule",
        "alertRuleTemplateName": "scheduled-template-guid",
        "query": "SecurityEvent | take 1",
        "severity": "Low",
        "queryFrequency": "PT5M",
        "queryPeriod": "PT5M",
        "triggerOperator": "GreaterThan",
        "triggerThreshold": 0,
        "enabled": True,
    }
    captured: list[dict] = []
    client = _client_with(httpx.MockTransport(_captured_put_body_handler(captured)))
    h = SentinelAnalyticHandler(lambda: client)
    result = h.apply(_loaded(payload))

    assert result.status == "success", f"expected success, got {result.status} / {result.detail}"
    assert len(captured) == 1
    put_properties = captured[0].get("properties") or {}
    assert "displayName" not in put_properties, (
        f"Scheduled+template PUT must not include displayName; got "
        f"properties={list(put_properties.keys())}"
    )
    # query / severity etc. stay — only the template-managed field is stripped.
    assert put_properties.get("query") == "SecurityEvent | take 1"
    assert put_properties.get("alertRuleTemplateName") == "scheduled-template-guid"


def test_scheduled_without_template_keeps_displayname() -> None:
    """Control: a plain Scheduled rule (no template binding) must KEEP
    displayName in the PUT body — operators rely on it being writeable
    for hand-authored detections."""
    payload = {
        "kind": "Scheduled",
        "displayName": "My hand-authored rule",
        "query": "SecurityEvent | take 1",
        "severity": "Low",
        "queryFrequency": "PT5M",
        "queryPeriod": "PT5M",
        "triggerOperator": "GreaterThan",
        "triggerThreshold": 0,
        "enabled": True,
    }
    captured: list[dict] = []
    client = _client_with(httpx.MockTransport(_captured_put_body_handler(captured)))
    h = SentinelAnalyticHandler(lambda: client)
    result = h.apply(_loaded(payload))

    assert result.status == "success"
    assert len(captured) == 1
    put_properties = captured[0].get("properties") or {}
    assert put_properties.get("displayName") == "My hand-authored rule"


# ---------------------------------------------------------------------------
# Drift round-trip — to_envelope preserves the right fields per kind
# ---------------------------------------------------------------------------


def test_to_envelope_drops_template_metadata_for_scheduled() -> None:
    h = SentinelAnalyticHandler(lambda: None)
    remote = {
        "name": "rule-1",
        "kind": "Scheduled",
        "properties": {
            "displayName": "X",
            "query": "print 1",
            "severity": "Low",
            "queryFrequency": "PT5M",
            "queryPeriod": "PT5M",
            "triggerOperator": "GreaterThan",
            "triggerThreshold": 0,
            "alertRuleTemplateName": "should-not-round-trip",
            "templateVersion": "1.0",
            "enabled": True,
        },
    }
    env = h.to_envelope(remote)
    assert env is not None
    assert "alertRuleTemplateName" not in env["payload"]
    assert "templateVersion" not in env["payload"]


def test_to_envelope_keeps_template_for_fusion() -> None:
    h = SentinelAnalyticHandler(lambda: None)
    remote = {
        "name": "rule-1",
        "kind": "Fusion",
        "properties": {
            "alertRuleTemplateName": "f71aba3d-28fb-450b-b192-4e76a83015c8",
            "enabled": True,
        },
    }
    env = h.to_envelope(remote)
    assert env is not None
    assert env["payload"]["alertRuleTemplateName"].startswith("f71aba3d")


def test_to_envelope_keeps_template_for_mlba_and_ti() -> None:
    h = SentinelAnalyticHandler(lambda: None)
    for kind, tpl in (
        ("MLBehaviorAnalytics", "fa118b98-de46-4e94-87f9-8e6d5060b60b"),
        ("ThreatIntelligence", "a1cf9c9b-2273-4664-a868-f60a23ed1d20"),
    ):
        env = h.to_envelope({
            "name": "rule-x",
            "kind": kind,
            "properties": {"alertRuleTemplateName": tpl, "enabled": True},
        })
        assert env is not None
        assert env["payload"]["alertRuleTemplateName"] == tpl


# ---------------------------------------------------------------------------
# Envelope version field (R.2 — surface Sentinel templateVersion)
# ---------------------------------------------------------------------------


def test_to_envelope_uses_template_version_for_templated_rules() -> None:
    """When ARM returns a ``templateVersion`` on a templated rule, the
    collected envelope's ``version`` field mirrors it so the YAML
    reflects which Microsoft template version is bound. Pre-R.2 this
    was hard-coded to ``"0.1.0"`` regardless of kind, which the
    2026-05-15 operator review flagged as wrong for templated rules."""
    h = SentinelAnalyticHandler(lambda: None)
    env = h.to_envelope({
        "name": "rule-x",
        "kind": "Scheduled",
        "properties": {
            "displayName": "Templated scheduled rule",
            "alertRuleTemplateName": "abcdef-template-guid",
            "templateVersion": "2.3.4",
            "query": "SecurityEvent | take 1",
            "severity": "Low",
            "queryFrequency": "PT5M",
            "queryPeriod": "PT5M",
            "triggerOperator": "GreaterThan",
            "triggerThreshold": 0,
            "enabled": True,
        },
    })
    assert env is not None
    # NB: the apply-time strip drops alertRuleTemplateName+templateVersion
    # from Scheduled-kind payloads (see test_to_envelope_drops_template_metadata_for_scheduled),
    # but the *envelope* version field is set before that strip — so the
    # templated Scheduled rule's YAML still surfaces 2.3.4 at the top.
    assert env["version"] == "2.3.4", (
        f"templated envelope should use templateVersion from ARM; got {env['version']!r}"
    )


def test_to_envelope_defaults_template_version_to_1_0_0_when_missing() -> None:
    """Fusion (and other templated kinds) where ARM does not return a
    templateVersion fall back to ``"1.0.0"`` — meaningful enough to spot
    a template-bound rule in git without claiming an upstream version
    we don't know."""
    h = SentinelAnalyticHandler(lambda: None)
    env = h.to_envelope({
        "name": "rule-y",
        "kind": "Fusion",
        "properties": {
            "alertRuleTemplateName": "f71aba3d-28fb-450b-b192-4e76a83015c8",
            "enabled": True,
            # no templateVersion — Microsoft Fusion is auto-versioned.
        },
    })
    assert env is not None
    assert env["version"] == "1.0.0", (
        f"templated envelope w/o templateVersion should default to 1.0.0; "
        f"got {env['version']!r}"
    )


def test_to_envelope_uses_collect_baseline_for_non_templated_rules() -> None:
    """Plain Scheduled / NRT rules with no alertRuleTemplateName get the
    shared collect baseline (1.0.0) — these are deployed production rules,
    so a stable 1.x baseline is more honest than a pre-1.0 tag."""
    from contentops.core.asset import COLLECT_BASELINE_VERSION

    h = SentinelAnalyticHandler(lambda: None)
    env = h.to_envelope({
        "name": "rule-z",
        "kind": "Scheduled",
        "properties": {
            "displayName": "Hand-authored rule",
            "query": "SecurityEvent | take 1",
            "severity": "Low",
            "queryFrequency": "PT5M",
            "queryPeriod": "PT5M",
            "triggerOperator": "GreaterThan",
            "triggerThreshold": 0,
            "enabled": True,
        },
    })
    assert env is not None
    assert env["version"] == COLLECT_BASELINE_VERSION == "1.0.0"
