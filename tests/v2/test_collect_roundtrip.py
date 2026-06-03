# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Unit-level roundtrip contract: per-handler to_envelope determinism.

The collect-then-recollect contract is: ``contentops collect`` against
the live tenant, then ``contentops collect`` again against the same
output dir, must report **zero new + zero changed** entries (every
item in ``in-sync``).

The live version of this is in
tests/integration/test_collect_live_roundtrip.py. This module covers
the unit-level invariant: per handler, ``to_envelope(remote)`` must
be deterministic and idempotent — calling it twice on the same
remote dict produces equal envelopes — and the resulting envelope
must round-trip through the YAML loader without raising.
"""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest
import yaml

from contentops.cli.handler_factories import register_default_handlers
from contentops.core.asset import Asset
from contentops.core.envelope import parse_envelope
from contentops.core.registry import default_registry


def _all_drift_handlers():
    register_default_handlers()
    from contentops.core.drift import DriftCapable
    return [
        default_registry.get(a) for a in default_registry.assets()
        if isinstance(default_registry.get(a), DriftCapable)
    ]


# ---------------------------------------------------------------------------
# Synthetic remote fixtures per handler — minimal but realistic shapes.
# ---------------------------------------------------------------------------


_REMOTE_FIXTURES: dict[Asset, dict] = {
    Asset.SENTINEL_ANALYTIC: {
        "name": "guid-1",
        "kind": "Scheduled",
        "properties": {
            "displayName": "Test rule",
            "query": "SecurityEvent | take 1",
            "severity": "Medium",
            "queryFrequency": "PT5M",
            "queryPeriod": "PT5M",
            "triggerOperator": "GreaterThan",
            "triggerThreshold": 0,
            "tactics": ["InitialAccess"],
            "enabled": True,
        },
    },
    Asset.SENTINEL_WATCHLIST: {
        "name": "MixedCaseList",
        "properties": {
            "displayName": "Mixed Case List",
            "provider": "Custom",
            "source": "MixedCaseList.csv",
            "itemsSearchKey": "Key",
            "watchlistType": "watchlist",
        },
    },
    Asset.SENTINEL_PARSER: {
        "name": "parser-1",
        "properties": {
            "category": "Function",
            "displayName": "GetFoo",
            "query": "print 1",
            "version": 2,
            "functionAlias": "GetFoo",
        },
    },
    Asset.SENTINEL_HUNTING: {
        "name": "hunting-1",
        "properties": {
            "category": "Hunting Queries",
            "displayName": "Hunt for Foo",
            "query": "DeviceProcessEvents | take 1",
            "version": 2,
        },
    },
}


# ---------------------------------------------------------------------------
# Property: to_envelope is deterministic
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "asset,remote",
    list(_REMOTE_FIXTURES.items()),
    ids=lambda v: v.value if hasattr(v, "value") else "fixture",
)
def test_to_envelope_is_deterministic(asset: Asset, remote: dict) -> None:
    """Same input -> same envelope on every call."""
    register_default_handlers()
    handler = default_registry.get(asset)
    e1 = handler.to_envelope(deepcopy(remote))
    e2 = handler.to_envelope(deepcopy(remote))
    assert e1 == e2, f"to_envelope is non-deterministic for {asset.value}"
    default_registry.close_all()


# ---------------------------------------------------------------------------
# Property: collected envelope passes parse_envelope without raising
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "asset,remote",
    list(_REMOTE_FIXTURES.items()),
    ids=lambda v: v.value if hasattr(v, "value") else "fixture",
)
def test_collected_envelope_parses(asset: Asset, remote: dict) -> None:
    """Round-trip the to_envelope output through YAML and parse_envelope.

    A collected envelope MUST satisfy the parse_envelope contract —
    otherwise the next ``contentops collect`` run can't index it as
    local and would re-flag the remote item as NEW.
    """
    register_default_handlers()
    handler = default_registry.get(asset)
    envelope_dict = handler.to_envelope(deepcopy(remote))
    if envelope_dict is None:
        pytest.skip(f"{asset.value} chose to skip this remote (None envelope)")
    serialised = yaml.safe_dump(envelope_dict, sort_keys=False)
    raw = yaml.safe_load(serialised)
    envelope, payload = parse_envelope(raw)
    assert envelope.asset == asset
    assert envelope.id == envelope_dict["id"]
    default_registry.close_all()


# ---------------------------------------------------------------------------
# Property: payloads_match agrees with itself (drift second-run invariant)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "asset,remote",
    list(_REMOTE_FIXTURES.items()),
    ids=lambda v: v.value if hasattr(v, "value") else "fixture",
)
def test_payloads_match_self(asset: Asset, remote: dict) -> None:
    """Two calls of to_envelope(remote) produce payloads that compare
    equal under the drift engine's stable comparison. This is the
    direct precondition for the second `contentops collect` reporting
    in-sync.
    """
    from contentops.core.drift import _payloads_match
    register_default_handlers()
    handler = default_registry.get(asset)
    e1 = handler.to_envelope(deepcopy(remote))
    e2 = handler.to_envelope(deepcopy(remote))
    if e1 is None or e2 is None:
        pytest.skip(f"{asset.value} chose to skip this remote")
    assert _payloads_match(e1["payload"], e2["payload"])
    default_registry.close_all()


# ---------------------------------------------------------------------------
# CamelCase round-trip
# ---------------------------------------------------------------------------


def test_watchlist_camelcase_alias_round_trips() -> None:
    """A watchlist with CamelCase alias collects to a lowercase
    envelope id (matching the regex) AND retains the original alias
    on payload.watchlistAlias so apply can target the right remote."""
    register_default_handlers()
    h = default_registry.get(Asset.SENTINEL_WATCHLIST)
    env = h.to_envelope({
        "name": "AutoClose",
        "properties": {
            "displayName": "Auto Close",
            "provider": "Microsoft",
            "source": "AutoClose.csv",
            "itemsSearchKey": "Title",
            "watchlistType": "watchlist",
        },
    })
    assert env is not None
    assert env["id"] == "autoclose"
    assert env["payload"]["watchlistAlias"] == "AutoClose"


def test_analytic_camelcase_arm_name_round_trips() -> None:
    """Analytic rules with CamelCase ARM names (e.g. BuiltInFusion)
    slug from displayName when present and stash the original ARM
    name on metadata.arm_name so apply can address the same remote.
    Falls back to the ARM name itself when no displayName is set."""
    register_default_handlers()
    h = default_registry.get(Asset.SENTINEL_ANALYTIC)
    env = h.to_envelope({
        "name": "BuiltInFusion",
        "kind": "Fusion",
        "properties": {
            "alertRuleTemplateName": "f71aba3d-28fb-450b-b192-4e76a83015c8",
            "enabled": True,
        },
    })
    assert env is not None
    # No displayName -> fallback to slugified ARM name.
    assert env["id"] == "builtinfusion"
    assert env["metadata"]["arm_name"] == "BuiltInFusion"


# ---------------------------------------------------------------------------
# Detection envelopes need legacy: true to parse
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Regression: templateVersion / alertRuleTemplateName coupling
# ---------------------------------------------------------------------------


def test_template_version_without_template_name_fails_validate() -> None:
    """Plan-time validate must reject the bad coupling.

    A live apply against the production tenant on 2026-05-06 hit
    HTTP 400 "Invalid Properties for alert rule: 'templateVersion'
    can only be used if 'alertRuleTemplateName' is not empty." on
    69 rules. This test pins the validate-time guard so the
    regression can't sneak back in.
    """
    from pathlib import Path
    from contentops.cli.handler_factories import register_default_handlers
    from contentops.core.envelope import EnvelopeV2
    from contentops.core.handler import LoadedAsset
    from contentops.core.registry import default_registry

    register_default_handlers()
    handler = default_registry.get(Asset.SENTINEL_ANALYTIC)

    env = EnvelopeV2(
        id="bad-coupling", version="0.1.0",
        asset=Asset.SENTINEL_ANALYTIC, status="production",
        legacy=True,  # mirrors the real legacy v1 envelopes that hit prod
    )
    payload = {
        "kind": "Scheduled",
        "displayName": "Bad coupling",
        "severity": "Medium",
        "query": "SecurityEvent | take 1",
        "queryFrequency": "PT5M",
        "queryPeriod": "PT5M",
        "triggerOperator": "GreaterThan",
        "triggerThreshold": 0,
        "templateVersion": "1.0.0",
        # alertRuleTemplateName intentionally absent
    }
    loaded = LoadedAsset(path=Path("bad.yml"), envelope=env, payload=payload)

    try:
        with pytest.raises(ValueError, match="templateVersion"):
            handler.validate(loaded)
    finally:
        default_registry.close_all()


def test_template_version_lint_rule_emits_payload001() -> None:
    """The PAYLOAD001 lint rule fires on the bad coupling and only on it.

    Minimal payloads in this test omit MITRE fields; PAYLOAD003 fires
    on those (expected), so the assertions filter to PAYLOAD001 rather
    than asserting zero findings overall."""
    from contentops.lint.payload import lint_payload

    findings = lint_payload(
        {"kind": "Scheduled", "templateVersion": "1.0.0"},
        asset=Asset.SENTINEL_ANALYTIC,
    )
    assert any(f.rule_id == "PAYLOAD001" and f.severity == "error"
               for f in findings)

    # Both fields together: no PAYLOAD001 finding.
    findings = lint_payload(
        {"kind": "Scheduled", "templateVersion": "1.0.0",
         "alertRuleTemplateName": "abc-123"},
        asset=Asset.SENTINEL_ANALYTIC,
    )
    assert [f for f in findings if f.rule_id == "PAYLOAD001"] == []

    # Just alertRuleTemplateName: no PAYLOAD001 finding.
    findings = lint_payload(
        {"kind": "Scheduled", "alertRuleTemplateName": "abc-123"},
        asset=Asset.SENTINEL_ANALYTIC,
    )
    assert [f for f in findings if f.rule_id == "PAYLOAD001"] == []


def test_apply_scrubs_template_version_when_template_name_empty(monkeypatch) -> None:
    """The apply-time scrub strips templateVersion from the body if the
    coupling rule is bypassed (e.g. retry-failed without re-validate).
    Mocks the Sentinel ARM provider so we can inspect the body that
    would have gone over the wire to ARM. Without the scrub this test
    fails (the body carries templateVersion); with the scrub it
    passes (the body does not)."""
    import httpx
    from pathlib import Path
    from contentops.config import SentinelConfig
    from contentops.core.envelope import EnvelopeV2
    from contentops.core.handler import LoadedAsset
    from contentops.handlers.sentinel_analytic import SentinelAnalyticHandler
    from contentops.providers import sentinel_arm
    from contentops.providers.sentinel_arm import SentinelArmProvider

    monkeypatch.setattr(sentinel_arm.time, "sleep", lambda *_: None)

    captured: dict = {}

    def transport_handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(404)
        if request.method == "PUT":
            captured["body"] = request.read().decode("utf-8")
            return httpx.Response(201, json={
                "name": "bad-coupling",
                "kind": "Scheduled",
                "etag": 'W/"e"',
                "properties": {
                    "displayName": "Bad coupling",
                    "query": "SecurityEvent | take 1",
                    "severity": "Medium",
                    "queryFrequency": "PT5M",
                    "queryPeriod": "PT5M",
                    "triggerOperator": "GreaterThan",
                    "triggerThreshold": 0,
                    "tactics": [],
                    "enabled": True,
                },
            })
        return httpx.Response(404)

    cfg = SentinelConfig(subscriptionId="sub", resourceGroup="rg", workspaceName="ws")
    c = SentinelArmProvider(cfg, token="t")
    c._client.close()
    c._client = httpx.Client(
        base_url="https://management.azure.com",
        transport=httpx.MockTransport(transport_handler),
        headers={"Authorization": "Bearer t"},
    )
    handler = SentinelAnalyticHandler(lambda: c)

    env = EnvelopeV2(
        id="bad-coupling", version="0.1.0",
        asset=Asset.SENTINEL_ANALYTIC, status="production",
        legacy=True,
    )
    payload = {
        "kind": "Scheduled",
        "displayName": "Bad coupling",
        "severity": "Medium",
        "query": "SecurityEvent | take 1",
        "queryFrequency": "PT5M",
        "queryPeriod": "PT5M",
        "triggerOperator": "GreaterThan",
        "triggerThreshold": 0,
        "tactics": [],
        "enabled": True,
        "templateVersion": "1.0.0",
        # alertRuleTemplateName intentionally absent
    }
    loaded = LoadedAsset(path=Path("bad.yml"), envelope=env, payload=payload)

    # Bypass validate() (simulates the retry-failed bypass).
    result = handler.apply(loaded)
    body = captured.get("body", "")
    # Body goes over the wire WITHOUT templateVersion (scrub stripped it).
    assert '"templateVersion"' not in body, (
        "apply-time scrub should have stripped templateVersion before PUT"
    )
    # And the apply succeeded (so retry-failed actually fixes the rule).
    assert result.status == "success"


def test_scaffold_includes_required_suppression_fields(tmp_path) -> None:
    """The sentinel_analytic scaffold MUST include suppressionDuration
    and suppressionEnabled. Live apply on 2026-05-06 hit HTTP 400
    'Required property suppressionDuration not found' on
    zz-itest-lifecycle (a freshly-scaffolded envelope) because the
    template was missing them."""
    import yaml as _yaml
    from contentops.devex.scaffold import scaffold

    out = tmp_path / "fresh.yml"
    scaffold("sentinel_analytic", "fresh-asset", out=out, force=True)
    raw = _yaml.safe_load(out.read_text(encoding="utf-8"))
    payload = raw.get("payload") or {}
    assert "suppressionDuration" in payload, (
        "scaffold must include suppressionDuration — ARM rejects "
        "Scheduled rules without it"
    )
    assert "suppressionEnabled" in payload, (
        "scaffold must include suppressionEnabled — ARM rejects "
        "Scheduled rules without it"
    )
    # And every other ARM-required Scheduled field is present.
    for required in (
        "kind", "displayName", "enabled", "severity", "query",
        "queryFrequency", "queryPeriod", "triggerOperator",
        "triggerThreshold",
    ):
        assert required in payload, f"scaffold missing required field {required!r}"


def test_collected_detection_envelopes_carry_minimal_metadata() -> None:
    """Collected detection envelopes (analytic, hunting, defender)
    carry a minimal ``metadata: {arm_name: ...}`` block so they
    round-trip through parse_envelope without inventing rich
    authoring fields. Authoring richness is enforced by
    ``contentops lint --strict``, not at parse time."""
    register_default_handlers()
    for asset in (
        Asset.SENTINEL_ANALYTIC, Asset.SENTINEL_HUNTING,
        Asset.DEFENDER_CUSTOM_DETECTION,
    ):
        handler = default_registry.get(asset)
        if asset == Asset.SENTINEL_ANALYTIC:
            env = handler.to_envelope(_REMOTE_FIXTURES[Asset.SENTINEL_ANALYTIC])
        elif asset == Asset.SENTINEL_HUNTING:
            env = handler.to_envelope(_REMOTE_FIXTURES[Asset.SENTINEL_HUNTING])
        else:
            env = handler.to_envelope({
                "id": "abc-1", "displayName": "Defender test",
                "isEnabled": True, "queryCondition": {"queryText": "DeviceEvents | take 1"},
                "schedule": {"period": "1H"},
                "detectionAction": {
                    "alertTemplate": {
                        "title": "Test", "severity": "medium",
                        "impactedAssets": [{
                            "@odata.type": "#microsoft.graph.security.impactedDeviceAsset",
                            "identifier": "deviceId",
                        }],
                    },
                },
            })
        assert env is not None, f"{asset.value} returned None"
        assert "legacy" not in env, (
            f"{asset.value} envelope must not carry the removed `legacy` flag"
        )
        assert isinstance(env.get("metadata"), dict), (
            f"{asset.value} envelope must carry a metadata block (even if empty)"
        )
    default_registry.close_all()
