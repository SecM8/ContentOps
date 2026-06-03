# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the displayName slug + metadata.arm_name pattern.

The pattern: collected envelopes use the slugified displayName as
their envelope id, and stash the original ARM name under
``metadata.arm_name`` so apply can still address the same remote
resource.
"""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest

from contentops.utils.slug import (
    arm_name_suffix,
    disambiguate,
    displayname_slug,
    is_valid_envelope_id,
)


# ---------------------------------------------------------------------------
# slug edges
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name,expected",
    [
        ("A User added an account", "a-user-added-an-account"),
        ("Hello   World!!", "hello-world"),
        ("--leading--and--trailing--", "leading-and-trailing"),
        ("UPPERCASE TITLE", "uppercase-title"),
        ("Numbers 123 OK", "numbers-123-ok"),
        ("Title with: colons & punctuation?", "title-with-colons-punctuation"),
        # Unicode and accents collapse — they're not in [a-z0-9].
        ("Café résumé naïve", "caf-r-sum-na-ve"),
    ],
)
def test_displayname_slug_basic(name: str, expected: str) -> None:
    assert displayname_slug(name) == expected
    assert is_valid_envelope_id(displayname_slug(name))


def test_displayname_slug_caps_at_80() -> None:
    long_name = "A" * 200
    slug = displayname_slug(long_name)
    assert len(slug) <= 80
    assert slug.endswith("a")
    assert is_valid_envelope_id(slug)


def test_displayname_slug_falls_back_to_id_when_empty() -> None:
    # Pure punctuation slugs to "" — fall back to the ARM name.
    assert displayname_slug("???", fallback_id="1840b991-a12b") == "1840b991-a12b"
    assert displayname_slug(None, fallback_id="abc-123") == "abc-123"


def test_displayname_slug_empty_when_no_fallback() -> None:
    assert displayname_slug("???") == ""
    assert displayname_slug("") == ""
    assert displayname_slug(None) == ""


def test_arm_name_suffix_first_8_alnum() -> None:
    assert arm_name_suffix("1840b991-a12b-4e67-a685-d0cad73863fc") == "1840b991"
    assert arm_name_suffix("BuiltInFusion") == "builtinf"
    # Non-alphanumeric is stripped before slicing.
    assert arm_name_suffix("---abc---def---") == "abcdef"
    assert arm_name_suffix("") == ""


def test_disambiguate_appends_arm8() -> None:
    assert disambiguate("test", "1840b991-a12b") == "test-1840b991"
    assert disambiguate("test", "BuiltInFusion") == "test-builtinf"


def test_disambiguate_no_arm_name_returns_slug_unchanged() -> None:
    assert disambiguate("test", None) == "test"
    assert disambiguate("test", "") == "test"


# ---------------------------------------------------------------------------
# Collision handling at the orchestration layer
# ---------------------------------------------------------------------------


def test_collision_disambiguation_suffixes_both_envelopes() -> None:
    """Two analytics named 'Test' both get suffixed — never one bare
    'test' alongside one 'test-<arm8>' (otherwise drift sees them as
    different items)."""
    from contentops.core.drift import disambiguate_envelope_ids

    envelopes = [
        {
            "id": "test", "asset": "sentinel_analytic",
            "metadata": {"arm_name": "1840b991-a12b-4e67-a685"},
            "payload": {"a": 1},
        },
        {
            "id": "test", "asset": "sentinel_analytic",
            "metadata": {"arm_name": "20fffe11-cccc-4444-bbbb"},
            "payload": {"a": 2},
        },
        # A different asset with the same id passes through unchanged.
        {
            "id": "test", "asset": "sentinel_data_connector",
            "metadata": {"arm_name": "deadbeef-1111-2222"},
            "payload": {"a": 3},
        },
    ]

    out = disambiguate_envelope_ids(envelopes)
    ids_per_asset = {(e["asset"], e["id"]) for e in out}
    # Both colliding envelopes get suffixed.
    assert ("sentinel_analytic", "test-1840b991") in ids_per_asset
    assert ("sentinel_analytic", "test-20fffe11") in ids_per_asset
    # Workbook id stays bare — no collision in its kind.
    assert ("sentinel_data_connector", "test") in ids_per_asset
    # No bare "sentinel_analytic/test" left over.
    assert ("sentinel_analytic", "test") not in ids_per_asset


def test_collision_disambiguation_idempotent() -> None:
    from contentops.core.drift import disambiguate_envelope_ids

    envelopes = [
        {"id": "alpha", "asset": "sentinel_analytic",
         "metadata": {"arm_name": "g1"}, "payload": {}},
        {"id": "beta", "asset": "sentinel_analytic",
         "metadata": {"arm_name": "g2"}, "payload": {}},
    ]
    once = disambiguate_envelope_ids(envelopes)
    twice = disambiguate_envelope_ids(once)
    assert once == twice


# ---------------------------------------------------------------------------
# Apply path: dual-lookup uses metadata.arm_name when set, else id
# ---------------------------------------------------------------------------


def test_apply_uses_arm_name_when_set(monkeypatch) -> None:
    """The sentinel_analytic apply path PUTs to metadata.arm_name when
    set, falling back to envelope.id when absent. This is the contract
    that lets old legacy envelopes (no metadata.arm_name) keep working
    side-by-side with new collected envelopes."""
    import httpx
    from contentops.config import SentinelConfig
    from contentops.core.asset import Asset
    from contentops.core.envelope import EnvelopeV2
    from contentops.core.handler import LoadedAsset
    from contentops.handlers.sentinel_analytic import SentinelAnalyticHandler
    from contentops.providers import sentinel_arm
    from contentops.providers.sentinel_arm import SentinelArmProvider

    monkeypatch.setattr(sentinel_arm.time, "sleep", lambda *_: None)

    captured: dict = {}

    def transport_handler(request: httpx.Request) -> httpx.Response:
        captured.setdefault("paths", []).append(request.url.path)
        if request.method == "GET":
            return httpx.Response(404)
        if request.method == "PUT":
            return httpx.Response(201, json={
                "name": "1840b991-a12b-4e67-a685-d0cad73863fc",
                "kind": "Scheduled",
                "etag": 'W/"e"',
                "properties": {
                    "displayName": "A user added an account",
                    "query": "SecurityEvent | take 1",
                    "severity": "Medium",
                    "queryFrequency": "PT5M", "queryPeriod": "PT5M",
                    "triggerOperator": "GreaterThan", "triggerThreshold": 0,
                    "tactics": [], "enabled": True,
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
        id="a-user-added-an-account",  # slug
        version="0.1.0",
        asset=Asset.SENTINEL_ANALYTIC,
        status="production",
        legacy=True,
        arm_name="1840b991-a12b-4e67-a685-d0cad73863fc",  # original GUID
    )
    payload = {
        "kind": "Scheduled",
        "displayName": "A user added an account",
        "severity": "Medium",
        "query": "SecurityEvent | take 1",
        "queryFrequency": "PT5M", "queryPeriod": "PT5M",
        "triggerOperator": "GreaterThan", "triggerThreshold": 0,
        "tactics": [], "enabled": True,
    }
    loaded = LoadedAsset(path=Path("a.yml"), envelope=env, payload=payload)
    result = handler.apply(loaded)
    assert result.status == "success"
    # The PUT path must contain the GUID (arm_name), not the slug.
    assert any(
        "1840b991-a12b-4e67-a685-d0cad73863fc" in p
        for p in captured["paths"]
    ), captured


def test_apply_falls_back_to_envelope_id_when_arm_name_missing(monkeypatch) -> None:
    """Legacy envelopes without metadata.arm_name use envelope.id as
    the ARM resource name — preserves v1 behaviour."""
    import httpx
    from contentops.config import SentinelConfig
    from contentops.core.asset import Asset
    from contentops.core.envelope import EnvelopeV2
    from contentops.core.handler import LoadedAsset
    from contentops.handlers.sentinel_analytic import SentinelAnalyticHandler
    from contentops.providers import sentinel_arm
    from contentops.providers.sentinel_arm import SentinelArmProvider

    monkeypatch.setattr(sentinel_arm.time, "sleep", lambda *_: None)
    captured: dict = {}

    def transport_handler(request: httpx.Request) -> httpx.Response:
        captured.setdefault("paths", []).append(request.url.path)
        if request.method == "GET":
            return httpx.Response(404)
        if request.method == "PUT":
            return httpx.Response(201, json={
                "name": "sentinel-1840b991-a12b",
                "kind": "Scheduled",
                "etag": 'W/"e"',
                "properties": {
                    "displayName": "Legacy", "query": "T | take 1",
                    "severity": "Medium",
                    "queryFrequency": "PT5M", "queryPeriod": "PT5M",
                    "triggerOperator": "GreaterThan", "triggerThreshold": 0,
                    "tactics": [], "enabled": True,
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
        id="sentinel-1840b991-a12b",
        version="0.1.0",
        asset=Asset.SENTINEL_ANALYTIC,
        status="production",
        legacy=True,
        # No arm_name — legacy v1 envelope.
    )
    payload = {
        "kind": "Scheduled", "displayName": "Legacy",
        "severity": "Medium", "query": "T | take 1",
        "queryFrequency": "PT5M", "queryPeriod": "PT5M",
        "triggerOperator": "GreaterThan", "triggerThreshold": 0,
        "tactics": [], "enabled": True,
    }
    loaded = LoadedAsset(path=Path("a.yml"), envelope=env, payload=payload)
    result = handler.apply(loaded)
    assert result.status == "success"
    assert any(
        "sentinel-1840b991-a12b" in p for p in captured["paths"]
    ), captured


# ---------------------------------------------------------------------------
# Envelope parser accepts loose metadata.arm_name on legacy envelopes
# ---------------------------------------------------------------------------


def test_parse_envelope_loose_metadata_with_arm_name() -> None:
    """Legacy collected envelopes can carry just `metadata.arm_name`
    without the strict authoring-metadata block."""
    from contentops.core.envelope import parse_envelope

    raw = {
        "id": "a-user-added-an-account",
        "version": "0.1.0",
        "asset": "sentinel_analytic",
        "status": "production",
        "legacy": True,
        "metadata": {"arm_name": "1840b991-a12b-4e67-a685"},
        "payload": {"kind": "Scheduled"},
    }
    envelope, payload = parse_envelope(raw)
    assert envelope.arm_name == "1840b991-a12b-4e67-a685"
    assert envelope.metadata is None  # loose form doesn't construct RuleMetadata
    assert payload == {"kind": "Scheduled"}
