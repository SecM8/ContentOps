# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Post-apply verification tests for SentinelAnalyticHandler.

Covers the happy path (hash matches), the hash-mismatch path, and the
ETag conflict (412) path.
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
from contentops.providers import sentinel_arm
from contentops.providers.sentinel_arm import SentinelArmProvider


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


_PAYLOAD = {
    "kind": "Scheduled",
    "displayName": "Test rule",
    "severity": "High",
    "query": "SecurityEvent | take 1",
    "queryFrequency": "PT5M",
    "queryPeriod": "PT5M",
    "triggerOperator": "GreaterThan",
    "triggerThreshold": 0,
    "tactics": ["Execution"],
    "enabled": True,
}


def _loaded() -> LoadedAsset:
    env = EnvelopeV2(
        id="rule-1", version="0.1.0",
        asset=Asset.SENTINEL_ANALYTIC, status="production",
    )
    return LoadedAsset(path=Path("test.yml"), envelope=env, payload=dict(_PAYLOAD))


def _matching_remote(properties_overrides: dict | None = None) -> dict:
    properties = {
        "displayName": _PAYLOAD["displayName"],
        "severity": _PAYLOAD["severity"],
        "query": _PAYLOAD["query"],
        "queryFrequency": _PAYLOAD["queryFrequency"],
        "queryPeriod": _PAYLOAD["queryPeriod"],
        "triggerOperator": _PAYLOAD["triggerOperator"],
        "triggerThreshold": _PAYLOAD["triggerThreshold"],
        "tactics": _PAYLOAD["tactics"],
        "enabled": True,
        "lastModifiedUtc": "2024-01-01T00:00:00Z",  # ignored field
    }
    if properties_overrides:
        properties.update(properties_overrides)
    return {
        "name": "rule-1",
        "kind": "Scheduled",
        "etag": "W/\"abc\"",
        "properties": properties,
    }


def test_apply_happy_path_verifies_hash() -> None:
    calls: list[tuple[str, dict]] = []
    get_count = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            get_count["n"] += 1
            return httpx.Response(200, json=_matching_remote())
        # PUT
        calls.append((request.method, dict(request.headers)))
        return httpx.Response(200, json=_matching_remote())

    client = _client_with(httpx.MockTransport(handler))
    h = SentinelAnalyticHandler(lambda: client)
    result = h.apply(_loaded())

    assert result.status == "success"
    assert result.action is PlanAction.UPDATE
    assert result.verified is True
    assert result.error is None
    # If-Match should have been sent on PUT (etag captured from initial GET).
    put_headers = calls[0][1]
    assert put_headers.get("if-match") == 'W/"abc"'
    assert get_count["n"] == 2  # one before PUT, one after


def test_apply_hash_mismatch_marks_unverified() -> None:
    state = {"phase": "pre"}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            if state["phase"] == "pre":
                state["phase"] = "post"
                return httpx.Response(200, json=_matching_remote())
            # post-apply GET returns altered query
            return httpx.Response(200, json=_matching_remote(
                {"query": "SecurityEvent | take 999"}
            ))
        return httpx.Response(200, json=_matching_remote())

    client = _client_with(httpx.MockTransport(handler))
    h = SentinelAnalyticHandler(lambda: client)
    result = h.apply(_loaded())

    assert result.status == "success"  # API call did succeed
    assert result.verified is False
    assert "post-apply hash mismatch" in (result.error or "")
    assert result.is_failure


def test_apply_412_etag_conflict() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(200, json=_matching_remote())
        return httpx.Response(412, text="Precondition Failed")

    client = _client_with(httpx.MockTransport(handler))
    h = SentinelAnalyticHandler(lambda: client)
    result = h.apply(_loaded())

    assert result.status == "error-412"
    assert result.verified is False
    assert "rerun contentops plan" in (result.error or "")
    assert result.is_failure
