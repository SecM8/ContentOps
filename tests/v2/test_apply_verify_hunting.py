# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Post-apply verification tests for SentinelHuntingHandler.

savedSearches at api-version 2023-09-01 returns ``etag`` in the GET
response body, so this handler also exercises the If-Match path.
"""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from contentops.config import SentinelConfig
from contentops.core.asset import Asset
from contentops.core.envelope import EnvelopeV2
from contentops.core.handler import LoadedAsset
from contentops.handlers.sentinel_hunting import SentinelHuntingHandler
from contentops.providers import sentinel_arm
from contentops.providers.sentinel_arm import SentinelArmProvider


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    monkeypatch.setattr(sentinel_arm.time, "sleep", lambda *_: None)


def _provider_with(transport: httpx.MockTransport) -> SentinelArmProvider:
    cfg = SentinelConfig(subscriptionId="sub", resourceGroup="rg", workspaceName="ws")
    p = SentinelArmProvider(cfg, token="t")
    p._client.close()
    p._client = httpx.Client(
        base_url=sentinel_arm.ARM_BASE_URL, transport=transport,
        headers={"Authorization": "Bearer t"},
    )
    return p


_PAYLOAD = {"displayName": "X", "query": "DeviceProcessEvents | take 1"}


def _loaded() -> LoadedAsset:
    env = EnvelopeV2(
        id="hunt-1", version="0.1.0",
        asset=Asset.SENTINEL_HUNTING, status="production",
    )
    return LoadedAsset(path=Path("h.yml"), envelope=env, payload=dict(_PAYLOAD))


def _matching_remote(query: str = _PAYLOAD["query"]) -> dict:
    return {
        "name": "hunt-1",
        "etag": 'W/"hunt-etag"',
        "properties": {
            "category": "Hunting Queries",
            "displayName": _PAYLOAD["displayName"],
            "query": query,
            "version": 2,
        },
    }


def test_apply_happy_path_verifies_and_sends_ifmatch() -> None:
    headers_seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(200, json=_matching_remote())
        headers_seen.update(request.headers)
        return httpx.Response(200, json=_matching_remote())

    provider = _provider_with(httpx.MockTransport(handler))
    h = SentinelHuntingHandler(lambda: provider)
    result = h.apply(_loaded())

    assert result.status == "success"
    assert result.verified is True
    assert headers_seen.get("if-match") == 'W/"hunt-etag"'


def test_apply_hash_mismatch() -> None:
    state = {"phase": "pre"}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            if state["phase"] == "pre":
                state["phase"] = "post"
                return httpx.Response(200, json=_matching_remote())
            return httpx.Response(200, json=_matching_remote(query="union *"))
        return httpx.Response(200, json=_matching_remote())

    provider = _provider_with(httpx.MockTransport(handler))
    h = SentinelHuntingHandler(lambda: provider)
    result = h.apply(_loaded())

    assert result.verified is False
    assert "post-apply hash mismatch" in (result.error or "")


def test_apply_412_etag_conflict() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(200, json=_matching_remote())
        return httpx.Response(412, text="Precondition Failed")

    provider = _provider_with(httpx.MockTransport(handler))
    h = SentinelHuntingHandler(lambda: provider)
    result = h.apply(_loaded())

    assert result.status == "error-412"
    assert result.verified is False
    assert "rerun contentops plan" in (result.error or "")
