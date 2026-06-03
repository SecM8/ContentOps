# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for SentinelHuntingHandler against a mocked ARM provider."""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from contentops.config import SentinelConfig
from contentops.core.asset import Asset
from contentops.core.envelope import EnvelopeV2
from contentops.core.handler import LoadedAsset
from contentops.core.result import PlanAction
from contentops.handlers.sentinel_hunting import SentinelHuntingHandler
from contentops.providers import sentinel_arm
from contentops.providers.sentinel_arm import SentinelArmProvider


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    monkeypatch.setattr(sentinel_arm.time, "sleep", lambda *_: None)


def _loaded(status: str = "production") -> LoadedAsset:
    env = EnvelopeV2(
        id="hunt-ps-encoded", version="0.1.0",
        asset=Asset.SENTINEL_HUNTING, status=status,
    )
    return LoadedAsset(
        path=Path("test.yml"), envelope=env,
        payload={"displayName": "X", "query": "DeviceProcessEvents | take 1"},
    )


def _provider_with(transport: httpx.MockTransport) -> SentinelArmProvider:
    cfg = SentinelConfig(subscriptionId="sub", resourceGroup="rg", workspaceName="ws")
    p = SentinelArmProvider(cfg, token="t")
    p._client.close()
    p._client = httpx.Client(
        base_url=sentinel_arm.ARM_BASE_URL, transport=transport,
        headers={"Authorization": "Bearer t"},
    )
    return p


def test_validate_passes_for_minimal_payload() -> None:
    SentinelHuntingHandler(lambda: None).validate(_loaded())


def test_plan_skips_experimental() -> None:
    h = SentinelHuntingHandler(lambda: None)
    result = h.plan(_loaded(status="experimental"))
    assert result.action is PlanAction.SKIP


def test_plan_update_for_production() -> None:
    h = SentinelHuntingHandler(lambda: None)
    assert h.plan(_loaded()).action is PlanAction.UPDATE


def test_apply_dry_run_makes_no_request() -> None:
    called = {"n": 0}

    def factory():
        called["n"] += 1
        return None

    h = SentinelHuntingHandler(factory)
    result = h.apply(_loaded(), dry_run=True)
    assert result.status == "dry-run"
    assert called["n"] == 0


def test_apply_real_put_targets_loganalytics_path() -> None:
    calls: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append((request.method, str(request.url)))
        if request.method == "GET":
            # First GET (pre-PUT) returns 404 so no etag; post-PUT GET
            # returns the same content we PUT so the hash check passes.
            if len([c for c in calls if c[0] == "GET"]) == 1:
                return httpx.Response(404)
            return httpx.Response(200, json={
                "name": "hunt-ps-encoded",
                "properties": {
                    "category": "Hunting Queries",
                    "displayName": "X",
                    "query": "DeviceProcessEvents | take 1",
                    "version": 2,
                },
            })
        return httpx.Response(201, json={"id": "x"})

    provider = _provider_with(httpx.MockTransport(handler))
    h = SentinelHuntingHandler(lambda: provider)
    result = h.apply(_loaded())

    assert result.status == "success"
    assert result.action is PlanAction.CREATE
    assert result.verified is True
    methods = [m for m, _ in calls]
    assert "PUT" in methods
    put_url = next(url for m, url in calls if m == "PUT")
    # Crucially: under Microsoft.OperationalInsights, NOT SecurityInsights.
    assert "Microsoft.OperationalInsights/workspaces/ws/savedSearches/hunt-ps-encoded" in put_url
    assert "Microsoft.SecurityInsights" not in put_url
    h.close()


def test_apply_surfaces_api_error() -> None:
    def handler(request: httpx.Request):
        if request.method == "GET":
            return httpx.Response(404)
        return httpx.Response(400, text="bad query")

    provider = _provider_with(httpx.MockTransport(handler))
    h = SentinelHuntingHandler(lambda: provider)
    result = h.apply(_loaded())
    assert result.status == "error-400"
    assert "bad query" in result.detail
    assert result.verified is False
    h.close()
