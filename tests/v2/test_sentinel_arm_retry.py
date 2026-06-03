# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for SentinelArmProvider.request retry behavior.

Uses httpx.MockTransport to inject 429 / 5xx sequences without real I/O.
time.sleep is monkeypatched so the test runs instantly.
"""

from __future__ import annotations

from typing import Iterator

import httpx
import pytest

from contentops.config import SentinelConfig
from contentops.providers import sentinel_arm
from contentops.providers.sentinel_arm import SentinelArmProvider


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    monkeypatch.setattr(sentinel_arm.time, "sleep", lambda *_: None)


def _provider(transport: httpx.MockTransport) -> SentinelArmProvider:
    cfg = SentinelConfig(
        subscriptionId="sub", resourceGroup="rg", workspaceName="ws",
    )
    p = SentinelArmProvider(cfg, token="t")
    # Replace the underlying client with one bound to the mock transport.
    p._client.close()
    p._client = httpx.Client(
        base_url=sentinel_arm.ARM_BASE_URL,
        transport=transport,
        headers={"Authorization": "Bearer t"},
    )
    return p


def _seq_handler(statuses: list[int]):
    it: Iterator[int] = iter(statuses)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(next(it), json={"value": []})

    return handler


def test_429_retried_with_backoff_then_succeeds() -> None:
    p = _provider(httpx.MockTransport(_seq_handler([429, 429, 200])))
    resp = p.request("GET", p.resource_url("alertRules"))
    assert resp.status_code == 200
    p.close()


def test_429_gives_up_after_max_retries() -> None:
    # Initial + 3 retries = 4 total 429s.
    p = _provider(httpx.MockTransport(_seq_handler([429, 429, 429, 429])))
    resp = p.request("GET", p.resource_url("alertRules"))
    assert resp.status_code == 429
    p.close()


def test_5xx_retried_with_backoff_then_succeeds() -> None:
    p = _provider(httpx.MockTransport(_seq_handler([503, 502, 200])))
    resp = p.request("GET", p.resource_url("alertRules"))
    assert resp.status_code == 200
    p.close()


def test_5xx_gives_up_after_max_retries() -> None:
    p = _provider(httpx.MockTransport(_seq_handler([500, 500, 500, 500])))
    resp = p.request("GET", p.resource_url("alertRules"))
    assert resp.status_code == 500
    p.close()


def test_429_then_5xx_both_retry_paths_run() -> None:
    # 429 → 503 → 200: must traverse the 429 loop AND the 5xx loop.
    p = _provider(httpx.MockTransport(_seq_handler([429, 503, 200])))
    resp = p.request("GET", p.resource_url("alertRules"))
    assert resp.status_code == 200
    p.close()


def test_resource_url_builds_workspace_path() -> None:
    p = _provider(httpx.MockTransport(_seq_handler([200])))
    url = p.resource_url("watchlists", "hva")
    assert "/subscriptions/sub/resourceGroups/rg" in url
    assert "/workspaces/ws/providers/Microsoft.SecurityInsights/watchlists/hva" in url
    assert "api-version=" in url
    p.close()
