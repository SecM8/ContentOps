# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for O.3 — DefenderCustomDetectionHandler's dry-run mode now
opportunistically fetches the remote name → graph-id map so the action
label in dry-run output distinguishes `create` from `update`.

Pre-O.3 behaviour: dry-run always returned an empty map, so every asset
was labelled `create` in the dry-run summary even when the rule
already existed remotely.

Post-O.3: best-effort fetch in dry-run. On any failure (no auth,
transient Graph 5xx) fall back to the pre-O.3 empty-map behaviour so
the dry-run still completes; the label just defaults to `create`.
"""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from contentops.core.asset import Asset
from contentops.core.envelope import EnvelopeV2
from contentops.core.handler import LoadedAsset
from contentops.core.result import PlanAction
from contentops.defender import client as defender_client_module
from contentops.defender.client import BASE_URL, DefenderClient
from contentops.handlers.defender_custom_detection import (
    DefenderCustomDetectionHandler,
)


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(defender_client_module.time, "sleep", lambda *_: None)


_PAYLOAD = {
    "displayName": "Defender Test Rule",
    "isEnabled": True,
    "queryCondition": {"queryText": "DeviceProcessEvents | take 1"},
    "schedule": {"period": "0"},
    "actions": [{"@odata.type": "#microsoft.graph.security.alertAction"}],
    "alertTemplate": {
        "title": "Alert",
        "severity": "high",
        "category": "Execution",
        "description": "d",
        "recommendedActions": "r",
        "mitreTechniques": ["T1059"],
        "impactedAssets": [],
    },
}


def _loaded() -> LoadedAsset:
    env = EnvelopeV2(
        id="defender-test", version="0.1.0",
        asset=Asset.DEFENDER_CUSTOM_DETECTION, status="production",
    )
    return LoadedAsset(path=Path("d.yml"), envelope=env, payload=dict(_PAYLOAD))


def _client_with(transport: httpx.MockTransport) -> DefenderClient:
    c = DefenderClient(token="t")
    c._client.close()
    c._client = httpx.Client(
        base_url=BASE_URL, transport=transport,
        headers={"Authorization": "Bearer t"},
    )
    return c


def _existing_rule_in_list() -> dict:
    """Mirror the displayName so build_display_name_map populates the
    map and the handler sees the rule as existing."""
    return {
        "id": "graph-1",
        "displayName": _PAYLOAD["displayName"],
        "isEnabled": True,
    }


def test_dry_run_labels_update_when_remote_rule_exists() -> None:
    """Dry-run with a matching displayName in the remote tenant should
    label the action UPDATE — the pre-O.3 default was CREATE."""

    def handler_(request: httpx.Request) -> httpx.Response:
        # build_display_name_map paginates GET /detectionRules.
        if request.method == "GET" and request.url.path.endswith("/detectionRules"):
            return httpx.Response(200, json={"value": [_existing_rule_in_list()]})
        return httpx.Response(404, text=f"unexpected {request.method} {request.url}")

    client = _client_with(httpx.MockTransport(handler_))
    h = DefenderCustomDetectionHandler(lambda: client)
    result = h.apply(_loaded(), dry_run=True)
    assert result.action is PlanAction.UPDATE, (
        f"dry-run should resolve to UPDATE when remote has a matching "
        f"displayName; got {result.action}"
    )


def test_dry_run_labels_create_when_remote_is_empty() -> None:
    """Dry-run against an empty tenant should label CREATE."""

    def handler_(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and request.url.path.endswith("/detectionRules"):
            return httpx.Response(200, json={"value": []})
        return httpx.Response(404, text=f"unexpected {request.method} {request.url}")

    client = _client_with(httpx.MockTransport(handler_))
    h = DefenderCustomDetectionHandler(lambda: client)
    result = h.apply(_loaded(), dry_run=True)
    assert result.action is PlanAction.CREATE


def test_dry_run_falls_back_when_list_raises() -> None:
    """If the best-effort name-map fetch fails (no auth, transient
    Graph 5xx), dry-run must still complete — the label defaults to
    CREATE as the pre-O.3 behaviour did."""

    def handler_(request: httpx.Request) -> httpx.Response:
        # Simulate a Graph 503 transient failure on the list.
        return httpx.Response(503, text="service unavailable")

    client = _client_with(httpx.MockTransport(handler_))
    h = DefenderCustomDetectionHandler(lambda: client)
    result = h.apply(_loaded(), dry_run=True)
    assert result.action is PlanAction.CREATE
    # Action defaulted because the map fetch failed silently.
    assert h._name_map == {}


def test_dry_run_handles_factory_returning_none() -> None:
    """Legacy factories that return None for dry-run runs must not
    crash; the map stays empty and the label is CREATE."""
    h = DefenderCustomDetectionHandler(lambda: None)
    result = h.apply(_loaded(), dry_run=True)
    assert result.action is PlanAction.CREATE
    assert h._name_map == {}
