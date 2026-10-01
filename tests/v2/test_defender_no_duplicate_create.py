# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Defender apply must never create a second rule for one YAML.

Three paths used to POST a duplicate custom detection:

* a YAML whose ``displayName`` was edited — apply matched on displayName
  only and ignored ``metadata.arm_name`` (the Graph id collect stores);
* two YAMLs with the same displayName in one run — the name map was not
  updated after the first create;
* a POST retried after a 5xx / read timeout that Graph had already
  committed.
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from contentops.core.asset import Asset
from contentops.core.envelope import EnvelopeV2
from contentops.core.handler import LoadedAsset
from contentops.core.result import PlanAction
from contentops.defender.client import BASE_URL, DefenderClient
from contentops.handlers.defender_custom_detection import DefenderCustomDetectionHandler
from contentops.utils import http_retry


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    # ``sleep`` is bound as a default at definition time, so patching
    # ``time.sleep`` would not reach it.
    monkeypatch.setitem(
        http_retry.request_with_retry.__kwdefaults__, "sleep", lambda *_: None,
    )


def _client_with(transport: httpx.MockTransport) -> DefenderClient:
    c = DefenderClient(token="t")
    c._client.close()
    c._client = httpx.Client(
        base_url=BASE_URL, transport=transport,
        headers={"Authorization": "Bearer t"},
    )
    return c


def _payload(display_name: str) -> dict:
    return {
        "displayName": display_name,
        "status": "enabled",
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


def _loaded(env_id: str, display_name: str, arm_name: str | None = None) -> LoadedAsset:
    env = EnvelopeV2(
        id=env_id, version="0.1.0",
        asset=Asset.DEFENDER_CUSTOM_DETECTION, status="production",
        arm_name=arm_name,
    )
    return LoadedAsset(
        path=Path(f"{env_id}.yml"), envelope=env, payload=_payload(display_name),
    )


class _Graph:
    """Tiny in-memory Graph: GET list / GET one / POST / PATCH."""

    def __init__(self, rules: dict[str, dict] | None = None) -> None:
        self.rules = dict(rules or {})
        self.calls: list[tuple[str, str]] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        self.calls.append((request.method, path))
        if request.method == "GET" and path.endswith("/detectionRules"):
            return httpx.Response(200, json={"value": list(self.rules.values())})
        if request.method == "POST" and path.endswith("/detectionRules"):
            gid = f"graph-new-{len(self.rules) + 1}"
            self.rules[gid] = {"id": gid, **json.loads(request.content)}
            return httpx.Response(201, json=self.rules[gid])
        gid = path.rsplit("/", 1)[-1]
        if request.method == "GET" and gid in self.rules:
            return httpx.Response(200, json=self.rules[gid])
        if request.method == "PATCH" and gid in self.rules:
            self.rules[gid] = {"id": gid, **json.loads(request.content)}
            return httpx.Response(200, json=self.rules[gid])
        return httpx.Response(404, text=f"unexpected {request.method} {path}")

    def count(self, method: str) -> int:
        return sum(1 for m, _ in self.calls if m == method)


def test_renamed_rule_patches_by_arm_name_without_post() -> None:
    graph = _Graph({"graph-1": {"id": "graph-1", **_payload("Old Name")}})
    h = DefenderCustomDetectionHandler(lambda: _client_with(httpx.MockTransport(graph)))

    result = h.apply(_loaded("new-name", "New Name", arm_name="graph-1"))

    assert result.status == "success", result.detail
    assert result.action == PlanAction.UPDATE
    assert graph.count("POST") == 0, "a rename must not create a second rule"
    assert ("PATCH", "/beta/security/rules/detectionRules/graph-1") in graph.calls \
        or any(m == "PATCH" and p.endswith("/graph-1") for m, p in graph.calls)
    assert list(graph.rules) == ["graph-1"]
    assert graph.rules["graph-1"]["displayName"] == "New Name"


def test_dry_run_labels_renamed_rule_as_update() -> None:
    graph = _Graph({"graph-1": {"id": "graph-1", **_payload("Old Name")}})
    h = DefenderCustomDetectionHandler(lambda: _client_with(httpx.MockTransport(graph)))

    result = h.apply(_loaded("new-name", "New Name", arm_name="graph-1"), dry_run=True)

    assert result.action == PlanAction.UPDATE


def test_stale_arm_name_falls_back_to_display_name() -> None:
    """The recorded rule was deleted in the portal: match by displayName."""
    graph = _Graph({"graph-2": {"id": "graph-2", **_payload("Old Name")}})
    h = DefenderCustomDetectionHandler(lambda: _client_with(httpx.MockTransport(graph)))

    h.apply(_loaded("old-name", "Old Name", arm_name="graph-gone"))

    assert graph.count("POST") == 0
    assert list(graph.rules) == ["graph-2"]


def test_same_display_name_twice_in_one_run_posts_once() -> None:
    graph = _Graph()
    h = DefenderCustomDetectionHandler(lambda: _client_with(httpx.MockTransport(graph)))

    first = h.apply(_loaded("dup-a", "Same Name"))
    second = h.apply(_loaded("dup-b", "Same Name"))

    assert first.action == PlanAction.CREATE
    assert second.action != PlanAction.CREATE
    assert graph.count("POST") == 1
    assert len(graph.rules) == 1


def test_create_rule_post_not_retried_on_5xx() -> None:
    """Graph may have committed the POST before the gateway 504'd."""
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.method)
        return httpx.Response(504, text="gateway timeout")

    client = _client_with(httpx.MockTransport(handler))
    response = client.create_rule(_payload("X"))

    assert response.status_code == 504
    assert calls == ["POST"]


def test_create_rule_post_not_retried_on_read_timeout() -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.method)
        raise httpx.ReadTimeout("read timed out", request=request)

    client = _client_with(httpx.MockTransport(handler))
    with pytest.raises(httpx.ReadTimeout):
        client.create_rule(_payload("X"))
    assert calls == ["POST"]


def test_create_rule_post_retried_on_429() -> None:
    """A 429 means the request was not processed: retrying is safe."""
    responses = iter([httpx.Response(429), httpx.Response(201, json={"id": "g"})])
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.method)
        return next(responses)

    client = _client_with(httpx.MockTransport(handler))
    response = client.create_rule(_payload("X"))

    assert response.status_code == 201
    assert calls == ["POST", "POST"]


def test_patch_still_retried_on_5xx() -> None:
    responses = iter([httpx.Response(503), httpx.Response(200, json={})])
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.method)
        return next(responses)

    client = _client_with(httpx.MockTransport(handler))
    response = client.update_rule("graph-1", _payload("X"))

    assert response.status_code == 200
    assert calls == ["PATCH", "PATCH"]
