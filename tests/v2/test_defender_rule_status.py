# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Defender ``status`` / ``description`` handling.

Graph beta replaced ``isEnabled`` with a ``status`` enum and added an
authorable ``description``; ``isEnabled`` was removed from the
``detectionRule`` resource on 2026-10-01. Collect started writing both
new fields into YAML, which the strict ``DefenderPayload`` rejected, so
every drift PR failed validation. These tests pin the new contract and
keep legacy ``isEnabled`` YAML working.
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
from contentops.defender import client as defender_client_module
from contentops.defender.client import BASE_URL, DefenderClient
from contentops.defender.rule_status import hashed_fields, is_enabled, rule_status
from contentops.handlers.defender_custom_detection import DefenderCustomDetectionHandler
from contentops.models import validate_defender_payload


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    monkeypatch.setattr(defender_client_module.time, "sleep", lambda *_: None)


def _client_with(transport: httpx.MockTransport) -> DefenderClient:
    c = DefenderClient(token="t")
    c._client.close()
    c._client = httpx.Client(
        base_url=BASE_URL, transport=transport,
        headers={"Authorization": "Bearer t"},
    )
    return c


# Shape of a rule as collect now writes it (status + description, no isEnabled).
_COLLECTED = {
    "displayName": "Defender Status Test",
    "description": "",
    "status": "enabled",
    "queryCondition": {"queryText": "DeviceProcessEvents | take 1"},
    "schedule": {"period": "3H"},
    "detectionAction": {
        "alertTemplate": {
            "title": "Alert",
            "severity": "medium",
            "impactedAssets": [{
                "@odata.type": "#microsoft.graph.security.impactedDeviceAsset",
                "identifier": "deviceId",
            }],
        },
    },
}


def _loaded(payload: dict, status: str = "production") -> LoadedAsset:
    env = EnvelopeV2(
        id="defender-status-test", version="0.1.0",
        asset=Asset.DEFENDER_CUSTOM_DETECTION, status=status,
    )
    return LoadedAsset(path=Path("d.yml"), envelope=env, payload=dict(payload))


def _remote(**overrides) -> dict:
    remote = {
        "id": "graph-1",
        "createdDateTime": "2026-01-01T00:00:00Z",
        **{k: v for k, v in _COLLECTED.items()},
    }
    remote.update(overrides)
    return remote


def _run(payload: dict, remote: dict, *, status: str = "production"):
    """Apply against a mock Graph where the rule already exists.

    Returns ``(result, patch_bodies)``. The post-apply GET returns the
    patched remote so verification sees what was sent.
    """
    state = {"remote": dict(remote)}
    patches: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if request.method == "GET" and path.endswith("/detectionRules"):
            return httpx.Response(200, json={"value": [state["remote"]]})
        if request.method == "GET" and "/detectionRules/graph-1" in path:
            return httpx.Response(200, json=state["remote"])
        if request.method == "PATCH" and "/detectionRules/graph-1" in path:
            body = json.loads(request.content)
            patches.append(body)
            state["remote"] = {**state["remote"], **body}
            return httpx.Response(200, json=state["remote"])
        return httpx.Response(404, text=f"unexpected {request.method} {path}")

    client = _client_with(httpx.MockTransport(handler))
    h = DefenderCustomDetectionHandler(lambda: client)
    return h.apply(_loaded(payload, status)), patches


# --- model ---------------------------------------------------------------


def test_collected_status_and_description_validate() -> None:
    """Regression: collect output with status + description must validate."""
    validate_defender_payload(dict(_COLLECTED))


def test_legacy_isenabled_still_validates() -> None:
    legacy = {k: v for k, v in _COLLECTED.items() if k not in ("status", "description")}
    validate_defender_payload({**legacy, "isEnabled": False})


def test_unknown_status_value_rejected() -> None:
    with pytest.raises(Exception):
        validate_defender_payload({**_COLLECTED, "status": "paused"})


# --- rule_status helpers --------------------------------------------------


@pytest.mark.parametrize(
    ("rule", "expected"),
    [
        ({"status": "disabled", "isEnabled": True}, "disabled"),  # status wins
        ({"isEnabled": False}, "disabled"),
        ({"isEnabled": True}, "enabled"),
        ({}, "enabled"),
        ({"status": "autoDisabled"}, "autoDisabled"),
    ],
)
def test_rule_status_precedence(rule: dict, expected: str) -> None:
    assert rule_status(rule) == expected


def test_auto_disabled_is_not_enabled() -> None:
    assert is_enabled({"status": "autoDisabled"}) is False


def test_description_hashed_only_when_authored() -> None:
    base = ["displayName"]
    assert hashed_fields(base, {"description": ""}) == base
    assert hashed_fields(base, {}) == base
    assert hashed_fields(base, {"description": "why"}) == [*base, "description"]


# --- apply ----------------------------------------------------------------


def test_unchanged_status_rule_is_noop() -> None:
    result, patches = _run(_COLLECTED, _remote())
    assert patches == []
    assert result.action == PlanAction.NOOP
    assert result.verified is True


def test_deprecated_sends_status_disabled_without_isenabled() -> None:
    result, patches = _run(_COLLECTED, _remote(), status="deprecated")
    assert len(patches) == 1
    assert patches[0]["status"] == "disabled"
    assert "isEnabled" not in patches[0]
    assert result.action == PlanAction.DISABLE
    assert result.verified is True


def test_legacy_yaml_against_status_only_remote_is_noop() -> None:
    """Old YAML (isEnabled, no description) vs a remote that dropped
    isEnabled and carries a portal description: nothing to push."""
    legacy = {k: v for k, v in _COLLECTED.items() if k not in ("status", "description")}
    legacy["isEnabled"] = True
    result, patches = _run(legacy, _remote(description="Written in the portal"))
    assert patches == []
    assert result.action == PlanAction.NOOP


def test_authored_description_change_is_pushed_and_verified() -> None:
    payload = {**_COLLECTED, "description": "New text"}
    result, patches = _run(payload, _remote(description="Old text"))
    assert len(patches) == 1
    assert patches[0]["description"] == "New text"
    assert result.verified is True


def test_auto_disabled_remote_is_left_alone() -> None:
    """Authored autoDisabled: status is not sent and does not force a PATCH."""
    payload = {**_COLLECTED, "status": "autoDisabled"}
    result, patches = _run(payload, _remote(status="autoDisabled"))
    assert patches == []
    assert result.action == PlanAction.NOOP


# --- collect --------------------------------------------------------------


def _envelope(remote: dict) -> dict:
    h = DefenderCustomDetectionHandler(lambda: None)
    env = h.to_envelope(remote)
    assert env is not None
    return env


def test_to_envelope_disabled_is_deprecated_and_drops_isenabled() -> None:
    env = _envelope(_remote(status="disabled", isEnabled=False))
    assert env["status"] == "deprecated"
    assert env["payload"]["status"] == "disabled"
    assert "isEnabled" not in env["payload"]


def test_to_envelope_auto_disabled_stays_production() -> None:
    env = _envelope(_remote(status="autoDisabled"))
    assert env["status"] == "production"
    assert env["payload"]["status"] == "autoDisabled"


def test_to_envelope_legacy_remote_keeps_isenabled() -> None:
    remote = {k: v for k, v in _remote().items() if k != "status"}
    remote["isEnabled"] = False
    env = _envelope(remote)
    assert env["status"] == "deprecated"
    assert env["payload"]["isEnabled"] is False
