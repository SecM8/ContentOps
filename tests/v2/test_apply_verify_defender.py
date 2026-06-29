# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Post-apply verification tests for DefenderCustomDetectionHandler.

Microsoft Graph Security Beta does not expose ARM-style ``etag`` /
``If-Match`` semantics for detection rules, so this handler does
content-hash verification only — there is no 412 path to test.
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
from contentops.handlers.defender_custom_detection import DefenderCustomDetectionHandler


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


_PAYLOAD = {
    "displayName": "Defender Test",
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


def _list_response(rules: list[dict] | None = None) -> dict:
    return {"value": rules or []}


def _full_remote(query: str = _PAYLOAD["queryCondition"]["queryText"]) -> dict:
    return {
        "id": "graph-1",
        "displayName": _PAYLOAD["displayName"],
        "isEnabled": True,
        "queryCondition": {"queryText": query},
        "schedule": _PAYLOAD["schedule"],
        "actions": _PAYLOAD["actions"],
        "alertTemplate": _PAYLOAD["alertTemplate"],
        "createdDateTime": "2024-01-01T00:00:00Z",  # ignored
    }


def test_apply_happy_path_verifies_hash_create() -> None:
    """First-create path: name_map empty, POST returns 201, GET verifies."""

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if request.method == "GET" and path.endswith("/detectionRules"):
            return httpx.Response(200, json=_list_response())
        if request.method == "POST" and path.endswith("/detectionRules"):
            return httpx.Response(201, json=_full_remote())
        if request.method == "GET" and "/detectionRules/graph-1" in path:
            return httpx.Response(200, json=_full_remote())
        return httpx.Response(404, text=f"unexpected {request.method} {path}")

    client = _client_with(httpx.MockTransport(handler))
    h = DefenderCustomDetectionHandler(lambda: client)
    result = h.apply(_loaded())

    assert result.status == "success", result.detail
    assert result.verified is True
    assert result.error is None


def test_apply_happy_path_verifies_hash_update() -> None:
    """PATCH path: the live rule DIFFERS from the desired body, so the handler
    updates it (not a no-op), then the post-apply GET verifies the new hash."""
    state = {"patched": False}

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if request.method == "GET" and path.endswith("/detectionRules"):
            # name-map build: rule exists under this displayName (graph-1).
            return httpx.Response(200, json=_list_response([_full_remote(query="OLD")]))
        if request.method == "GET" and "/detectionRules/graph-1" in path:
            # pre-update no-op probe sees OLD content (forces a real PATCH);
            # the post-apply verify GET sees the new, matching content.
            return httpx.Response(
                200,
                json=_full_remote() if state["patched"] else _full_remote(query="OLD"),
            )
        if request.method == "PATCH" and "/detectionRules/graph-1" in path:
            state["patched"] = True
            return httpx.Response(200, json=_full_remote())
        return httpx.Response(404, text=f"unexpected {request.method} {path}")

    client = _client_with(httpx.MockTransport(handler))
    h = DefenderCustomDetectionHandler(lambda: client)
    result = h.apply(_loaded())

    assert state["patched"] is True, "a differing rule must be PATCHed"
    assert result.status == "success", result.detail
    assert result.verified is True


def test_apply_verifies_when_remote_has_server_managed_nested_fields() -> None:
    """Regression: post-apply GET returns ``schedule.nextRunDateTime``
    (server-managed runtime field that moves between PUT and the
    verifying GET). The local body has it stripped at collect time, so
    without symmetric stripping at apply-verify the hash mismatches on
    every Defender rule forever.

    This test pins the fix: the handler strips the same server-managed
    nested fields (``_SERVER_NESTED_FIELDS``) from the GET response
    before hashing, so the post-apply hash matches the pre-PUT hash
    even when the API echoes back fields we never authored."""

    # Remote response carries a freshly-minted nextRunDateTime that
    # is NOT in the local payload's schedule block.
    def _remote_with_nextrun() -> dict:
        remote = _full_remote()
        remote["schedule"] = {
            "period": _PAYLOAD["schedule"]["period"],
            "nextRunDateTime": "2026-05-10T21:18:14.6933333Z",
        }
        # Also throw in the other server-managed nested field for good
        # measure — queryCondition.lastModifiedDateTime — so we cover
        # both entries of _SERVER_NESTED_FIELDS at once.
        remote["queryCondition"] = {
            "queryText": _PAYLOAD["queryCondition"]["queryText"],
            "lastModifiedDateTime": "2026-05-10T21:18:14.6933333Z",
        }
        return remote

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if request.method == "GET" and path.endswith("/detectionRules"):
            return httpx.Response(200, json=_list_response())
        if request.method == "POST" and path.endswith("/detectionRules"):
            return httpx.Response(201, json=_remote_with_nextrun())
        if request.method == "GET" and "/detectionRules/graph-1" in path:
            return httpx.Response(200, json=_remote_with_nextrun())
        return httpx.Response(404, text=f"unexpected {request.method} {path}")

    client = _client_with(httpx.MockTransport(handler))
    h = DefenderCustomDetectionHandler(lambda: client)
    result = h.apply(_loaded())

    assert result.status == "success", result.detail
    assert result.verified is True, (
        "remote nextRunDateTime/lastModifiedDateTime must NOT cause MISMATCH"
    )
    assert result.error is None


def test_apply_create_logs_non_json_response_body(caplog) -> None:
    """Regression for H-4: when create_rule returns non-JSON (e.g. a
    transient gateway 5xx that's actually an HTML error page), the
    handler used to swallow the decode error with bare ``except`` and
    silently set ``graph_id = ""``. The post-apply GET then 404'd and
    reported the wrong root cause. We now log the body excerpt so the
    operator can triage."""

    import logging

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if request.method == "GET" and path.endswith("/detectionRules"):
            return httpx.Response(200, json=_list_response())
        if request.method == "POST" and path.endswith("/detectionRules"):
            # 201 but body is not JSON.
            return httpx.Response(201, text="<html>oops</html>")
        return httpx.Response(404)

    client = _client_with(httpx.MockTransport(handler))
    h = DefenderCustomDetectionHandler(lambda: client)
    with caplog.at_level(
        logging.ERROR, logger="contentops.handlers.defender_custom_detection",
    ):
        result = h.apply(_loaded())
    assert result.verified is False
    assert any("non-JSON" in r.message for r in caplog.records)
    assert any("oops" in r.message for r in caplog.records)


def test_apply_hash_mismatch() -> None:
    state = {"phase": "create"}

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if request.method == "GET" and path.endswith("/detectionRules"):
            return httpx.Response(200, json=_list_response())
        if request.method == "POST" and path.endswith("/detectionRules"):
            return httpx.Response(201, json=_full_remote())
        if request.method == "GET" and "/detectionRules/graph-1" in path:
            # post-apply GET returns altered query
            return httpx.Response(200, json=_full_remote(query="union *"))
        return httpx.Response(404)

    client = _client_with(httpx.MockTransport(handler))
    h = DefenderCustomDetectionHandler(lambda: client)
    result = h.apply(_loaded())

    assert result.verified is False
    assert "post-apply hash mismatch" in (result.error or "")


def test_apply_noop_when_unchanged() -> None:
    """A rule whose live content already matches the desired body is NOT
    re-pushed: no PATCH is issued and the result is a NOOP. This is what
    spares collected-but-unchanged FileProfile rules from the beta
    save-validator 400 on every deploy."""
    state = {"patched": False}

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if request.method == "GET" and path.endswith("/detectionRules"):
            return httpx.Response(200, json=_list_response([_full_remote()]))
        if request.method == "GET" and "/detectionRules/graph-1" in path:
            return httpx.Response(200, json=_full_remote())  # identical to desired
        if request.method == "PATCH" and "/detectionRules/graph-1" in path:
            state["patched"] = True
            return httpx.Response(200, json=_full_remote())
        return httpx.Response(404, text=f"unexpected {request.method} {path}")

    client = _client_with(httpx.MockTransport(handler))
    h = DefenderCustomDetectionHandler(lambda: client)
    result = h.apply(_loaded())

    assert state["patched"] is False, "unchanged rule must NOT be PATCHed"
    assert result.action == PlanAction.NOOP
    assert result.status == "success"
    assert result.verified is True


def test_apply_disable_pushes_even_when_content_matches() -> None:
    """An enable->disable must still be pushed. ``isEnabled`` is not in
    ``_HASHED_FIELDS``, so a deprecated rule whose content matches but is
    still enabled remotely must NOT be swallowed by the no-op skip."""
    state = {"patched": False}

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if request.method == "GET" and path.endswith("/detectionRules"):
            return httpx.Response(200, json=_list_response([_full_remote()]))
        if request.method == "GET" and "/detectionRules/graph-1" in path:
            remote = _full_remote()
            # Still enabled on the pre-update probe (forces the disable PATCH);
            # disabled on the post-apply verify GET.
            remote["isEnabled"] = not state["patched"]
            return httpx.Response(200, json=remote)
        if request.method == "PATCH" and "/detectionRules/graph-1" in path:
            state["patched"] = True
            return httpx.Response(200, json={**_full_remote(), "isEnabled": False})
        return httpx.Response(404, text=f"unexpected {request.method} {path}")

    env = EnvelopeV2(
        id="defender-test", version="0.1.0",
        asset=Asset.DEFENDER_CUSTOM_DETECTION, status="deprecated",
    )
    loaded = LoadedAsset(path=Path("d.yml"), envelope=env, payload=dict(_PAYLOAD))

    client = _client_with(httpx.MockTransport(handler))
    h = DefenderCustomDetectionHandler(lambda: client)
    result = h.apply(loaded)

    assert state["patched"] is True, "enable->disable must be pushed, not skipped"
    assert result.action == PlanAction.DISABLE
    assert result.status == "success"
