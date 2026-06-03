# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Round-trip drift tests for hunting, watchlist, and defender handlers."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import httpx
import pytest

from contentops.config import SentinelConfig
from contentops.core.asset import Asset
from contentops.core.drift import DriftCapable, detect_drift
from contentops.handlers.defender_custom_detection import DefenderCustomDetectionHandler
from contentops.handlers.sentinel_hunting import SentinelHuntingHandler
from contentops.handlers.sentinel_watchlist import SentinelWatchlistHandler
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


# ---------------- Hunting ----------------

def _hunting_list_response() -> dict:
    return {
        "value": [
            {
                "name": "hunt-a",
                "properties": {
                    "category": "Hunting Queries",
                    "displayName": "Hunt A",
                    "query": "T | take 1",
                    "version": 2,
                    "tags": [
                        {"name": "description", "value": "desc-a"},
                        {"name": "tactics", "value": "Execution,Persistence"},
                        {"name": "techniques", "value": "T1059,T1547"},
                        {"name": "custom", "value": "v"},
                    ],
                },
            },
            {
                "name": "hunt-b",
                "properties": {
                    "category": "Hunting Queries",
                    "displayName": "Hunt B",
                    "query": "T | take 2",
                    "version": 2,
                },
            },
            {
                "name": "dashboard-x",
                "properties": {
                    "category": "Workbook",
                    "displayName": "Dashboard X",
                    "query": "T | take 0",
                },
            },
        ]
    }


def test_hunting_list_remote_filters_to_hunting_category() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert "savedSearches" in str(request.url)
        return httpx.Response(200, json=_hunting_list_response())

    provider = _provider_with(httpx.MockTransport(handler))
    h = SentinelHuntingHandler(lambda: provider)
    items = h.list_remote()
    assert {i["name"] for i in items} == {"hunt-a", "hunt-b"}
    assert isinstance(h, DriftCapable)
    h.close()


def test_hunting_to_envelope_decodes_tags_back_to_tactics_techniques() -> None:
    h = SentinelHuntingHandler(lambda: None)
    remote = _hunting_list_response()["value"][0]
    env = h.to_envelope(remote)
    assert env is not None
    assert env["id"] == "hunt-a"
    assert env["asset"] == Asset.SENTINEL_HUNTING.value
    assert env["status"] == "production"
    payload = env["payload"]
    assert payload["displayName"] == "Hunt A"
    assert payload["query"] == "T | take 1"
    assert payload["category"] == "Hunting Queries"
    assert payload["version"] == 2
    assert payload["description"] == "desc-a"
    assert payload["tactics"] == ["Execution", "Persistence"]
    assert payload["techniques"] == ["T1059", "T1547"]
    assert payload["tags"] == [{"name": "custom", "value": "v"}]


def test_hunting_to_envelope_returns_None_for_non_hunting_category() -> None:
    h = SentinelHuntingHandler(lambda: None)
    remote = _hunting_list_response()["value"][2]
    assert h.to_envelope(remote) is None


# ---------------- Watchlist ----------------

CSV_BODY = "ip,owner\n10.0.0.1,alice\n10.0.0.2,bob\n"


def test_watchlist_list_remote_returns_all_items() -> None:
    items_payload = {"value": [
        {"name": "hva", "properties": {"displayName": "HVA"}},
        {"name": "vips", "properties": {"displayName": "VIPs"}},
    ]}

    def handler(_):
        return httpx.Response(200, json=items_payload)

    provider = _provider_with(httpx.MockTransport(handler))
    h = SentinelWatchlistHandler(lambda: provider)
    items = h.list_remote()
    assert {i["name"] for i in items} == {"hva", "vips"}
    assert isinstance(h, DriftCapable)
    h.close()


def test_watchlist_to_envelope_fetches_rawcontent_when_missing() -> None:
    full_response = {
        "name": "hva",
        "properties": {
            "displayName": "HVA", "provider": "Custom",
            "source": "Local file", "itemsSearchKey": "ip",
            "contentType": "text/csv", "rawContent": CSV_BODY,
            "watchlistId": "guid-123", "etag": "abc",
        },
    }

    def handler(request: httpx.Request) -> httpx.Response:
        # Per-item GET path includes the resource name.
        assert "watchlists/hva" in str(request.url)
        return httpx.Response(200, json=full_response)

    provider = _provider_with(httpx.MockTransport(handler))
    h = SentinelWatchlistHandler(lambda: provider)
    list_item = {
        "name": "hva",
        "properties": {
            "displayName": "HVA", "provider": "Custom",
            "source": "Local file", "itemsSearchKey": "ip",
            "contentType": "text/csv",
            # rawContent intentionally omitted from list response
        },
    }
    env = h.to_envelope(list_item)
    assert env is not None
    assert env["id"] == "hva"
    assert env["asset"] == Asset.SENTINEL_WATCHLIST.value
    assert env["status"] == "production"
    assert env["payload"]["rawContent"] == CSV_BODY
    h.close()


def test_watchlist_to_envelope_strips_server_fields() -> None:
    h = SentinelWatchlistHandler(lambda: None)
    remote = {
        "name": "hva",
        "properties": {
            "displayName": "HVA", "provider": "Custom", "source": "Local file",
            "itemsSearchKey": "ip", "contentType": "text/csv",
            "rawContent": CSV_BODY, "numberOfLinesToSkip": 0,
            "etag": "abc", "watchlistId": "guid-1", "tenantId": "tid",
            "watchlistAlias": "hva", "isDeleted": False,
            "created": "2024-01-01", "updated": "2024-01-02",
            "createdBy": {"name": "u"}, "updatedBy": {"name": "u"},
            "provisioningState": "Succeeded",
        },
    }
    env = h.to_envelope(remote)
    assert env is not None
    payload = env["payload"]
    for k in ("etag", "watchlistId", "tenantId", "watchlistAlias", "isDeleted",
              "created", "updated", "createdBy", "updatedBy", "provisioningState",
              "numberOfLinesToSkip"):
        assert k not in payload
    assert payload["displayName"] == "HVA"
    assert payload["rawContent"] == CSV_BODY


# ---------------- Defender ----------------

def test_defender_list_remote_paginates() -> None:
    page1 = {
        "value": [{"id": "1", "displayName": "R1", "isEnabled": True}],
        "@odata.nextLink": "https://graph.microsoft.com/beta/security/rules/detectionRules?$skiptoken=abc",
    }
    page2 = {
        "value": [{"id": "2", "displayName": "R2", "isEnabled": True}],
    }
    client = MagicMock()
    client.list_rules = lambda: page1["value"] + page2["value"]
    h = DefenderCustomDetectionHandler(lambda: client)
    items = h.list_remote()
    assert [i["id"] for i in items] == ["1", "2"]
    assert isinstance(h, DriftCapable)


def test_defender_client_list_rules_follows_nextlink() -> None:
    """The DefenderClient itself paginates via @odata.nextLink."""
    from contentops.defender import client as dc

    page1 = {
        "value": [{"id": "1", "displayName": "R1"}],
        "@odata.nextLink": "https://graph.microsoft.com/beta/security/rules/detectionRules?$skiptoken=abc",
    }
    page2 = {"value": [{"id": "2", "displayName": "R2"}]}
    pages = iter([page1, page2])

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=next(pages))

    transport = httpx.MockTransport(handler)
    client = dc.DefenderClient(token="t")
    client._client.close()
    client._client = httpx.Client(
        base_url=dc.BASE_URL, transport=transport,
        headers={"Authorization": "Bearer t"},
    )
    items = client.list_rules()
    assert [i["id"] for i in items] == ["1", "2"]
    client.close()


def test_defender_to_envelope_status_reflects_isEnabled() -> None:
    h = DefenderCustomDetectionHandler(lambda: None)
    enabled = h.to_envelope({
        "id": "guid-1", "displayName": "Suspicious Logon",
        "isEnabled": True, "queryCondition": {"queryText": "T | take 1"},
        "createdDateTime": "x", "lastModifiedDateTime": "y",
        "createdBy": {}, "lastModifiedBy": {}, "lastExecutionDateTime": "z",
    })
    assert enabled is not None
    # The envelope id is now the displayName slug (no "defender-" prefix);
    # the original Graph id is preserved on metadata.arm_name so apply can
    # still PATCH the same remote rule.
    assert enabled["id"] == "suspicious-logon"
    assert enabled["metadata"]["arm_name"] == "guid-1"
    assert enabled["asset"] == Asset.DEFENDER_CUSTOM_DETECTION.value
    assert enabled["status"] == "production"
    for k in ("id", "createdDateTime", "lastModifiedDateTime",
              "createdBy", "lastModifiedBy", "lastExecutionDateTime"):
        assert k not in enabled["payload"]
    assert enabled["payload"]["displayName"] == "Suspicious Logon"

    disabled = h.to_envelope({
        "id": "guid-2", "displayName": "Old Rule", "isEnabled": False,
    })
    assert disabled is not None
    assert disabled["status"] == "deprecated"


def test_defender_to_envelope_strips_g2_server_fields() -> None:
    """G2 regression: detectorId / lastRunDetails / nested server timestamps
    must not leak into the round-tripped payload.

    Pre-fix, every defender rule reported `changed` in drift because the
    remote payload kept these server-set fields and the v1-collected
    local YAML didn't have them. See docs/reference/gap-assessment.md G2.
    """
    h = DefenderCustomDetectionHandler(lambda: None)
    remote = {
        "id": "guid-1",
        "displayName": "Suspicious Logon",
        "isEnabled": True,
        "queryCondition": {
            "queryText": "T | take 1",
            "lastModifiedDateTime": "2026-05-01T00:00:00Z",
        },
        "schedule": {
            "period": "1H",
            "nextRunDateTime": "2026-05-07T10:00:00Z",
        },
        "detectorId": "det-abc",
        "lastRunDetails": {
            "lastRunDateTime": "2026-05-07T09:00:00Z",
            "status": "succeeded",
            "errorCode": None,
        },
        # Already-stripped fields — keep them in the fixture so this test
        # also covers the previous behaviour by regression.
        "createdDateTime": "x", "lastModifiedDateTime": "y",
        "createdBy": {}, "lastModifiedBy": {}, "lastExecutionDateTime": "z",
    }
    env = h.to_envelope(remote)
    assert env is not None
    payload = env["payload"]

    # New top-level server fields are gone.
    assert "detectorId" not in payload
    assert "lastRunDetails" not in payload

    # Nested server timestamps are gone but the meaningful fields survive.
    assert payload["queryCondition"] == {"queryText": "T | take 1"}
    assert payload["schedule"] == {"period": "1H"}


def test_defender_drift_clean_after_g2_fix() -> None:
    """End-to-end: a remote with server fields round-trips clean against
    a local payload that doesn't carry them (the v1-collected shape).

    This is the actual scenario that produced the 46/46 false-changed
    count in drift-report.json before the fix.
    """
    from contentops.core.drift import _payloads_match

    # Local payload as v1 collect produced it — no server fields.
    local_payload = {
        "displayName": "T1087.002 Account Discovery: Domain Account",
        "isEnabled": True,
        "queryCondition": {"queryText": "DeviceProcessEvents | take 1"},
        "schedule": {"period": "1H"},
        "detectionAction": {
            "alertTemplate": {
                "title": "Discovery", "severity": "medium",
                "category": "Discovery",
            },
            "responseActions": [],
        },
    }

    # Remote as the Graph API returns it — same content plus server fields.
    remote = {
        **local_payload,
        "id": "graph-id-xyz",
        "createdDateTime": "x",
        "lastModifiedDateTime": "y",
        "createdBy": {},
        "lastModifiedBy": {},
        "detectorId": "det-xyz",
        "lastRunDetails": {"status": "succeeded"},
        "queryCondition": {
            **local_payload["queryCondition"],
            "lastModifiedDateTime": "2026-05-01T00:00:00Z",
        },
        "schedule": {
            **local_payload["schedule"],
            "nextRunDateTime": "2026-05-07T10:00:00Z",
        },
    }

    h = DefenderCustomDetectionHandler(lambda: None)
    env = h.to_envelope(remote)
    assert env is not None

    # The remote payload after to_envelope() must compare equal to the
    # locally-stored payload — i.e. no false-positive drift.
    assert _payloads_match(local_payload, env["payload"]), (
        f"local != remote after to_envelope; diff:\n"
        f"  local : {sorted(local_payload.keys())}\n"
        f"  remote: {sorted(env['payload'].keys())}"
    )


# ---------------- Integration ----------------

class _StubHandler:
    def __init__(self, asset: Asset, items: list[dict]) -> None:
        self.asset = asset
        self._items = items

    def list_remote(self) -> list[dict]:
        return self._items

    def to_envelope(self, remote: dict) -> dict | None:
        return {
            "id": remote["name"],
            "version": "0.1.0",
            "asset": self.asset.value,
            "status": "production",
            "payload": remote.get("payload", {}),
        }


def test_drift_command_includes_hunting_watchlist_defender(tmp_path: Path) -> None:
    hunting = _StubHandler(Asset.SENTINEL_HUNTING, [{"name": "hunt-1"}])
    watchlist = _StubHandler(Asset.SENTINEL_WATCHLIST, [{"name": "wl-1"}])
    defender = _StubHandler(Asset.DEFENDER_CUSTOM_DETECTION, [{"name": "defender-rule-a"}])

    for h in (hunting, watchlist, defender):
        assert isinstance(h, DriftCapable)

    report = detect_drift([hunting, watchlist, defender], tmp_path)
    assets = {(e.asset, e.asset_id) for e in report.new}
    assert (Asset.SENTINEL_HUNTING, "hunt-1") in assets
    assert (Asset.SENTINEL_WATCHLIST, "wl-1") in assets
    assert (Asset.DEFENDER_CUSTOM_DETECTION, "defender-rule-a") in assets
