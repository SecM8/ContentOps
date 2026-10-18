# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Live CRUD round-trip against Defender XDR custom detections.

Skipped unless RUN_LIVE_TESTS=1 and the credential has the
CustomDetection.ReadWrite.All Graph application permission.
"""

from __future__ import annotations

import time

import pytest

from tests.integration.conftest import RESOURCE_PREFIX_UNDERSCORE

# Graph acknowledges PATCH / DELETE with 2xx before its read path catches
# up; a GET issued straight after can return the pre-write body or the
# deleted rule (observed 2026-10-18, seconds-scale). Poll before asserting.
_READ_CONVERGE_TIMEOUT_S = 120
_READ_POLL_INTERVAL_S = 5
# DELETE is slower still: on 2026-10-18 a rule stayed readable for
# minutes after a 204 (and after the teardown's second DELETE), then
# disappeared on its own. Give it two DELETEs and this long before
# calling it a Graph-side lag instead of a pipeline failure.
_DELETE_CONVERGE_TIMEOUT_S = 180


def _wait_for(check, *, what: str, timeout_s: float = _READ_CONVERGE_TIMEOUT_S) -> bool:
    """Poll ``check()`` until truthy or ``timeout_s`` elapses."""
    deadline = time.monotonic() + timeout_s
    while not check():
        if time.monotonic() >= deadline:
            return False
        time.sleep(_READ_POLL_INTERVAL_S)
    return True


def _display_name(integration_id: str) -> str:
    """Test displayName starts with the sweep-recognised prefix."""
    return f"{RESOURCE_PREFIX_UNDERSCORE}{integration_id}"


def _detection_body(display_name: str) -> dict:
    """Minimal valid Defender custom detection payload (Graph beta).

    impactedAssets must be non-empty — the API rejects with InvalidInput
    "At least one of impactedAssets or entityMappings must be provided."
    The DeviceId column from DeviceProcessEvents satisfies the
    impactedDeviceAsset type.
    """
    return {
        "displayName": display_name,
        "isEnabled": False,
        "queryCondition": {
            "queryText": "DeviceProcessEvents | take 1",
        },
        "schedule": {"period": "1H"},
        "detectionAction": {
            "alertTemplate": {
                "title": display_name,
                "description": "integration test — safe to delete",
                "severity": "informational",
                "category": "SuspiciousActivity",
                "recommendedActions": "none",
                "mitreTechniques": [],
                "impactedAssets": [
                    {
                        "@odata.type": "#microsoft.graph.security.impactedDeviceAsset",
                        "identifier": "deviceId",
                    },
                ],
            },
            "organizationalScope": None,
            "responseActions": [],
        },
    }


def test_defender_custom_detection_full_crud(defender_client, integration_id, created_defender_rules):
    name = _display_name(integration_id)

    # CREATE
    create_resp = defender_client.create_rule(_detection_body(name))
    assert create_resp.status_code in (200, 201), create_resp.text
    graph_id = create_resp.json()["id"]
    created_defender_rules.append(graph_id)

    # READ
    fetched = defender_client.get_rule(graph_id)
    assert fetched is not None
    assert fetched["displayName"] == name

    # UPDATE
    update_resp = defender_client.update_rule(graph_id, {"displayName": f"{name} v2"})
    assert update_resp.status_code in (200, 204), update_resp.text
    assert _wait_for(
        lambda: (defender_client.get_rule(graph_id) or {}).get("displayName", "").endswith("v2"),
        what="updated displayName",
    ), f"updated displayName not visible {_READ_CONVERGE_TIMEOUT_S}s after PATCH"

    # LIST contains it
    listed_ids = {r["id"] for r in defender_client.list_rules()}
    assert graph_id in listed_ids

    # DELETE
    delete_resp = defender_client.delete_rule(graph_id)
    assert delete_resp.status_code in (200, 204), delete_resp.text
    gone = _wait_for(lambda: defender_client.get_rule(graph_id) is None, what="deletion")
    if not gone:
        # Second DELETE must be accepted (2xx) or report the rule gone (404).
        again = defender_client.delete_rule(graph_id)
        assert again.status_code in (200, 204, 404), again.text
        gone = _wait_for(
            lambda: defender_client.get_rule(graph_id) is None,
            what="deletion", timeout_s=_DELETE_CONVERGE_TIMEOUT_S,
        )
    if not gone:
        # Leave the id in created_defender_rules: teardown and the next
        # session's sweep keep retrying. The pipeline's own delete path
        # never reads back, so this is a Graph convergence lag, not a
        # pipeline defect — report it as such instead of failing.
        pytest.xfail(
            f"Graph accepted DELETE for rule {graph_id} twice but still serves it "
            f"{_READ_CONVERGE_TIMEOUT_S + _DELETE_CONVERGE_TIMEOUT_S}s later; "
            "teardown sweep retries"
        )

    created_defender_rules.remove(graph_id)
