# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Live CRUD round-trip against Defender XDR custom detections.

Skipped unless RUN_LIVE_TESTS=1 and the credential has the
CustomDetection.ReadWrite.All Graph application permission.
"""

from __future__ import annotations


from tests.integration.conftest import RESOURCE_PREFIX_UNDERSCORE


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
    assert defender_client.get_rule(graph_id)["displayName"].endswith("v2")

    # LIST contains it
    listed_ids = {r["id"] for r in defender_client.list_rules()}
    assert graph_id in listed_ids

    # DELETE
    delete_resp = defender_client.delete_rule(graph_id)
    assert delete_resp.status_code in (200, 204), delete_resp.text
    assert defender_client.get_rule(graph_id) is None

    created_defender_rules.remove(graph_id)
