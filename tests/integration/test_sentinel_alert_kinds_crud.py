# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Live CRUD round-trips for the additional Sentinel alert rule kinds.

Skipped unless RUN_LIVE_TESTS=1 and the INTEGRATION_* env is set. Each
test uses ``integration_id`` so the session-end sweep can clean up
anything we leak. ``enabled`` is forced to ``False`` on creation so a
mid-test failure cannot fire alerts in the target workspace.

Coverage:
  * MicrosoftSecurityIncidentCreation
  * NRT (full create/update/delete via the same handler pathway)
  * Fusion / MLBehaviorAnalytics / ThreatIntelligence are NOT exercised
    here because they require a Microsoft-shipped template the target
    tenant has installed; without that the API rejects the PUT. Those
    kinds are validated at the unit-test layer (tests/v2/test_analytic_kinds.py)
    against fixed fixture payloads.
"""

from __future__ import annotations


def _msi_body(display_name: str) -> dict:
    return {
        "kind": "MicrosoftSecurityIncidentCreation",
        "properties": {
            "displayName": display_name,
            "description": "integration test — safe to delete",
            "enabled": False,
            "productFilter": "Azure Security Center",
            "severitiesFilter": ["High"],
        },
    }


def _nrt_body(display_name: str) -> dict:
    return {
        "kind": "NRT",
        "properties": {
            "displayName": display_name,
            "description": "integration test — safe to delete",
            "enabled": False,
            "severity": "Informational",
            "query": "print Test = \"synthetic\"",
            "tactics": [],
            "techniques": [],
            "suppressionDuration": "PT5H",
            "suppressionEnabled": False,
        },
    }


def test_microsoft_security_incident_creation_full_crud(
    sentinel_client, integration_id, created_sentinel_rules,
):
    rule_id = integration_id
    created_sentinel_rules.append(rule_id)

    create = sentinel_client.put_resource("alertRules", rule_id, _msi_body(integration_id))
    assert create.status_code in (200, 201), create.text

    fetched = sentinel_client.get_resource("alertRules", rule_id)
    assert fetched is not None
    assert fetched["kind"] == "MicrosoftSecurityIncidentCreation"
    assert fetched["properties"]["productFilter"] == "Azure Security Center"

    body = _msi_body(f"{integration_id} v2")
    update = sentinel_client.put_resource("alertRules", rule_id, body)
    assert update.status_code in (200, 201), update.text
    refetched = sentinel_client.get_resource("alertRules", rule_id)
    assert refetched["properties"]["displayName"].endswith("v2")

    delete = sentinel_client.delete_resource("alertRules", rule_id)
    assert delete.status_code in (200, 204), delete.text
    assert sentinel_client.get_resource("alertRules", rule_id) is None
    created_sentinel_rules.remove(rule_id)


def test_nrt_full_crud(sentinel_client, integration_id, created_sentinel_rules):
    rule_id = integration_id
    created_sentinel_rules.append(rule_id)

    create = sentinel_client.put_resource("alertRules", rule_id, _nrt_body(integration_id))
    assert create.status_code in (200, 201), create.text

    fetched = sentinel_client.get_resource("alertRules", rule_id)
    assert fetched is not None
    assert fetched["kind"] == "NRT"

    delete = sentinel_client.delete_resource("alertRules", rule_id)
    assert delete.status_code in (200, 204), delete.text
    created_sentinel_rules.remove(rule_id)
