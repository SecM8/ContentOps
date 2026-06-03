# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Live CRUD round-trip against a Sentinel workspace.

Skipped unless RUN_LIVE_TESTS=1 and INTEGRATION_* env vars are set.
Each test cleans up via the `created_sentinel_rules` fixture.
"""

from __future__ import annotations


def _scheduled_rule_body(display_name: str) -> dict:
    """Minimal valid ScheduledAlertRule payload for the ARM upsert API.

    The query intentionally references no Log Analytics tables. ARM
    validates the KQL on UPDATE, and Sentinel Contributor on the RG
    does not grant table-read on the underlying workspace; using
    ``print`` sidesteps that validation entirely.
    """
    return {
        "kind": "Scheduled",
        "properties": {
            "displayName": display_name,
            "description": "integration test — safe to delete",
            "severity": "Informational",
            "enabled": False,
            "query": "print Test = \"synthetic\"",
            "queryFrequency": "PT1H",
            "queryPeriod": "PT1H",
            "triggerOperator": "GreaterThan",
            "triggerThreshold": 0,
            "suppressionDuration": "PT5H",
            "suppressionEnabled": False,
            "tactics": [],
            "techniques": [],
        },
    }


def test_sentinel_analytic_full_crud(sentinel_client, integration_id, created_sentinel_rules):
    rule_id = integration_id
    created_sentinel_rules.append(rule_id)

    # CREATE
    create_resp = sentinel_client.put_resource(
        "alertRules", rule_id, _scheduled_rule_body(integration_id),
    )
    assert create_resp.status_code in (200, 201), create_resp.text

    # READ
    fetched = sentinel_client.get_resource("alertRules", rule_id)
    assert fetched is not None
    assert fetched["properties"]["displayName"] == integration_id

    # UPDATE
    body = _scheduled_rule_body(f"{integration_id} v2")
    update_resp = sentinel_client.put_resource("alertRules", rule_id, body)
    assert update_resp.status_code in (200, 201), update_resp.text
    assert sentinel_client.get_resource("alertRules", rule_id)["properties"]["displayName"].endswith("v2")

    # LIST contains it
    listed_ids = {r["name"] for r in sentinel_client.list_resource("alertRules")}
    assert rule_id in listed_ids

    # DELETE
    delete_resp = sentinel_client.delete_resource("alertRules", rule_id)
    assert delete_resp.status_code in (200, 204), delete_resp.text
    assert sentinel_client.get_resource("alertRules", rule_id) is None

    # Already deleted; nothing for the fixture to clean up.
    created_sentinel_rules.remove(rule_id)
