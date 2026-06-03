# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Live create -> prune -> 404 round-trip per write-capable handler.

Skipped unless RUN_LIVE_TESTS=1. Each test:
  1. Creates a temp resource on the live tenant (zz-itest-* prefix).
  2. Calls handler.delete(remote_id) directly.
  3. Asserts a subsequent GET returns 404.
  4. Best-effort cleanup on failure via try/finally.

Coverage (post asset-taxonomy reduction — 6 surviving assets):
  - sentinel_analytic        (Microsoft.SecurityInsights/alertRules)
  - sentinel_hunting         (Microsoft.OperationalInsights/.../savedSearches)
  - sentinel_parser          (savedSearches Function category)
  - sentinel_watchlist       (watchlists; alias is the resource name)
  - defender_custom_detection (Graph beta detectionRules — already covered
                               by test_defender_custom_detection_crud)

Singleton handlers (settings, onboarding) are NOT exercised — their
delete() raises NotSupportedError and that's tested at the unit
layer. content_package, workbook, data_connector, summary_rule,
playbook need extra setup (parent resources, RGs) and are covered at
the unit layer + the broader collect/apply integration suite.
"""

from __future__ import annotations

import uuid

import pytest

from contentops.core.asset import Asset


def _expect_404(provider, url: str) -> None:
    resp = provider.request("GET", url)
    assert resp.status_code == 404, (
        f"expected 404 after delete, got {resp.status_code}: {resp.text[:200]}"
    )


# ---------------------------------------------------------------------------
# Sentinel analytic
# ---------------------------------------------------------------------------


def test_prune_sentinel_analytic_create_then_delete(
    sentinel_client, integration_id, created_sentinel_rules,
):
    from contentops.handlers.sentinel_analytic import SentinelAnalyticHandler

    body = {
        "kind": "Scheduled",
        "properties": {
            "displayName": integration_id,
            "description": "prune-itest — safe to delete",
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
    rule_id = integration_id
    created_sentinel_rules.append(rule_id)
    create = sentinel_client.put_resource("alertRules", rule_id, body)
    assert create.status_code in (200, 201), create.text

    h = SentinelAnalyticHandler(lambda: sentinel_client)
    result = h.delete(rule_id)
    assert result.status == "success", result.error
    assert sentinel_client.get_resource("alertRules", rule_id) is None
    created_sentinel_rules.remove(rule_id)


# ---------------------------------------------------------------------------
# Sentinel ARM provider-based handlers
# ---------------------------------------------------------------------------


@pytest.fixture
def arm_provider_for_prune(integration_sentinel_config, integration_credential):
    from contentops.providers.sentinel_arm import SentinelArmProvider

    p = SentinelArmProvider(
        integration_sentinel_config,
        credential=integration_credential,
    )
    yield p
    p.close()


def _name_to_guid(name: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_URL, name))






def test_prune_sentinel_parser_create_then_delete(
    arm_provider_for_prune, integration_id,
):
    """Parser = savedSearches with category='Function'."""
    from contentops.handlers.sentinel_parser import SentinelParserHandler

    body = {"properties": {
        "category": "Function",
        "displayName": integration_id,
        "query": "print synthetic = \"parser\"",
        "version": 2,
        "functionAlias": integration_id.replace("-", "_"),
    }}
    url = arm_provider_for_prune.la_resource_url("savedSearches", integration_id)
    create = arm_provider_for_prune.request("PUT", url, json=body)
    assert create.status_code in (200, 201), create.text

    h = SentinelParserHandler(lambda: arm_provider_for_prune)
    result = h.delete(integration_id)
    assert result.status == "success", result.error
    got = arm_provider_for_prune.request("GET", url)
    assert got.status_code == 404


