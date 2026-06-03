# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Regression test for ARM ``nextLink`` pagination on
``SentinelArmProvider.list_resource``.

The provider silently dropped page 2+ before, which made drift /
prune misclassify tail-of-collection rules as orphans. This test
stages two pages and asserts the provider returns *all* items.

The v1 shim's ``list_rules`` pagination test was moved to
``tests/v2/test_sentinel_client_shim_compat.py`` so all shim-specific
coverage lives next to its sibling shim regression tests.
"""

from __future__ import annotations

import respx
from httpx import Response

from contentops.config import SentinelConfig
from contentops.providers.sentinel_arm import SentinelArmProvider


def _config() -> SentinelConfig:
    return SentinelConfig(
        subscriptionId="00000000-0000-0000-0000-000000000000",
        resourceGroup="rg-test",
        workspaceName="ws-test",
    )


@respx.mock
def test_sentinel_arm_provider_list_resource_follows_nextlink() -> None:
    provider = SentinelArmProvider(_config(), token="fake")
    page2_url = "https://management.azure.com/wl-page2"
    base = (
        "https://management.azure.com/subscriptions/"
        "00000000-0000-0000-0000-000000000000/resourceGroups/rg-test"
        "/providers/Microsoft.OperationalInsights/workspaces/ws-test"
        "/providers/Microsoft.SecurityInsights/watchlists"
    )
    respx.get(url__startswith=base).mock(
        return_value=Response(
            200,
            json={"value": [{"name": "wl-1"}], "nextLink": page2_url},
        )
    )
    respx.get(page2_url).mock(
        return_value=Response(200, json={"value": [{"name": "wl-2"}, {"name": "wl-3"}]})
    )

    items = provider.list_resource("watchlists")

    assert [i["name"] for i in items] == ["wl-1", "wl-2", "wl-3"]
