# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Live CRUD round-trip for the parser asset kind.

After the asset-taxonomy reduction (Phase 1C), this file's surviving
coverage is the parser CRUD test only. The bookmark / hunt CRUDs the
file used to carry went with their handlers.

Skipped unless RUN_LIVE_TESTS=1.
"""

from __future__ import annotations

import uuid

import pytest


def _name_to_guid(name: str) -> str:
    """Stable GUID derived from a slug — for resources that require one."""
    return str(uuid.uuid5(uuid.NAMESPACE_URL, name))


# ---------------------------------------------------------------------------
# Per-resource cleanup fixtures (parallel to created_sentinel_rules)
# ---------------------------------------------------------------------------


@pytest.fixture
def created_sentinel_extras(integration_sentinel_config, integration_credential):
    """Track per-resource-type ids; sweep on teardown via the same client."""
    from contentops.providers.sentinel_arm import SentinelArmProvider

    provider = SentinelArmProvider(
        integration_sentinel_config,
        credential=integration_credential,
    )
    pending: list[tuple[str, str]] = []
    try:
        yield pending
    finally:
        for kind, name in pending:
            try:
                provider.delete_resource(kind, name)
            except Exception:
                pass
        provider.close()



# ---------------------------------------------------------------------------
# Parser (savedSearch with category=Function)
# ---------------------------------------------------------------------------


def test_parser_full_crud(integration_sentinel_config, integration_credential,
                          integration_id, created_sentinel_extras):
    from contentops.providers.sentinel_arm import SentinelArmProvider

    provider = SentinelArmProvider(
        integration_sentinel_config,
        credential=integration_credential,
    )
    try:
        # parser names cannot contain hyphens at the start; integration_id
        # uses zz-itest- prefix which is fine for savedSearches.
        body = {
            "properties": {
                "category": "Function",
                "displayName": integration_id,
                "query": "print synthetic = \"parser\"",
                "version": 2,
                "functionAlias": integration_id.replace("-", "_"),
            }
        }
        url = provider.la_resource_url("savedSearches", integration_id)

        # CREATE
        resp = provider.request("PUT", url, json=body)
        assert resp.status_code in (200, 201), resp.text

        # READ
        got = provider.request("GET", url)
        assert got.status_code == 200
        assert got.json()["properties"]["category"] == "Function"

        # DELETE
        deleted = provider.request("DELETE", url)
        assert deleted.status_code in (200, 204), deleted.text
    finally:
        provider.close()


