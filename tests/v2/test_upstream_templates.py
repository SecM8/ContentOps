# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for `contentops.upstream.templates.fetch_templates`."""

from __future__ import annotations

from unittest.mock import MagicMock

from contentops.upstream.templates import fetch_templates


def test_fetch_templates_normalises_arm_response() -> None:
    provider = MagicMock()
    provider.list_resource.return_value = [
        {
            "name": "b07f3f0d-1234-5678-aaaa-000000000001",
            "kind": "Scheduled",
            "properties": {
                "displayName": "Brute force SSH",
                "version": "1.0.4",
                "lastUpdatedDateTime": "2026-04-30T12:00:00Z",
                "source": {"kind": "Solution"},
            },
        },
        # Missing name -> defensive drop.
        {"properties": {"displayName": "Headless"}},
    ]
    out = fetch_templates(provider)
    assert len(out) == 1
    assert out[0]["name"] == "b07f3f0d-1234-5678-aaaa-000000000001"
    assert out[0]["displayName"] == "Brute force SSH"
    assert out[0]["kind"] == "Scheduled"
    assert out[0]["version"] == "1.0.4"
    assert out[0]["lastUpdatedDateTime"] == "2026-04-30T12:00:00Z"
    assert out[0]["source"] == "Solution"
    provider.list_resource.assert_called_once_with("alertRuleTemplates")
