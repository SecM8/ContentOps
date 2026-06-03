# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for `contentops.upstream.marketplace.fetch_packages`."""

from __future__ import annotations

from unittest.mock import MagicMock

from contentops.upstream.marketplace import fetch_packages


def test_fetch_packages_normalises_arm_response() -> None:
    """Two packages plus one entry without a name -> 2 normalised entries."""
    provider = MagicMock()
    provider.list_resource.return_value = [
        {
            "name": "azuresentinel-microsoftsentinelteam-1",
            "kind": "Solution",
            "properties": {
                "displayName": "Azure Sentinel",
                "version": "2.0.5",
                "contentKind": "Solution",
                "source": {"kind": "Solution"},
                "lastPublishDate": "2026-04-30",
            },
        },
        {
            "name": "office-365-microsoft",
            "properties": {
                "displayName": "Office 365",
                "version": "3.1.0",
                "contentKind": "Solution",
                "source": {"kind": "Solution"},
            },
        },
        # Missing name -> defensive drop.
        {"name": "", "properties": {"displayName": "x"}},
    ]

    out = fetch_packages(provider)
    assert len(out) == 2
    assert out[0]["name"] == "azuresentinel-microsoftsentinelteam-1"
    assert out[0]["displayName"] == "Azure Sentinel"
    assert out[0]["version"] == "2.0.5"
    assert out[0]["source"] == "Solution"
    assert out[0]["lastPublishDate"] == "2026-04-30"
    # Missing-source case: empty string, not crash.
    assert out[1]["lastPublishDate"] == ""

    provider.list_resource.assert_called_once_with("contentPackages")


def test_fetch_packages_empty_list_returns_empty() -> None:
    provider = MagicMock()
    provider.list_resource.return_value = []
    assert fetch_packages(provider) == []
