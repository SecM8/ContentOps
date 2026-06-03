# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for Defender deploy logic."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from contentops.defender.deploy import build_display_name_map, deploy_defender_rule


class TestBuildDisplayNameMap:
    def test_builds_map(self) -> None:
        mock_client = MagicMock()
        mock_client.list_rules.return_value = [
            {"displayName": "Rule A", "id": "1"},
            {"displayName": "Rule B", "id": "2"},
        ]
        name_map = build_display_name_map(mock_client)
        assert name_map == {"Rule A": "1", "Rule B": "2"}

    def test_fails_on_duplicates(self) -> None:
        mock_client = MagicMock()
        mock_client.list_rules.return_value = [
            {"displayName": "Rule A", "id": "1"},
            {"displayName": "Rule A", "id": "2"},
        ]
        with pytest.raises(Exception, match="Duplicate displayNames"):
            build_display_name_map(mock_client)


class TestDeployDefenderRule:
    def test_dry_run(self) -> None:
        result = deploy_defender_rule(
            client=None,
            rule_id="defender-test-001",
            payload={"displayName": "Test Rule", "isEnabled": True},
            status="production",
            name_map={},
            dry_run=True,
        )
        assert result["result"] == "dry-run"
        assert result["action"] == "create"

    def test_create_new_rule(self) -> None:
        mock_response = MagicMock()
        mock_response.status_code = 201
        mock_client = MagicMock()
        mock_client.create_rule.return_value = mock_response

        result = deploy_defender_rule(
            client=mock_client,
            rule_id="defender-test-001",
            payload={"displayName": "New Rule", "isEnabled": True},
            status="production",
            name_map={},
        )
        assert result["result"] == "success"
        assert result["action"] == "created"

    def test_update_existing_rule(self) -> None:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_client = MagicMock()
        mock_client.update_rule.return_value = mock_response

        result = deploy_defender_rule(
            client=mock_client,
            rule_id="defender-test-001",
            payload={"displayName": "Existing Rule", "isEnabled": True},
            status="production",
            name_map={"Existing Rule": "42"},
        )
        assert result["result"] == "success"
        assert result["action"] == "updated"
        mock_client.update_rule.assert_called_once_with("42", {"displayName": "Existing Rule", "isEnabled": True})

    def test_deprecated_disables(self) -> None:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_client = MagicMock()
        mock_client.update_rule.return_value = mock_response

        result = deploy_defender_rule(
            client=mock_client,
            rule_id="defender-test-001",
            payload={"displayName": "Old Rule", "isEnabled": True},
            status="deprecated",
            name_map={"Old Rule": "42"},
        )
        # Verify isEnabled was set to False
        call_args = mock_client.update_rule.call_args
        body = call_args[0][1]
        assert body["isEnabled"] is False
        assert result["action"] == "disabled"
