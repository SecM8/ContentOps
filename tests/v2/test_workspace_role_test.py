# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for the `test` WorkspaceRole (G21 closeout).

Verifies that `role: test` is a valid tenant-config value and that
`workspaces_for_role("test")` resolves the right entries.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from contentops.config import SentinelWorkspaceConfig, TenantConfig


def _ws(**overrides) -> SentinelWorkspaceConfig:
    base = dict(
        subscriptionId="00000000-0000-0000-0000-000000000001",
        resourceGroup="rg-test",
        workspaceName="ws-test",
        location="westeurope",
    )
    base.update(overrides)
    return SentinelWorkspaceConfig(**base)


def test_test_role_is_a_valid_workspace_role() -> None:
    """The four canonical roles are prod, integration, dev, test."""
    for role in ("prod", "integration", "dev", "test"):
        ws = _ws(role=role, workspaceName=f"ws-{role}")
        assert ws.role == role


def test_unknown_role_still_rejected() -> None:
    with pytest.raises(ValidationError):
        _ws(role="staging-unknown")


def test_workspaces_for_role_picks_only_test_entries() -> None:
    cfg = TenantConfig(
        name="t",
        tenantId="00000000-0000-0000-0000-000000000000",
        sentinelWorkspaces=[
            _ws(role="prod", workspaceName="ws-prod"),
            _ws(role="integration", workspaceName="ws-integ"),
            _ws(role="test", workspaceName="ws-test"),
        ],
    )
    matches = cfg.workspaces_for_role("test")
    assert len(matches) == 1
    assert matches[0].workspaceName == "ws-test"


def test_workspaces_for_role_allows_multiple_test_workspaces() -> None:
    """An operator can stand up several test workspaces (e.g. one per
    detection engineer) and `--role test` returns all of them."""
    cfg = TenantConfig(
        name="t",
        tenantId="00000000-0000-0000-0000-000000000000",
        sentinelWorkspaces=[
            _ws(role="test", workspaceName="ws-test-a"),
            _ws(role="test", workspaceName="ws-test-b"),
        ],
    )
    matches = cfg.workspaces_for_role("test")
    assert {w.workspaceName for w in matches} == {"ws-test-a", "ws-test-b"}
