# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for ``contentops.workspace_kql.resolve_workspace_id`` (PR-J).

The function auto-derives the LA workspace customerId GUID from
``config/tenant.yml`` + an ARM lookup, replacing the need for a
separate ``PIPELINE_WORKSPACE_ID`` Actions variable.
"""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from contentops.workspace_kql import WorkspaceKqlError, resolve_workspace_id


def _arm_response(customer_id: str | None) -> dict:
    return {
        "id": "/subscriptions/sub-x/resourceGroups/rg-x/providers/"
              "Microsoft.OperationalInsights/workspaces/ws-x",
        "name": "ws-x",
        "properties": (
            {"customerId": customer_id} if customer_id else {}
        ),
    }


def _seed_tenant_config(tmp_path: Path, *workspaces: dict) -> Path:
    """Write a minimal config/tenant.yml under tmp_path. Returns the path."""
    cfg = tmp_path / "config"
    cfg.mkdir(parents=True, exist_ok=True)
    target = cfg / "tenant.yml"
    ws_yaml = "\n".join(
        f"    - role: {w.get('role', 'prod')}\n"
        f"      subscriptionId: {w.get('subscriptionId', 'sub-1')}\n"
        f"      resourceGroup: {w.get('resourceGroup', 'rg-1')}\n"
        f"      workspaceName: {w.get('workspaceName', 'ws-1')}\n"
        f"      location: westeurope"
        for w in workspaces
    )
    target.write_text(
        "tenant:\n"
        "  name: production\n"
        "  tenantId: 00000000-0000-0000-0000-000000000001\n"
        "  defender:\n"
        "    enabled: false\n"
        "  sentinelWorkspaces:\n"
        f"{ws_yaml}\n",
        encoding="utf-8",
    )
    return target


class _FakeCred:
    """Stand-in for DefaultAzureCredential."""

    def get_token(self, *_scopes):
        class _T:
            token = "stub-arm-token"
        return _T()


def _mock_transport(response_fn):
    """Build an httpx.MockTransport that delegates to response_fn(request)."""
    def _handler(request: httpx.Request) -> httpx.Response:
        return response_fn(str(request.url))
    return httpx.MockTransport(_handler)


@pytest.fixture
def chdir_tmp(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    return tmp_path


def test_resolve_workspace_id_picks_role_match(chdir_tmp, monkeypatch) -> None:
    """When multiple workspaces exist, the role match wins."""
    _seed_tenant_config(
        chdir_tmp,
        {"role": "dev", "workspaceName": "ws-dev"},
        {"role": "prod", "workspaceName": "ws-prod"},
    )

    def _resp(url):
        # Verify the ARM path targets the prod workspace.
        assert "workspaces/ws-prod" in url
        return httpx.Response(200, json=_arm_response("guid-prod"))

    transport = _mock_transport(_resp)
    gid = resolve_workspace_id(role="prod", credential=_FakeCred(), transport=transport, tenant_config_path=chdir_tmp / "config" / "tenant.yml")
    assert gid == "guid-prod"


def test_resolve_workspace_id_falls_back_to_first_when_role_unmatched(
    chdir_tmp, monkeypatch,
) -> None:
    _seed_tenant_config(
        chdir_tmp,
        {"role": "prod", "workspaceName": "ws-prod"},
    )

    def _resp(_url):
        return httpx.Response(200, json=_arm_response("guid-fallback"))

    transport = _mock_transport(_resp)
    # role="integration" doesn't match but falls back to the first workspace.
    gid = resolve_workspace_id(role="integration", credential=_FakeCred(), transport=transport, tenant_config_path=chdir_tmp / "config" / "tenant.yml")
    assert gid == "guid-fallback"


def test_resolve_workspace_id_honours_workspace_name_override(
    chdir_tmp, monkeypatch,
) -> None:
    _seed_tenant_config(
        chdir_tmp,
        {"role": "prod", "workspaceName": "ws-prod"},
        {"role": "dev", "workspaceName": "ws-dev"},
    )

    def _resp(url):
        assert "workspaces/ws-dev" in url
        return httpx.Response(200, json=_arm_response("guid-dev"))

    transport = _mock_transport(_resp)
    gid = resolve_workspace_id(
        role="prod", workspace_name="ws-dev", credential=_FakeCred(), transport=transport, tenant_config_path=chdir_tmp / "config" / "tenant.yml",
    )
    assert gid == "guid-dev"


def test_resolve_workspace_id_no_workspaces_in_tenant_raises(
    chdir_tmp,
) -> None:
    (chdir_tmp / "config").mkdir(parents=True, exist_ok=True)
    (chdir_tmp / "config" / "tenant.yml").write_text(
        "tenant:\n"
        "  name: production\n"
        "  tenantId: 00000000-0000-0000-0000-000000000001\n"
        "  defender:\n    enabled: false\n"
        "  sentinelWorkspaces: []\n",
        encoding="utf-8",
    )
    with pytest.raises(WorkspaceKqlError) as exc_info:
        resolve_workspace_id(credential=_FakeCred(), tenant_config_path=chdir_tmp / "config" / "tenant.yml")
    assert "no Sentinel workspaces" in str(exc_info.value)


def test_resolve_workspace_id_unknown_name_raises(chdir_tmp) -> None:
    _seed_tenant_config(
        chdir_tmp,
        {"role": "prod", "workspaceName": "ws-prod"},
    )
    with pytest.raises(WorkspaceKqlError) as exc_info:
        resolve_workspace_id(
            workspace_name="ws-ghost", credential=_FakeCred(), tenant_config_path=chdir_tmp / "config" / "tenant.yml",
        )
    assert "not in tenant.yml" in str(exc_info.value)
    assert "ws-prod" in str(exc_info.value)  # lists available


def test_resolve_workspace_id_arm_4xx_raises(chdir_tmp, monkeypatch) -> None:
    _seed_tenant_config(
        chdir_tmp,
        {"role": "prod", "workspaceName": "ws-prod"},
    )

    def _resp(_url):
        return httpx.Response(404, text="not found")

    transport = _mock_transport(_resp)
    with pytest.raises(WorkspaceKqlError) as exc_info:
        resolve_workspace_id(credential=_FakeCred(), transport=transport, tenant_config_path=chdir_tmp / "config" / "tenant.yml")
    assert "404" in str(exc_info.value)


def test_resolve_workspace_id_missing_customer_id_raises(
    chdir_tmp, monkeypatch,
) -> None:
    _seed_tenant_config(
        chdir_tmp,
        {"role": "prod", "workspaceName": "ws-prod"},
    )

    def _resp(_url):
        return httpx.Response(200, json=_arm_response(None))

    transport = _mock_transport(_resp)
    with pytest.raises(WorkspaceKqlError) as exc_info:
        resolve_workspace_id(credential=_FakeCred(), transport=transport, tenant_config_path=chdir_tmp / "config" / "tenant.yml")
    assert "customerId" in str(exc_info.value)
