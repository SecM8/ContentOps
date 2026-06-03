# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the integration test harness's production-safety guard.

The integration conftest at ``tests/integration/conftest.py`` refuses
to run live CRUD tests against a workspace whose name matches any
prod-role workspace in the tenant config, unless explicitly confirmed
via the ``I_UNDERSTAND_THIS_IS_PRODUCTION`` env var. That decision
logic is extracted into ``_is_production_workspace`` so it can be
exercised here without live Azure.

These tests prevent a regression where a future tenant-config schema
change silently disarms the guard (which is what happened pre-fix:
``cfg.sentinel.workspaceName`` was a stale single-workspace path
that started raising ``AttributeError`` after the multi-workspace
migration, masking the production-match check).
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

from contentops.config import SentinelWorkspaceConfig, TenantConfig, DefenderConfig


def _load_conftest_module():
    """Load ``tests/integration/conftest.py`` as a plain module.

    pytest's conftest discovery makes it inconvenient to import the
    integration conftest by package path, so we load it explicitly
    via importlib. The module's only side effect on import is
    ``load_env_file()``, which is idempotent.
    """
    here = Path(__file__).resolve().parent.parent
    conftest_path = here / "integration" / "conftest.py"
    spec = importlib.util.spec_from_file_location(
        "tests_integration_conftest_for_unit_test", conftest_path,
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _cfg_with(*workspaces: SentinelWorkspaceConfig) -> TenantConfig:
    return TenantConfig(
        name="test-tenant",
        tenantId="00000000-0000-0000-0000-000000000000",
        defender=DefenderConfig(enabled=False),
        sentinelWorkspaces=list(workspaces),
    )


def _ws(name: str, role: str = "prod") -> SentinelWorkspaceConfig:
    return SentinelWorkspaceConfig(
        role=role,
        subscriptionId="11111111-1111-1111-1111-111111111111",
        resourceGroup="rg-test",
        workspaceName=name,
        location="westeurope",
    )


def test_guard_flags_exact_prod_workspace_name() -> None:
    """``law-sentinel`` configured as prod → guard fires for
    ``law-sentinel``."""
    conftest = _load_conftest_module()
    cfg = _cfg_with(_ws("law-sentinel", role="prod"))
    matches, matched = conftest._is_production_workspace(cfg, "law-sentinel")
    assert matches is True
    assert matched == "law-sentinel"


def test_guard_is_case_insensitive() -> None:
    """Operators routinely type workspace names with inconsistent
    casing in env files; the guard must catch ``LAW-SENTINEL`` if
    prod is ``law-sentinel``."""
    conftest = _load_conftest_module()
    cfg = _cfg_with(_ws("law-sentinel", role="prod"))
    matches, matched = conftest._is_production_workspace(cfg, "LAW-SENTINEL")
    assert matches is True
    assert matched == "law-sentinel"


def test_guard_does_not_fire_for_integration_workspace() -> None:
    """The whole point: ``sit-workspace`` (role=integration) must not
    trigger the prod guard even though it's in the same tenant."""
    conftest = _load_conftest_module()
    cfg = _cfg_with(
        _ws("law-sentinel", role="prod"),
        _ws("sit-workspace", role="integration"),
    )
    matches, matched = conftest._is_production_workspace(cfg, "sit-workspace")
    assert matches is False
    assert matched is None


def test_guard_with_no_prod_workspaces_is_quiet() -> None:
    """Conservative behaviour from the docstring: tenants with zero
    prod workspaces never trigger the guard, regardless of the
    candidate name."""
    conftest = _load_conftest_module()
    cfg = _cfg_with(_ws("sit-workspace", role="integration"))
    matches, matched = conftest._is_production_workspace(cfg, "sit-workspace")
    assert matches is False
    assert matched is None


def test_guard_handles_multiple_prod_workspaces() -> None:
    """A tenant can legitimately have multiple prod-role workspaces
    (e.g. regional splits). The guard must match against any of
    them, not just the first."""
    conftest = _load_conftest_module()
    cfg = _cfg_with(
        _ws("prod-eu", role="prod"),
        _ws("prod-us", role="prod"),
        _ws("sit-workspace", role="integration"),
    )
    matches, _ = conftest._is_production_workspace(cfg, "prod-us")
    assert matches is True
