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


def test_guard_stops_when_tenant_yml_cannot_be_read(monkeypatch) -> None:
    """Any error reading tenant.yml read as "nothing to guard", so a malformed
    file let live CRUD tests run against a production workspace unconfirmed.
    Only a missing file means there is nothing to compare against."""
    import pytest

    module = _load_conftest_module()

    def broken():
        raise ValueError("tenant.yml: sentinelWorkspaces.0.role: invalid")

    monkeypatch.setattr("contentops.config.load_tenant_config", broken)
    monkeypatch.delenv("I_UNDERSTAND_THIS_IS_PRODUCTION", raising=False)
    with pytest.raises(pytest.exit.Exception, match="could not read"):
        module._confirm_not_production("law-prod")


def test_guard_is_quiet_without_a_tenant_yml(monkeypatch) -> None:
    module = _load_conftest_module()

    def missing():
        raise FileNotFoundError("config/tenant.yml")

    monkeypatch.setattr("contentops.config.load_tenant_config", missing)
    module._confirm_not_production("law-prod")  # no exit


class _ArmFake:
    """Lists alert rules and saved searches; records deletes."""

    def __init__(self, rules, searches) -> None:
        self.rules, self.searches, self.deleted = rules, searches, []

    def list_resource(self, kind):
        assert kind == "alertRules"
        return [{"name": n} for n in self.rules]

    def la_resource_url(self, kind, name=None, **_kw):
        assert kind == "savedSearches"
        return f"ss/{name}" if name else "ss"

    def request(self, method, url, **_kw):
        class _R:
            status_code = 200

            def __init__(self, body):
                self._body = body

            def json(self):
                return self._body

            def raise_for_status(self):
                return None

        if method == "GET" and url == "ss":
            return _R({"value": [{"name": n} for n in self.searches]})
        if method == "DELETE":
            self.deleted.append(url)
        return _R({})

    def delete_resource(self, kind, name):
        self.deleted.append(f"{kind}/{name}")


def test_the_sweep_deletes_test_saved_searches_too() -> None:
    """Parser and hunting tests create saved searches; a test that failed
    between create and delete left them, and the sweep only knew alert
    rules."""
    module = _load_conftest_module()
    fake = _ArmFake(["zz-itest-1", "keep-rule"], ["zz-itest-2", "keep-search"])
    module._sweep_sentinel(fake)
    assert sorted(fake.deleted) == ["alertRules/zz-itest-1", "ss/zz-itest-2"]


def test_the_parser_live_tests_register_what_they_create() -> None:
    import ast

    here = Path(__file__).resolve().parent.parent / "integration"
    for module, test in (("test_sentinel_extras_crud.py", "test_parser_full_crud"),
                         ("test_prune_live.py", "test_prune_sentinel_parser_create_then_delete")):
        tree = ast.parse((here / module).read_text(encoding="utf-8"))
        fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == test)
        assert "created_saved_searches" in {a.arg for a in fn.args.args}, f"{module}::{test}"
        calls = [n for n in ast.walk(fn) if isinstance(n, ast.Call)
                 and getattr(n.func, "attr", "") == "append"
                 and getattr(n.func.value, "id", "") == "created_saved_searches"]
        assert calls, f"{module}::{test} never registers the saved search it creates"
