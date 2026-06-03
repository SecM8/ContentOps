# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for ``contentops.cli.commands.apply_support``.

The helpers in apply_support.py were extracted from apply.py (PR #273)
and had no direct unit tests — only indirect coverage through CLI
integration tests. This file pins each helper's contract.

``_print_against_tenant_summary`` is omitted: it is a print-formatting
wrapper around ``detect_drift`` and is already covered by the
integration tests in ``test_plan_against_tenant.py``.
"""

from __future__ import annotations

from pathlib import Path

import click.exceptions
import pytest

from contentops.config import (
    DefenderConfig,
    SentinelWorkspaceConfig,
    TenantConfig,
)
from contentops.core.asset import Asset
from contentops.core.envelope import EnvelopeV2
from contentops.core.handler import LoadedAsset
from contentops.core.result import ActionResult, PlanAction


# ---------------------------------------------------------------------------
# Factories
# ---------------------------------------------------------------------------


def _make_loaded(
    *,
    asset: Asset = Asset.SENTINEL_ANALYTIC,
    payload: dict | None = None,
    envelope_id: str = "test-rule",
    status: str = "production",
    metadata: object | None = None,
) -> LoadedAsset:
    envelope = EnvelopeV2(
        id=envelope_id,
        version="0.1.0",
        asset=asset,
        status=status,
        metadata=metadata,
    )
    return LoadedAsset(path=Path("synthetic"), envelope=envelope, payload=payload or {})


def _meta(**overrides):
    from contentops.core.metadata import RuleMetadata
    base = {
        "owner": "blue@contoso.com",
        "runbookUrl": "https://wiki/runbook",
        "severity": "high",
        "tactics": ["InitialAccess"],
        "techniques": ["T1059"],
        "expectedAlertsPerDay": 1,
        "fpHandling": "n/a",
    }
    base.update(overrides)
    return RuleMetadata(**base)


def _tenant_cfg(
    *,
    sentinel_write_allowed: bool = True,
    role: str = "prod",
    defender_block: bool = False,
    defender_write_allowed: bool = True,
):
    return TenantConfig(
        name="test-tenant",
        tenantId="aad-test-guid",
        defender=(
            DefenderConfig(writeAllowed=defender_write_allowed)
            if defender_block
            else None
        ),
        sentinelWorkspaces=[
            SentinelWorkspaceConfig(
                role=role,
                subscriptionId="sub-1",
                resourceGroup="rg-1",
                workspaceName="ws-prod",
                writeAllowed=sentinel_write_allowed,
            ),
        ],
    )


def _action_result(
    *,
    action: PlanAction = PlanAction.CREATE,
    status: str = "ok",
    error: str | None = None,
    detail: str = "",
    verified: bool | None = None,
) -> ActionResult:
    return ActionResult(
        asset_id="test-rule",
        asset_kind="sentinel_analytic",
        action=action,
        status=status,
        error=error,
        detail=detail,
        verified=verified,
    )


# ---------------------------------------------------------------------------
# _resolve_workspaces_for_run
# ---------------------------------------------------------------------------

_MOD = "contentops.cli.commands.apply_support"


class TestResolveWorkspacesForRun:

    def test_missing_tenant_yml_returns_none(self, monkeypatch):
        from contentops.cli.commands.apply_support import _resolve_workspaces_for_run

        monkeypatch.setattr(
            f"{_MOD}._config.load_tenant_config",
            lambda *a, **kw: (_ for _ in ()).throw(FileNotFoundError("no file")),
        )
        cfg, ws = _resolve_workspaces_for_run(None, None)
        assert cfg is None
        assert ws == []

    def test_value_error_exits_2(self, monkeypatch):
        from contentops.cli.commands.apply_support import _resolve_workspaces_for_run

        monkeypatch.setattr(
            f"{_MOD}._config.load_tenant_config",
            lambda *a, **kw: (_ for _ in ()).throw(ValueError("bad")),
        )
        with pytest.raises(click.exceptions.Exit) as exc_info:
            _resolve_workspaces_for_run(None, None)
        assert exc_info.value.exit_code == 2

    def test_key_error_exits_2(self, monkeypatch):
        from contentops.cli.commands.apply_support import _resolve_workspaces_for_run

        monkeypatch.setattr(
            f"{_MOD}._config.load_tenant_config",
            lambda *a, **kw: (_ for _ in ()).throw(KeyError("missing")),
        )
        with pytest.raises(click.exceptions.Exit) as exc_info:
            _resolve_workspaces_for_run(None, None)
        assert exc_info.value.exit_code == 2

    def test_normal_returns_cfg_and_workspaces(self, monkeypatch):
        from contentops.cli.commands.apply_support import _resolve_workspaces_for_run

        expected_cfg = _tenant_cfg()
        expected_ws = list(expected_cfg.sentinelWorkspaces)
        monkeypatch.setattr(f"{_MOD}._config.load_tenant_config", lambda *a, **kw: expected_cfg)
        monkeypatch.setattr(f"{_MOD}._config.select_workspaces", lambda *a, **kw: expected_ws)
        cfg, ws = _resolve_workspaces_for_run("prod", None)
        assert cfg is expected_cfg
        assert ws is expected_ws


# ---------------------------------------------------------------------------
# _check_apply_write_allowed_or_exit
# ---------------------------------------------------------------------------


class TestCheckApplyWriteAllowedOrExit:

    def test_locked_workspace_exits_2(self):
        from contentops.cli.commands.apply_support import _check_apply_write_allowed_or_exit

        cfg = _tenant_cfg(sentinel_write_allowed=False)
        with pytest.raises(SystemExit) as exc_info:
            _check_apply_write_allowed_or_exit(
                cfg, list(cfg.sentinelWorkspaces), None, dry_run=False,
            )
        assert exc_info.value.code == 2

    def test_dry_run_bypasses_gate(self):
        from contentops.cli.commands.apply_support import _check_apply_write_allowed_or_exit

        cfg = _tenant_cfg(sentinel_write_allowed=False)
        _check_apply_write_allowed_or_exit(
            cfg, list(cfg.sentinelWorkspaces), None, dry_run=True,
        )

    def test_writable_workspace_passes(self):
        from contentops.cli.commands.apply_support import _check_apply_write_allowed_or_exit

        cfg = _tenant_cfg(sentinel_write_allowed=True)
        _check_apply_write_allowed_or_exit(
            cfg, list(cfg.sentinelWorkspaces), None, dry_run=False,
        )

    def test_defender_blocked_exits_2(self):
        from contentops.cli.commands.apply_support import _check_apply_write_allowed_or_exit

        cfg = _tenant_cfg(defender_block=True, defender_write_allowed=False)
        with pytest.raises(SystemExit) as exc_info:
            _check_apply_write_allowed_or_exit(
                cfg, list(cfg.sentinelWorkspaces), None, dry_run=False,
            )
        assert exc_info.value.code == 2

    def test_sentinel_only_asset_skips_defender_check(self):
        from contentops.cli.commands.apply_support import _check_apply_write_allowed_or_exit

        cfg = _tenant_cfg(defender_block=True, defender_write_allowed=False)
        _check_apply_write_allowed_or_exit(
            cfg, list(cfg.sentinelWorkspaces), "sentinel_analytic", dry_run=False,
        )

    def test_none_cfg_is_noop(self):
        from contentops.cli.commands.apply_support import _check_apply_write_allowed_or_exit

        _check_apply_write_allowed_or_exit(None, [], None, dry_run=False)


# ---------------------------------------------------------------------------
# _apply_integration_no_workspace_skip
# ---------------------------------------------------------------------------


class TestApplyIntegrationNoWorkspaceSkip:

    def test_integration_returns_true(self):
        from contentops.cli.commands.apply_support import _apply_integration_no_workspace_skip

        assert _apply_integration_no_workspace_skip("integration") is True

    def test_prod_returns_false(self):
        from contentops.cli.commands.apply_support import _apply_integration_no_workspace_skip

        assert _apply_integration_no_workspace_skip("prod") is False

    def test_none_returns_false(self):
        from contentops.cli.commands.apply_support import _apply_integration_no_workspace_skip

        assert _apply_integration_no_workspace_skip(None) is False


# ---------------------------------------------------------------------------
# _skip_if_integration_role_absent (shared helper for drift/collect/prune/
# rollback/plan — "no integration env must never fail the pipeline")
# ---------------------------------------------------------------------------


class TestSkipIfIntegrationRoleAbsent:

    @staticmethod
    def _cfg(*, with_integration: bool):
        from contentops.config import SentinelWorkspaceConfig, TenantConfig

        ws = [SentinelWorkspaceConfig(
            role="prod", subscriptionId="s", resourceGroup="rg",
            workspaceName="prod-ws",
        )]
        if with_integration:
            ws.append(SentinelWorkspaceConfig(
                role="integration", subscriptionId="s", resourceGroup="rg",
                workspaceName="int-ws",
            ))
        return TenantConfig(name="t", tenantId="aad-guid", sentinelWorkspaces=ws)

    def test_non_integration_role_is_false(self):
        from contentops.cli.commands._shared import _skip_if_integration_role_absent

        assert _skip_if_integration_role_absent("prod") is False
        assert _skip_if_integration_role_absent(None) is False

    def test_explicit_workspace_defers_to_resolver(self):
        from contentops.cli.commands._shared import _skip_if_integration_role_absent

        # An explicit --workspace is the operator being specific; let the
        # normal resolver handle (and error on) it.
        assert _skip_if_integration_role_absent("integration", "some-ws") is False

    def test_integration_present_proceeds(self, monkeypatch):
        from contentops.cli.commands._shared import _skip_if_integration_role_absent

        monkeypatch.setattr(
            "contentops.config.load_tenant_config",
            lambda *a, **k: self._cfg(with_integration=True),
        )
        assert _skip_if_integration_role_absent("integration") is False

    def test_integration_absent_skips(self, monkeypatch, capsys):
        from contentops.cli.commands._shared import _skip_if_integration_role_absent

        monkeypatch.setattr(
            "contentops.config.load_tenant_config",
            lambda *a, **k: self._cfg(with_integration=False),
        )
        assert _skip_if_integration_role_absent("integration", command="drift") is True
        out = capsys.readouterr().out
        assert "role=integration" in out and "skipping" in out

    def test_unreadable_config_defers(self, monkeypatch):
        from contentops.cli.commands._shared import _skip_if_integration_role_absent

        def _raise(*a, **k):
            raise FileNotFoundError("no config")

        monkeypatch.setattr("contentops.config.load_tenant_config", _raise)
        # Falls through so the normal resolver reports the missing config.
        assert _skip_if_integration_role_absent("integration") is False


# ---------------------------------------------------------------------------
# _load_assets_for_run
# ---------------------------------------------------------------------------


class TestLoadAssetsForRun:

    def test_asset_filter(self, tmp_path, monkeypatch):
        from contentops.cli.commands.apply_support import _load_assets_for_run

        la_analytic = _make_loaded(asset=Asset.SENTINEL_ANALYTIC, envelope_id="rule-a")
        la_hunting = _make_loaded(asset=Asset.SENTINEL_HUNTING, envelope_id="rule-b")
        monkeypatch.setattr(f"{_MOD}._load_all", lambda _p: [la_analytic, la_hunting])
        monkeypatch.setattr(f"{_MOD}._filter_disabled_engines", lambda x: x)

        result = _load_assets_for_run(tmp_path, asset="sentinel_analytic", changed_since=None)
        assert len(result) == 1
        assert result[0].envelope.id == "rule-a"

    def test_no_filters_returns_all(self, tmp_path, monkeypatch):
        from contentops.cli.commands.apply_support import _load_assets_for_run

        la1 = _make_loaded(envelope_id="rule-a")
        la2 = _make_loaded(envelope_id="rule-b")
        monkeypatch.setattr(f"{_MOD}._load_all", lambda _p: [la1, la2])
        monkeypatch.setattr(f"{_MOD}._filter_disabled_engines", lambda x: x)

        result = _load_assets_for_run(tmp_path, asset=None, changed_since=None)
        assert len(result) == 2

    def test_changed_since_delegates(self, tmp_path, monkeypatch):
        from contentops.cli.commands.apply_support import _load_assets_for_run

        la1 = _make_loaded(envelope_id="rule-a")
        la2 = _make_loaded(envelope_id="rule-b")
        monkeypatch.setattr(f"{_MOD}._load_all", lambda _p: [la1, la2])
        monkeypatch.setattr(f"{_MOD}._filter_changed_since", lambda loaded, _since: [loaded[0]])
        monkeypatch.setattr(f"{_MOD}._filter_disabled_engines", lambda x: x)

        result = _load_assets_for_run(tmp_path, asset=None, changed_since="abc123")
        assert len(result) == 1


# ---------------------------------------------------------------------------
# _filter_loaded_by_env_status
# ---------------------------------------------------------------------------


class TestFilterLoadedByEnvStatus:

    def test_prod_keeps_production_only(self):
        from contentops.cli.commands.apply_support import _filter_loaded_by_env_status

        cfg = _tenant_cfg(role="prod")
        ws = list(cfg.sentinelWorkspaces)
        la_prod = _make_loaded(envelope_id="prod-rule", status="production")
        la_test = _make_loaded(envelope_id="test-rule", status="test")

        result = _filter_loaded_by_env_status([la_prod, la_test], cfg, ws)
        assert len(result) == 1
        assert result[0].envelope.id == "prod-rule"

    def test_integration_keeps_test_and_production(self):
        from contentops.cli.commands.apply_support import _filter_loaded_by_env_status

        cfg = _tenant_cfg(role="integration")
        ws = list(cfg.sentinelWorkspaces)
        la_prod = _make_loaded(envelope_id="prod-rule", status="production")
        la_test = _make_loaded(envelope_id="test-rule", status="test")

        result = _filter_loaded_by_env_status([la_prod, la_test], cfg, ws)
        assert len(result) == 2

    def test_defender_dropped_on_non_prod(self):
        from contentops.cli.commands.apply_support import _filter_loaded_by_env_status

        cfg = _tenant_cfg(role="integration")
        ws = list(cfg.sentinelWorkspaces)
        la_defender = _make_loaded(
            asset=Asset.DEFENDER_CUSTOM_DETECTION,
            envelope_id="defender-rule",
            status="production",
        )

        result = _filter_loaded_by_env_status([la_defender], cfg, ws)
        assert len(result) == 0

    def test_defender_kept_on_prod(self):
        from contentops.cli.commands.apply_support import _filter_loaded_by_env_status

        cfg = _tenant_cfg(role="prod")
        ws = list(cfg.sentinelWorkspaces)
        la_defender = _make_loaded(
            asset=Asset.DEFENDER_CUSTOM_DETECTION,
            envelope_id="defender-rule",
            status="production",
        )

        result = _filter_loaded_by_env_status([la_defender], cfg, ws)
        assert len(result) == 1

    def test_file_not_found_returns_unchanged(self, monkeypatch):
        from contentops.cli.commands.apply_support import _filter_loaded_by_env_status

        monkeypatch.setattr(
            f"{_MOD}._config.load_tenant_config",
            lambda *a, **kw: (_ for _ in ()).throw(FileNotFoundError()),
        )
        loaded = [_make_loaded()]
        result = _filter_loaded_by_env_status(loaded, None, [])
        assert result is loaded


# ---------------------------------------------------------------------------
# _apply_no_loaded_assets_or_return
# ---------------------------------------------------------------------------


class TestApplyNoLoadedAssetsOrReturn:

    def test_empty_returns_true(self):
        from contentops.cli.commands.apply_support import _apply_no_loaded_assets_or_return

        assert _apply_no_loaded_assets_or_return([]) is True

    def test_non_empty_returns_false(self):
        from contentops.cli.commands.apply_support import _apply_no_loaded_assets_or_return

        assert _apply_no_loaded_assets_or_return([_make_loaded()]) is False


# ---------------------------------------------------------------------------
# _apply_dependency_violations_or_exit
# ---------------------------------------------------------------------------


class TestApplyDependencyViolationsOrExit:

    def test_violations_exit_1(self, monkeypatch):
        from contentops.cli.commands.apply_support import _apply_dependency_violations_or_exit

        monkeypatch.setattr(f"{_MOD}._emit_dependency_report", lambda _: True)
        with pytest.raises(SystemExit) as exc_info:
            _apply_dependency_violations_or_exit([_make_loaded()], skip_deps_check=False)
        assert exc_info.value.code == 1

    def test_no_violations_passes(self, monkeypatch):
        from contentops.cli.commands.apply_support import _apply_dependency_violations_or_exit

        monkeypatch.setattr(f"{_MOD}._emit_dependency_report", lambda _: False)
        _apply_dependency_violations_or_exit([_make_loaded()], skip_deps_check=False)

    def test_skip_deps_check_bypasses(self, monkeypatch):
        from contentops.cli.commands.apply_support import _apply_dependency_violations_or_exit

        called = []
        monkeypatch.setattr(f"{_MOD}._emit_dependency_report", lambda _: called.append(1) or True)
        _apply_dependency_violations_or_exit([_make_loaded()], skip_deps_check=True)
        assert called == []


# ---------------------------------------------------------------------------
# _filter_locked_loaded_assets
# ---------------------------------------------------------------------------


class TestFilterLockedLoadedAssets:

    def test_locked_skipped_without_force(self, monkeypatch):
        from contentops.cli.commands.apply_support import _filter_locked_loaded_assets

        monkeypatch.setattr(f"{_MOD}._is_locked", lambda _: True)
        result = _filter_locked_loaded_assets([_make_loaded()], force_overwrite=False)
        assert result == []

    def test_locked_kept_with_force(self, monkeypatch):
        from contentops.cli.commands.apply_support import _filter_locked_loaded_assets

        monkeypatch.setattr(f"{_MOD}._is_locked", lambda _: True)
        result = _filter_locked_loaded_assets([_make_loaded()], force_overwrite=True)
        assert len(result) == 1

    def test_unlocked_always_kept(self, monkeypatch):
        from contentops.cli.commands.apply_support import _filter_locked_loaded_assets

        monkeypatch.setattr(f"{_MOD}._is_locked", lambda _: False)
        result = _filter_locked_loaded_assets([_make_loaded()], force_overwrite=False)
        assert len(result) == 1


# ---------------------------------------------------------------------------
# _build_audit_record
# ---------------------------------------------------------------------------


class TestBuildAuditRecord:

    @pytest.fixture(autouse=True)
    def _pin_git(self, monkeypatch):
        monkeypatch.setattr(f"{_MOD}._resolve_sha", lambda _: "abc123")
        monkeypatch.setattr(f"{_MOD}._resolve_actor", lambda: "test-actor")

    def test_success_record(self):
        from contentops.cli.commands.apply_support import _build_audit_record

        rec = _build_audit_record(_action_result(), _make_loaded())
        assert rec.status == "success"
        assert rec.message is None
        assert rec.action == "create"

    def test_error_record(self):
        from contentops.cli.commands.apply_support import _build_audit_record

        rec = _build_audit_record(
            _action_result(status="error", error="boom"),
            _make_loaded(),
        )
        assert rec.status == "failed"
        assert rec.message == "boom"

    def test_skip_record(self):
        from contentops.cli.commands.apply_support import _build_audit_record

        rec = _build_audit_record(
            _action_result(action=PlanAction.SKIP, detail="no change"),
            _make_loaded(),
        )
        assert rec.status == "skipped"
        assert rec.message == "no change"

    def test_workspace_and_digest_populated(self):
        from contentops.cli.commands.apply_support import _build_audit_record

        rec = _build_audit_record(
            _action_result(), _make_loaded(),
            workspace="ws-prod", snippet_digest="deadbeef",
        )
        assert rec.workspace == "ws-prod"
        assert rec.snippet_digest == "deadbeef"

    def test_metadata_owner_populated(self):
        from contentops.cli.commands.apply_support import _build_audit_record

        rec = _build_audit_record(
            _action_result(),
            _make_loaded(metadata=_meta(owner="secops@corp.com")),
        )
        assert rec.metadata_owner == "secops@corp.com"

    def test_metadata_owner_none_when_no_metadata(self):
        from contentops.cli.commands.apply_support import _build_audit_record

        rec = _build_audit_record(_action_result(), _make_loaded(metadata=None))
        assert rec.metadata_owner is None

    def test_verified_false_is_failed(self):
        from contentops.cli.commands.apply_support import _build_audit_record

        rec = _build_audit_record(
            _action_result(verified=False, detail="hash mismatch"),
            _make_loaded(),
        )
        assert rec.status == "failed"

    def test_prune_path_with_envelope_id(self):
        from contentops.cli.commands.apply_support import _build_audit_record

        rec = _build_audit_record(
            _action_result(action=PlanAction.DELETE, status="deleted"),
            envelope_id="orphan-rule",
            asset_value="sentinel_analytic",
            success_detail="pruned",
        )
        assert rec.status == "success"
        assert rec.message == "pruned"
        assert rec.id == "orphan-rule"
        assert rec.asset == "sentinel_analytic"
        assert rec.metadata_owner is None

    def test_prune_path_failure(self):
        from contentops.cli.commands.apply_support import _build_audit_record

        rec = _build_audit_record(
            _action_result(status="error", error="API 403"),
            envelope_id="orphan-rule",
            asset_value="sentinel_analytic",
            success_detail="pruned",
        )
        assert rec.status == "failed"
        assert rec.message == "API 403"


# ---------------------------------------------------------------------------
# _compute_snippet_digest
# ---------------------------------------------------------------------------


class TestComputeSnippetDigest:

    def test_identity_returns_none(self):
        from contentops.cli.commands.apply_support import _compute_snippet_digest

        la = _make_loaded(payload={"query": "SecurityEvent"})
        assert _compute_snippet_digest(la, la) is None

    def test_no_divergence_returns_none(self):
        from contentops.cli.commands.apply_support import _compute_snippet_digest

        original = _make_loaded(payload={"query": "SecurityEvent"})
        resolved = _make_loaded(payload={"query": "SecurityEvent"})
        assert _compute_snippet_digest(original, resolved) is None

    def test_diverged_returns_hex_sha256(self):
        from contentops.cli.commands.apply_support import _compute_snippet_digest

        original = _make_loaded(payload={"query": "SecurityEvent"})
        resolved = _make_loaded(payload={"query": "SecurityEvent | where Level == 8"})
        digest = _compute_snippet_digest(original, resolved)
        assert digest is not None
        assert len(digest) == 64
        assert all(c in "0123456789abcdef" for c in digest)

    def test_asset_without_kql_fields_returns_none(self):
        from contentops.cli.commands.apply_support import _compute_snippet_digest

        original = _make_loaded(
            asset=Asset.SENTINEL_WATCHLIST,
            payload={"displayName": "test"},
        )
        resolved = _make_loaded(
            asset=Asset.SENTINEL_WATCHLIST,
            payload={"displayName": "changed"},
        )
        assert _compute_snippet_digest(original, resolved) is None

    def test_deterministic(self):
        from contentops.cli.commands.apply_support import _compute_snippet_digest

        original = _make_loaded(payload={"query": "SecurityEvent"})
        resolved = _make_loaded(payload={"query": "SigninLogs"})
        d1 = _compute_snippet_digest(original, resolved)
        d2 = _compute_snippet_digest(original, resolved)
        assert d1 == d2
