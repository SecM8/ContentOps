# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Regression tests for multi-workspace targeting in apply / drift / prune.

These pin Phase 1 behaviour:

  * ``apply --role <role>`` iterates every workspace matched by
    ``--role`` instead of erroring out when N>1.
  * ``apply`` rebinds ``PIPELINE_WORKSPACE_NAME`` per iteration and
    drops cached handler instances between iterations so factories
    re-fire against the new env.
  * Tenant-scoped assets (Defender) are applied **once** even when
    the Sentinel iteration runs N times.
  * ``apply --workspace <name>`` targets exactly one workspace.
  * ``drift`` / ``prune`` accept ``--role`` / ``--workspace`` flags
    additively — neither flag means "fall through to env-var or
    implicit single-workspace pick" (backward-compat with existing
    tests and the env-var workflow).
  * ``drift`` / ``prune`` with ``--role`` matching multiple
    workspaces fail closed with exit 2 (these commands target one
    workspace per invocation; only ``apply`` iterates).
  * Tenant config errors when only flags require it (no tenant.yml
    on disk + a flag passed) also exit 2 rather than crash.

The tests avoid the ambient ``config/tenant.yml`` on disk by
monkey-patching ``contentops.config.load_tenant_config`` /
``contentops.config.select_workspaces`` and by writing test
detections under a tmp_path. No live Azure access.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner

from contentops.cli import cli
from contentops.config import (
    SentinelWorkspaceConfig,
    TenantConfig,
)
from contentops.core.asset import Asset
from contentops.core.registry import default_registry
from contentops.core.result import ActionResult, PlanAction


# ---------------------------------------------------------------------------
# Test fixtures
# ---------------------------------------------------------------------------


def _make_tenant(*workspaces: tuple[str, str], defender: bool = True) -> TenantConfig:
    """Build a TenantConfig with the given (role, workspaceName) workspaces.

    Each gets a deterministic subscription/RG triplet keyed on the
    workspaceName so the Pydantic uniqueness validators are happy.
    """
    ws_list = []
    for role, name in workspaces:
        ws_list.append(SentinelWorkspaceConfig(
            role=role,
            subscriptionId=f"sub-{name}",
            resourceGroup=f"rg-{name}",
            workspaceName=name,
            location="westeurope",
        ))
    from contentops.config import DefenderConfig
    return TenantConfig(
        name="production-tenant",
        tenantId="00000000-0000-0000-0000-000000000000",
        defender=DefenderConfig(enabled=True) if defender else None,
        sentinelWorkspaces=ws_list,
    )


def _patch_tenant(monkeypatch, cfg: TenantConfig) -> None:
    """Make every code path that loads tenant.yml see ``cfg`` instead."""
    monkeypatch.setattr(
        "contentops.config.load_tenant_config",
        lambda *a, **kw: cfg,
    )


@pytest.fixture(autouse=True)
def _scrub_workspace_env(monkeypatch):
    """Each test starts without an inherited PIPELINE_WORKSPACE_NAME.

    The top-level conftest already resets the handler registry between
    tests; here we additionally make sure the env var doesn't leak from
    a prior test into the CLI invocation we're about to make.
    """
    monkeypatch.delenv("PIPELINE_WORKSPACE_NAME", raising=False)
    yield


def _write_sentinel_yaml(detections: Path, rule_id: str) -> Path:
    """Write a legacy-flagged Sentinel envelope.

    ``legacy: true`` bypasses the strict authoring metadata schema
    (owner/runbookUrl/tactics/...) — this is the same shape collected
    envelopes carry on disk, so it's the realistic input for the
    apply/drift/prune control-flow tests.
    """
    detections.mkdir(parents=True, exist_ok=True)
    asset_dir = detections / "sentinel_analytic"
    asset_dir.mkdir(parents=True, exist_ok=True)
    p = asset_dir / f"{rule_id}.yml"
    p.write_text(yaml.safe_dump({
        "id": rule_id,
        "version": "0.1.0",
        "asset": "sentinel_analytic",
        "status": "production",
        "legacy": True,
        "payload": {
            "kind": "Scheduled",
            "displayName": rule_id,
            "severity": "Medium",
            "query": "SecurityEvent | take 1",
            "queryFrequency": "PT5M",
            "queryPeriod": "PT5M",
            "triggerOperator": "GreaterThan",
            "triggerThreshold": 0,
            "tactics": [],
            "enabled": True,
        },
    }), encoding="utf-8")
    return p


def _write_defender_yaml(detections: Path, rule_id: str) -> Path:
    detections.mkdir(parents=True, exist_ok=True)
    asset_dir = detections / "defender_custom_detection"
    asset_dir.mkdir(parents=True, exist_ok=True)
    p = asset_dir / f"{rule_id}.yml"
    p.write_text(yaml.safe_dump({
        "id": rule_id,
        "version": "0.1.0",
        "asset": "defender_custom_detection",
        "status": "production",
        "legacy": True,
        "payload": {
            "displayName": rule_id,
            "isEnabled": True,
            "queryCondition": {"queryText": "DeviceProcessEvents | take 1"},
            "schedule": {"period": "0"},
            "actions": [
                {"@odata.type": "#microsoft.graph.security.alertAction"},
            ],
            "alertTemplate": {
                "title": rule_id,
                "severity": "high",
                "category": "Execution",
                "description": "d",
                "recommendedActions": "r",
                "mitreTechniques": [],
                "impactedAssets": [],
            },
        },
    }), encoding="utf-8")
    return p


class _ApplyTrackingHandler:
    """Fake handler that records which workspace each apply call saw.

    The apply path sets ``PIPELINE_WORKSPACE_NAME`` between iterations,
    drops cached handler instances, then re-fetches the handler from
    the registry (which calls the factory). Each factory call here
    bumps ``factory_calls`` so tests can assert handler instances were
    rebound across iterations.
    """

    def __init__(self, asset: Asset) -> None:
        self.asset = asset
        self.apply_calls: list[tuple[str, str | None]] = []  # (asset_id, workspace_env)
        self.closed = False

    def validate(self, loaded) -> None:
        return None

    def plan(self, loaded) -> ActionResult:
        return ActionResult(
            asset_id=loaded.envelope.id, asset_kind=self.asset.value,
            action=PlanAction.UPDATE, status="planned",
        )

    def apply(self, loaded, *, dry_run: bool = False) -> ActionResult:
        ws_env = os.environ.get("PIPELINE_WORKSPACE_NAME")
        self.apply_calls.append((loaded.envelope.id, ws_env))
        return ActionResult(
            asset_id=loaded.envelope.id, asset_kind=self.asset.value,
            action=PlanAction.UPDATE, status="success", verified=True,
        )

    def close(self) -> None:
        self.closed = True


def _factory_counter(handler: _ApplyTrackingHandler) -> tuple[list[int], callable]:
    """A factory that returns the same handler but counts invocations.

    ``apply``'s multi-workspace iteration calls ``close_all`` then
    refetches the handler via ``registry.get(asset)``; ``get`` calls
    the factory once per asset per "registry refresh", giving us a
    proxy for "did the iteration re-bind?".
    """
    calls: list[int] = []

    def factory():
        calls.append(1)
        return handler

    return calls, factory


# ===========================================================================
# apply iteration
# ===========================================================================


def test_apply_role_iterates_over_all_matching_workspaces(monkeypatch, tmp_path):
    """``--role prod`` matches two workspaces → apply runs twice for the
    one Sentinel rule on disk, once per workspace."""
    cfg = _make_tenant(("prod", "ws-a"), ("prod", "ws-b"))
    _patch_tenant(monkeypatch, cfg)

    detections = tmp_path / "detections"
    _write_sentinel_yaml(detections, "rule-1")

    fake = _ApplyTrackingHandler(Asset.SENTINEL_ANALYTIC)
    factory_calls, factory = _factory_counter(fake)
    default_registry.register(Asset.SENTINEL_ANALYTIC, factory)

    result = CliRunner().invoke(
        cli, ["apply", "--path", str(detections),
              "--asset", "sentinel_analytic",
              "--role", "prod", "--dry-run", "--no-audit"],
    )
    assert result.exit_code == 0, result.output
    # Iteration header is printed once, listing both workspaces.
    assert "iterating 2 workspaces" in result.output
    assert "ws-a" in result.output and "ws-b" in result.output
    # Apply called twice — once per workspace — for our one rule.
    assert len(fake.apply_calls) == 2
    seen_workspaces = sorted(ws for _, ws in fake.apply_calls)
    assert seen_workspaces == ["ws-a", "ws-b"]


def test_apply_iteration_rebinds_pipeline_workspace_name_env(
    monkeypatch, tmp_path,
):
    """Each apply iteration sees the right workspace in
    ``PIPELINE_WORKSPACE_NAME`` (proves the env var is rebound, not
    just set once)."""
    cfg = _make_tenant(("prod", "ws-a"), ("prod", "ws-b"))
    _patch_tenant(monkeypatch, cfg)

    detections = tmp_path / "detections"
    _write_sentinel_yaml(detections, "rule-1")

    fake = _ApplyTrackingHandler(Asset.SENTINEL_ANALYTIC)
    _, factory = _factory_counter(fake)
    default_registry.register(Asset.SENTINEL_ANALYTIC, factory)

    result = CliRunner().invoke(
        cli, ["apply", "--path", str(detections),
              "--asset", "sentinel_analytic",
              "--role", "prod", "--dry-run", "--no-audit"],
    )
    assert result.exit_code == 0, result.output
    # First apply saw ws-a, second saw ws-b (or vice-versa, order
    # follows tenant.yml list). Either way the SAME workspace name
    # must not be seen twice.
    workspaces_per_call = [ws for _, ws in fake.apply_calls]
    assert len(set(workspaces_per_call)) == 2, workspaces_per_call


def test_apply_iteration_drops_cached_handler_between_workspaces(
    monkeypatch, tmp_path,
):
    """Factory is re-invoked between iterations because the apply
    loop calls ``default_registry.close_all()`` per workspace, which
    clears the cached instance.

    Without this, the per-workspace provider bound to workspace A
    would keep serving requests intended for workspace B."""
    cfg = _make_tenant(("prod", "ws-a"), ("prod", "ws-b"))
    _patch_tenant(monkeypatch, cfg)

    detections = tmp_path / "detections"
    _write_sentinel_yaml(detections, "rule-1")

    fake = _ApplyTrackingHandler(Asset.SENTINEL_ANALYTIC)
    factory_calls, factory = _factory_counter(fake)
    default_registry.register(Asset.SENTINEL_ANALYTIC, factory)

    result = CliRunner().invoke(
        cli, ["apply", "--path", str(detections),
              "--asset", "sentinel_analytic",
              "--role", "prod", "--dry-run", "--no-audit"],
    )
    assert result.exit_code == 0, result.output
    # Two iterations -> factory invoked twice (once per iteration's
    # first .get() call after the close_all). One iteration only
    # would mean the rebind step was skipped.
    assert sum(factory_calls) >= 2, factory_calls
    # Handler.close() called between iterations.
    assert fake.closed is True


def test_apply_iteration_applies_defender_content_only_once(
    monkeypatch, tmp_path,
):
    """Defender XDR is tenant-scoped. With two prod workspaces matched,
    the Sentinel handler runs twice (one per ws) but the Defender
    handler must run **once** — applying the same Defender payload
    N times is wasteful and would echo N PUTs in the audit chain."""
    cfg = _make_tenant(("prod", "ws-a"), ("prod", "ws-b"))
    _patch_tenant(monkeypatch, cfg)

    detections = tmp_path / "detections"
    _write_sentinel_yaml(detections, "sen-rule")
    _write_defender_yaml(detections, "def-rule")

    sentinel_fake = _ApplyTrackingHandler(Asset.SENTINEL_ANALYTIC)
    defender_fake = _ApplyTrackingHandler(Asset.DEFENDER_CUSTOM_DETECTION)
    _, sen_factory = _factory_counter(sentinel_fake)
    _, def_factory = _factory_counter(defender_fake)
    default_registry.register(Asset.SENTINEL_ANALYTIC, sen_factory)
    default_registry.register(Asset.DEFENDER_CUSTOM_DETECTION, def_factory)

    result = CliRunner().invoke(
        cli, ["apply", "--path", str(detections),
              "--role", "prod", "--dry-run", "--no-audit"],
    )
    assert result.exit_code == 0, result.output
    # Sentinel: one rule × two workspaces = 2 applies.
    sen_calls = [c for c in sentinel_fake.apply_calls if c[0] == "sen-rule"]
    assert len(sen_calls) == 2, sentinel_fake.apply_calls
    # Defender: one rule × tenant-scope = exactly 1 apply, regardless
    # of how many Sentinel workspaces matched.
    def_calls = [c for c in defender_fake.apply_calls if c[0] == "def-rule"]
    assert len(def_calls) == 1, defender_fake.apply_calls


def test_apply_workspace_flag_targets_single_workspace(monkeypatch, tmp_path):
    """``--workspace ws-b`` selects exactly that one even when the
    tenant has multiple workspaces sharing a role."""
    cfg = _make_tenant(("prod", "ws-a"), ("prod", "ws-b"))
    _patch_tenant(monkeypatch, cfg)

    detections = tmp_path / "detections"
    _write_sentinel_yaml(detections, "rule-1")

    fake = _ApplyTrackingHandler(Asset.SENTINEL_ANALYTIC)
    _, factory = _factory_counter(fake)
    default_registry.register(Asset.SENTINEL_ANALYTIC, factory)

    result = CliRunner().invoke(
        cli, ["apply", "--path", str(detections),
              "--asset", "sentinel_analytic",
              "--workspace", "ws-b",
              "--dry-run", "--no-audit"],
    )
    assert result.exit_code == 0, result.output
    assert len(fake.apply_calls) == 1
    assert fake.apply_calls[0] == ("rule-1", "ws-b")
    # No multi-workspace iteration banner.
    assert "iterating" not in result.output


def test_apply_role_integration_with_no_matching_workspace_no_ops(
    monkeypatch, tmp_path,
):
    """When the tenant has no ``integration`` workspace, ``--role
    integration`` exits 0 with a "skipping" message instead of
    failing — keeps the integration-deploy PR workflow green on
    tenants that don't define one."""
    cfg = _make_tenant(("prod", "ws-a"))
    _patch_tenant(monkeypatch, cfg)

    detections = tmp_path / "detections"
    _write_sentinel_yaml(detections, "rule-1")

    fake = _ApplyTrackingHandler(Asset.SENTINEL_ANALYTIC)
    _, factory = _factory_counter(fake)
    default_registry.register(Asset.SENTINEL_ANALYTIC, factory)

    result = CliRunner().invoke(
        cli, ["apply", "--path", str(detections),
              "--asset", "sentinel_analytic",
              "--role", "integration", "--dry-run", "--no-audit"],
    )
    assert result.exit_code == 0, result.output
    assert "no Sentinel workspace with role=integration" in result.output
    # Apply not called — handler factory should have been left alone.
    assert fake.apply_calls == []


def test_apply_multi_workspace_no_flag_fails_with_helpful_error(
    monkeypatch, tmp_path,
):
    """On a tenant with multiple Sentinel workspaces, running ``apply``
    with no ``--role`` / ``--workspace`` flag must exit non-zero with
    a message naming the missing flags.

    Without this guard, ``select_workspaces`` raises ValueError
    ("specify --role or --workspace"), the apply path catches it, and
    — because both flags are None — silently falls through to a
    no-workspace state where handler factories receive no
    PIPELINE_WORKSPACE_NAME. The operator sees no clear error; the
    apply may even succeed at dry-run time before failing at the
    first real API call. Force a clean error here instead.
    """
    cfg = _make_tenant(("prod", "ws-a"), ("prod", "ws-b"))
    _patch_tenant(monkeypatch, cfg)

    detections = tmp_path / "detections"
    _write_sentinel_yaml(detections, "rule-1")

    fake = _ApplyTrackingHandler(Asset.SENTINEL_ANALYTIC)
    _, factory = _factory_counter(fake)
    default_registry.register(Asset.SENTINEL_ANALYTIC, factory)

    result = CliRunner().invoke(
        cli, ["apply", "--path", str(detections),
              "--asset", "sentinel_analytic",
              "--dry-run", "--no-audit"],
    )
    assert result.exit_code != 0, (
        f"expected non-zero exit, got 0. output: {result.output}"
    )
    # Error names at least one of the missing flags so the operator
    # knows how to recover.
    assert "--role" in result.output or "--workspace" in result.output, (
        result.output
    )
    # Apply must not have run.
    assert fake.apply_calls == []


# ===========================================================================
# drift role/workspace flags
# ===========================================================================


class _NoOpDriftHandler:
    """Drift-capable fake whose list_remote returns nothing.

    Just enough surface to satisfy ``DriftCapable`` so drift_cmd's
    "no drift-capable handlers registered" branch doesn't short-circuit
    the test before our workspace selector runs.
    """

    asset = Asset.SENTINEL_ANALYTIC

    def list_remote(self):
        return []

    def to_envelope(self, remote):
        return None

    def close(self):
        return None

    def validate(self, loaded):
        return None

    def plan(self, loaded):
        return ActionResult(
            asset_id=loaded.envelope.id, asset_kind=self.asset.value,
            action=PlanAction.NOOP, status="planned",
        )

    def apply(self, loaded, *, dry_run=False):
        return ActionResult(
            asset_id=loaded.envelope.id, asset_kind=self.asset.value,
            action=PlanAction.NOOP, status="success",
        )


def test_drift_workspace_flag_pins_pipeline_workspace_name(monkeypatch, tmp_path):
    """``drift --workspace ws-b`` sets ``PIPELINE_WORKSPACE_NAME`` so
    the handler factories target that workspace."""
    cfg = _make_tenant(("prod", "ws-a"), ("prod", "ws-b"))
    _patch_tenant(monkeypatch, cfg)

    detections = tmp_path / "detections"
    detections.mkdir()

    default_registry.register(Asset.SENTINEL_ANALYTIC, lambda: _NoOpDriftHandler())

    captured: dict[str, str] = {}

    def _capture(*args, **kwargs):
        captured["pipeline_workspace_name"] = (
            os.environ.get("PIPELINE_WORKSPACE_NAME") or ""
        )
        from contentops.core.drift import DriftReport
        return DriftReport()

    monkeypatch.setattr("contentops.cli.commands.drift.detect_drift", _capture)

    result = CliRunner().invoke(
        cli, ["drift", "--path", str(detections),
              "--workspace", "ws-b", "--no-exit-on-drift"],
    )
    assert result.exit_code == 0, result.output
    assert captured["pipeline_workspace_name"] == "ws-b"


def test_drift_role_single_match_is_accepted(monkeypatch, tmp_path):
    """``--role integration`` matching exactly one workspace works."""
    cfg = _make_tenant(("prod", "ws-prod"), ("integration", "ws-int"))
    _patch_tenant(monkeypatch, cfg)

    detections = tmp_path / "detections"
    detections.mkdir()

    default_registry.register(Asset.SENTINEL_ANALYTIC, lambda: _NoOpDriftHandler())

    captured: dict[str, str] = {}

    def _capture(*args, **kwargs):
        captured["pipeline_workspace_name"] = (
            os.environ.get("PIPELINE_WORKSPACE_NAME") or ""
        )
        from contentops.core.drift import DriftReport
        return DriftReport()

    monkeypatch.setattr("contentops.cli.commands.drift.detect_drift", _capture)

    result = CliRunner().invoke(
        cli, ["drift", "--path", str(detections),
              "--role", "integration", "--no-exit-on-drift"],
    )
    assert result.exit_code == 0, result.output
    assert captured["pipeline_workspace_name"] == "ws-int"


def test_drift_role_multi_match_fails_closed(monkeypatch, tmp_path):
    """``--role prod`` matching multiple workspaces exits 2 with a
    clear message. Drift targets one workspace per run; ``apply``
    iterates because it writes."""
    cfg = _make_tenant(("prod", "ws-a"), ("prod", "ws-b"))
    _patch_tenant(monkeypatch, cfg)

    detections = tmp_path / "detections"
    detections.mkdir()

    default_registry.register(Asset.SENTINEL_ANALYTIC, lambda: _NoOpDriftHandler())

    result = CliRunner().invoke(
        cli, ["drift", "--path", str(detections),
              "--role", "prod", "--no-exit-on-drift"],
    )
    assert result.exit_code == 2, result.output
    msg = result.output.lower()
    assert "matches 2 workspaces" in result.output
    assert "one workspace per run" in msg or "one workspace per" in msg
    # Suggests the operator's remediation paths.
    assert "--workspace" in result.output
    assert "contentops apply" in result.output


def test_drift_with_no_flag_passes_through(monkeypatch, tmp_path):
    """Without ``--role`` / ``--workspace``, the resolver is a no-op.

    This preserves backward compat with operators relying on
    ``PIPELINE_WORKSPACE_NAME`` env var, and with the existing
    single-workspace test suite that constructs fake handlers
    without setting either flag."""
    cfg = _make_tenant(("prod", "ws-a"), ("prod", "ws-b"))
    _patch_tenant(monkeypatch, cfg)

    detections = tmp_path / "detections"
    detections.mkdir()

    default_registry.register(Asset.SENTINEL_ANALYTIC, lambda: _NoOpDriftHandler())

    # Set env var to a workspace name — the resolver should not touch it.
    monkeypatch.setenv("PIPELINE_WORKSPACE_NAME", "ws-a")

    captured: dict[str, str] = {}

    def _capture(*args, **kwargs):
        captured["pipeline_workspace_name"] = (
            os.environ.get("PIPELINE_WORKSPACE_NAME") or ""
        )
        from contentops.core.drift import DriftReport
        return DriftReport()

    monkeypatch.setattr("contentops.cli.commands.drift.detect_drift", _capture)

    result = CliRunner().invoke(
        cli, ["drift", "--path", str(detections), "--no-exit-on-drift"],
    )
    assert result.exit_code == 0, result.output
    # Env-var value preserved.
    assert captured["pipeline_workspace_name"] == "ws-a"


# ===========================================================================
# prune role/workspace flags
# ===========================================================================


class _NoOpPruneHandler:
    """Drift-capable fake with no orphans — exercises prune control flow
    without modelling specific delete semantics."""

    asset = Asset.SENTINEL_ANALYTIC

    def list_remote(self):
        return []

    def to_envelope(self, remote):
        return None

    def delete(self, remote_id):
        return ActionResult(
            asset_id=remote_id, asset_kind=self.asset.value,
            action=PlanAction.DELETE, status="success",
        )

    def close(self):
        return None

    def validate(self, loaded):
        return None

    def plan(self, loaded):
        return ActionResult(
            asset_id=loaded.envelope.id, asset_kind=self.asset.value,
            action=PlanAction.NOOP, status="planned",
        )

    def apply(self, loaded, *, dry_run=False):
        return ActionResult(
            asset_id=loaded.envelope.id, asset_kind=self.asset.value,
            action=PlanAction.NOOP, status="success",
        )


def test_prune_workspace_flag_pins_pipeline_workspace_name(monkeypatch, tmp_path):
    """``prune --workspace ws-b`` sets ``PIPELINE_WORKSPACE_NAME``."""
    cfg = _make_tenant(("prod", "ws-a"), ("prod", "ws-b"))
    _patch_tenant(monkeypatch, cfg)

    detections = tmp_path / "detections"
    detections.mkdir()

    default_registry.register(Asset.SENTINEL_ANALYTIC, lambda: _NoOpPruneHandler())

    result = CliRunner().invoke(
        cli, ["prune", "--path", str(detections),
              "--asset", "sentinel_analytic",
              "--workspace", "ws-b"],
    )
    assert result.exit_code == 0, result.output
    # Env-var got pinned BEFORE the handler factory was invoked.
    # The fake handler doesn't read the env, but the resolver path
    # in _shared.py sets it; verify directly via os.environ.
    assert os.environ.get("PIPELINE_WORKSPACE_NAME") == "ws-b"


def test_prune_role_single_match_is_accepted(monkeypatch, tmp_path):
    cfg = _make_tenant(("prod", "ws-prod"), ("integration", "ws-int"))
    _patch_tenant(monkeypatch, cfg)

    detections = tmp_path / "detections"
    detections.mkdir()

    default_registry.register(Asset.SENTINEL_ANALYTIC, lambda: _NoOpPruneHandler())

    result = CliRunner().invoke(
        cli, ["prune", "--path", str(detections),
              "--asset", "sentinel_analytic",
              "--role", "integration"],
    )
    assert result.exit_code == 0, result.output
    assert os.environ.get("PIPELINE_WORKSPACE_NAME") == "ws-int"


def test_prune_role_multi_match_fails_closed(monkeypatch, tmp_path):
    """``prune --role prod`` matching multiple workspaces exits 2."""
    cfg = _make_tenant(("prod", "ws-a"), ("prod", "ws-b"))
    _patch_tenant(monkeypatch, cfg)

    detections = tmp_path / "detections"
    detections.mkdir()

    default_registry.register(Asset.SENTINEL_ANALYTIC, lambda: _NoOpPruneHandler())

    result = CliRunner().invoke(
        cli, ["prune", "--path", str(detections),
              "--asset", "sentinel_analytic",
              "--role", "prod"],
    )
    assert result.exit_code == 2, result.output
    assert "matches 2 workspaces" in result.output


def test_prune_with_no_flag_passes_through(monkeypatch, tmp_path):
    """``prune`` without ``--role`` / ``--workspace`` preserves the
    pre-Phase-1 control flow: no tenant.yml is consulted, the
    ``PIPELINE_WORKSPACE_NAME`` env var (if set) flows through to
    the handler factories untouched. Backward-compat with the
    pre-existing fake-handler test pattern in test_prune.py."""
    # Don't patch tenant config — the additive resolver shouldn't even
    # call load_tenant_config() when no flag is passed.
    detections = tmp_path / "detections"
    detections.mkdir()

    default_registry.register(Asset.SENTINEL_ANALYTIC, lambda: _NoOpPruneHandler())

    # An env var the resolver MUST NOT overwrite.
    monkeypatch.setenv("PIPELINE_WORKSPACE_NAME", "from-env")

    result = CliRunner().invoke(
        cli, ["prune", "--path", str(detections),
              "--asset", "sentinel_analytic"],
    )
    assert result.exit_code == 0, result.output
    assert os.environ.get("PIPELINE_WORKSPACE_NAME") == "from-env"
