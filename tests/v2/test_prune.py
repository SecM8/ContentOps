# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for `contentops prune` and the per-handler `delete()` method.

These cover the pure CLI control-flow + handler delete paths (with
respx mocks) — the live create→prune→404 round-trip lives in
tests/integration/test_prune_live.py.
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
import yaml
from click.testing import CliRunner

from contentops.cli import cli
from contentops.config import SentinelConfig
from contentops.core.asset import Asset
from contentops.core.envelope import EnvelopeV2
from contentops.core.handler import LoadedAsset
from contentops.core.registry import default_registry
from contentops.core.result import ActionResult, NotSupportedError, PlanAction
from contentops.handlers._delete import (
    delete_result_from_exception,
    delete_result_from_response,
)
from contentops.handlers.sentinel_analytic import SentinelAnalyticHandler
from contentops.providers import sentinel_arm
from contentops.providers.sentinel_arm import SentinelArmProvider


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    monkeypatch.setattr(sentinel_arm.time, "sleep", lambda *_: None)
    # Re-init registry between tests so tests don't see each other's
    # registered factories.
    default_registry.reset()


def _provider_with(transport: httpx.MockTransport) -> SentinelArmProvider:
    cfg = SentinelConfig(subscriptionId="sub", resourceGroup="rg", workspaceName="ws")
    p = SentinelArmProvider(cfg, token="t")
    p._client.close()
    p._client = httpx.Client(
        base_url=sentinel_arm.ARM_BASE_URL, transport=transport,
        headers={"Authorization": "Bearer t"},
    )
    return p


# ---------------------------------------------------------------------------
# _delete helpers
# ---------------------------------------------------------------------------


class _Resp:
    """Tiny duck-typed response for the helpers."""

    def __init__(self, status_code: int, text: str = "") -> None:
        self.status_code = status_code
        self.text = text


def test_delete_result_200_is_success() -> None:
    r = delete_result_from_response("rid-1", Asset.SENTINEL_ANALYTIC, _Resp(200))
    assert r.status == "success"
    assert r.action is PlanAction.DELETE


def test_delete_result_404_is_idempotent_success() -> None:
    r = delete_result_from_response("rid-1", Asset.SENTINEL_ANALYTIC, _Resp(404, "not found"))
    assert r.status == "success"
    assert "already absent" in r.detail


def test_delete_result_500_is_error() -> None:
    r = delete_result_from_response(
        "rid-1", Asset.SENTINEL_ANALYTIC, _Resp(500, "boom"),
    )
    assert r.status == "error-500"
    assert r.is_failure
    assert "boom" in (r.error or "")


def test_delete_result_from_exception() -> None:
    r = delete_result_from_exception(
        "rid-1", Asset.SENTINEL_ANALYTIC, RuntimeError("kaboom"),
    )
    assert r.status == "error-exception"
    assert r.is_failure


# ---------------------------------------------------------------------------
# Per-handler delete() — write-capable shape
# ---------------------------------------------------------------------------


def test_analytic_handler_delete_calls_provider() -> None:
    """R3/Q2 — handler delegates DELETE to the shared SentinelArmProvider,
    not a dedicated v1 shim client. The fake provider mirrors the
    method shape the handler now depends on (delete_resource taking
    a resource_type + name)."""
    deleted: list[tuple[str, str]] = []

    class FakeProvider:
        def __init__(self) -> None:
            self.closed = False

        def delete_resource(self, resource_type, name):
            deleted.append((resource_type, name))
            return _Resp(200)

        def close(self):
            self.closed = True

    provider = FakeProvider()
    h = SentinelAnalyticHandler(lambda: provider)
    result = h.delete("guid-1")
    assert result.status == "success"
    assert deleted == [("alertRules", "guid-1")]


# ---------------------------------------------------------------------------
# contentops prune CLI
# ---------------------------------------------------------------------------


def _envelope(rule_id: str, *, locked: bool = False) -> dict:
    body = {
        "id": rule_id,
        "version": "1.0.0",
        "asset": "sentinel_analytic",
        "status": "production",
        "payload": {
            "kind": "Scheduled",
            "displayName": rule_id,
            "severity": "Low",
            "query": "print 1",
            "queryFrequency": "PT5M",
            "queryPeriod": "PT5M",
            "triggerOperator": "GreaterThan",
            "triggerThreshold": 0,
        },
    }
    if locked:
        body["localCustomization"] = True
    return body


def _write_yaml(detections: Path, rule_id: str, *, locked: bool = False) -> Path:
    detections.mkdir(parents=True, exist_ok=True)
    p = detections / f"{rule_id}.yml"
    p.write_text(yaml.safe_dump(_envelope(rule_id, locked=locked)),
                 encoding="utf-8")
    return p


class _FakeAnalyticHandler:
    """In-memory analytic handler for prune CLI tests.

    Implements list_remote / to_envelope / delete + the standard
    Handler protocol bits the registry needs.
    """

    asset = Asset.SENTINEL_ANALYTIC

    def __init__(self, remote_items: list[dict]) -> None:
        self.remote_items = list(remote_items)
        self.deleted: list[str] = []
        self.delete_responses: dict[str, ActionResult] = {}

    def list_remote(self) -> list[dict]:
        return list(self.remote_items)

    def to_envelope(self, remote: dict) -> dict | None:
        rid = remote.get("name")
        if not rid:
            return None
        return {
            "id": rid, "version": "0.1.0",
            "asset": Asset.SENTINEL_ANALYTIC.value,
            "status": "production",
            "payload": {"kind": "Scheduled", "displayName": rid,
                        "severity": "Low", "query": "x",
                        "queryFrequency": "PT5M", "queryPeriod": "PT5M",
                        "triggerOperator": "GreaterThan",
                        "triggerThreshold": 0},
        }

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

    def delete(self, remote_id: str) -> ActionResult:
        self.deleted.append(remote_id)
        return self.delete_responses.get(remote_id) or ActionResult(
            asset_id=remote_id, asset_kind=self.asset.value,
            action=PlanAction.DELETE, status="success", detail="deleted",
        )

    def close(self):
        return None


def _register_only(asset: Asset, handler) -> None:
    default_registry.reset()
    default_registry._factories.clear()
    default_registry._instances.clear()
    default_registry.register(asset, lambda: handler)


def test_prune_dry_run_does_not_delete(tmp_path: Path) -> None:
    detections = tmp_path / "detections"
    _write_yaml(detections, "kept-1")  # only this one in git
    fake = _FakeAnalyticHandler([{"name": "kept-1"}, {"name": "orphan-1"}])
    _register_only(Asset.SENTINEL_ANALYTIC, fake)

    result = CliRunner().invoke(
        cli, ["prune", "--path", str(detections), "--asset", "sentinel_analytic"],
    )
    assert result.exit_code == 0, result.output
    assert "ORPHAN" in result.output
    assert "orphan-1" in result.output
    assert "[dry-run]" in result.output
    assert fake.deleted == []


def test_prune_yes_no_dry_run_actually_deletes(tmp_path: Path) -> None:
    detections = tmp_path / "detections"
    _write_yaml(detections, "kept-1")
    fake = _FakeAnalyticHandler([{"name": "kept-1"}, {"name": "orphan-1"}])
    _register_only(Asset.SENTINEL_ANALYTIC, fake)

    result = CliRunner().invoke(
        cli, ["prune", "--path", str(detections),
              "--asset", "sentinel_analytic",
              "--no-dry-run", "--yes"],
    )
    assert result.exit_code == 0, result.output
    assert "DELETED" in result.output
    assert fake.deleted == ["orphan-1"]


def test_prune_max_deletes_fails_closed(tmp_path: Path) -> None:
    detections = tmp_path / "detections"
    detections.mkdir()
    fake = _FakeAnalyticHandler([{"name": f"orphan-{i}"} for i in range(5)])
    _register_only(Asset.SENTINEL_ANALYTIC, fake)

    result = CliRunner().invoke(
        cli, ["prune", "--path", str(detections),
              "--asset", "sentinel_analytic",
              "--no-dry-run", "--yes", "--max-deletes", "3"],
    )
    assert result.exit_code == 1
    assert "exceeds --max-deletes" in result.output
    assert fake.deleted == []


def test_prune_fails_closed_when_list_remote_errors(tmp_path: Path) -> None:
    """A handler that can't enumerate its remote (e.g. an unreadable /
    auth-failed tenant config) must NOT be read as 'zero remote items =
    nothing to prune'. Prune fails closed (exit 2) instead of reporting a
    false-green empty orphan set — the regression where a fully-blind run
    printed "Nothing to prune" and exited 0."""
    detections = tmp_path / "detections"
    detections.mkdir()
    fake = _FakeAnalyticHandler([])

    def _boom() -> list[dict]:
        raise RuntimeError("Tenant config not found at config/tenant.prod.yml")

    fake.list_remote = _boom  # type: ignore[assignment]
    _register_only(Asset.SENTINEL_ANALYTIC, fake)

    result = CliRunner().invoke(
        cli, ["prune", "--path", str(detections),
              "--asset", "sentinel_analytic",
              "--no-dry-run", "--yes"],
    )
    assert result.exit_code == 2, result.output
    assert "could not list the remote inventory" in result.output
    assert fake.deleted == []


def test_prune_partial_list_failure_proceeds(tmp_path: Path) -> None:
    """A PARTIAL listing failure (one kind hiccups while another lists fine)
    must NOT fail-closed: prune the kinds it could see and report the rest.
    Only a FULLY-blind run (zero visibility) refuses. Regression — an unscoped
    prune used to exit 2 if a single kind's list_remote raised (e.g. a Defender
    / transient error blocking an otherwise-fine Sentinel prune)."""
    detections = tmp_path / "detections"
    _write_yaml(detections, "kept-1")

    good = _FakeAnalyticHandler([{"name": "kept-1"}, {"name": "orphan-1"}])

    class _BadWatchlistHandler(_FakeAnalyticHandler):
        asset = Asset.SENTINEL_WATCHLIST

        def list_remote(self):
            raise RuntimeError("transient 500 listing watchlists")

    bad = _BadWatchlistHandler([])

    default_registry.reset()
    default_registry._factories.clear()
    default_registry._instances.clear()
    default_registry.register(Asset.SENTINEL_ANALYTIC, lambda: good)
    default_registry.register(Asset.SENTINEL_WATCHLIST, lambda: bad)

    result = CliRunner().invoke(
        cli, ["prune", "--path", str(detections), "--no-dry-run", "--yes"],
    )
    assert result.exit_code == 0, result.output        # proceeds, not exit 2
    assert good.deleted == ["orphan-1"]                # visible orphan handled
    assert "sentinel_watchlist" in result.output       # un-listable kind reported


def test_prune_locked_assets_skipped_by_default(tmp_path: Path) -> None:
    detections = tmp_path / "detections"
    # The orphan exists remote AND has a local YAML marked locked. The
    # prune command should treat it as locked, not as an orphan to
    # delete. We test both branches via a third asset that's purely
    # remote.
    _write_yaml(detections, "locked-keep", locked=True)
    fake = _FakeAnalyticHandler([
        {"name": "locked-keep"},     # has local YAML — not an orphan anyway
        {"name": "purely-orphan"},   # no local YAML — should delete
    ])
    _register_only(Asset.SENTINEL_ANALYTIC, fake)

    result = CliRunner().invoke(
        cli, ["prune", "--path", str(detections),
              "--asset", "sentinel_analytic",
              "--no-dry-run", "--yes"],
    )
    assert result.exit_code == 0, result.output
    assert fake.deleted == ["purely-orphan"]


def test_prune_locked_orphans_skipped(tmp_path: Path) -> None:
    """If an envelope is on disk + locked but has no remote, that's not
    an orphan and shouldn't appear at all. If an envelope is remote-only
    (no local YAML) it's an orphan; locked-set membership is keyed on
    local files, so a remote-only orphan can never be locked."""
    detections = tmp_path / "detections"
    detections.mkdir()
    fake = _FakeAnalyticHandler([{"name": "orphan-only"}])
    _register_only(Asset.SENTINEL_ANALYTIC, fake)

    result = CliRunner().invoke(
        cli, ["prune", "--path", str(detections),
              "--asset", "sentinel_analytic",
              "--no-dry-run", "--yes"],
    )
    assert result.exit_code == 0, result.output
    assert "orphan-only" in result.output


def test_prune_handles_not_supported_error_as_skip(tmp_path: Path) -> None:
    detections = tmp_path / "detections"
    detections.mkdir()
    fake = _FakeAnalyticHandler([{"name": "orphan-1"}])
    fake.delete_responses = {}
    # Override delete to raise NotSupportedError to exercise that branch.
    original_delete = fake.delete

    def _raising_delete(rid):
        raise NotSupportedError("test: read-only")
    fake.delete = _raising_delete  # type: ignore[assignment]
    _register_only(Asset.SENTINEL_ANALYTIC, fake)

    result = CliRunner().invoke(
        cli, ["prune", "--path", str(detections),
              "--asset", "sentinel_analytic",
              "--no-dry-run", "--yes"],
    )
    # NotSupportedError -> SKIP, not an error; exit 0.
    assert result.exit_code == 0, result.output
    assert "SKIP" in result.output


def test_prune_json_output(tmp_path: Path) -> None:
    detections = tmp_path / "detections"
    detections.mkdir()
    fake = _FakeAnalyticHandler([{"name": "orphan-1"}])
    _register_only(Asset.SENTINEL_ANALYTIC, fake)

    result = CliRunner().invoke(
        cli, ["prune", "--path", str(detections),
              "--asset", "sentinel_analytic",
              "--json"],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output.split("\n[dry-run]")[0].strip()
                         if result.output.strip().startswith("{")
                         else result.output[result.output.index("{"):])
    assert payload["dry_run"] is True
    assert any(o["envelope_id"] == "orphan-1" for o in payload["orphans"])


# ---------------------------------------------------------------------------
# Cross-phase Seam B: prune audit records carry the workspace dimension
# ---------------------------------------------------------------------------


def test_build_prune_audit_record_threads_workspace() -> None:
    """The workspace kwarg must populate the AuditRecord field so
    multi-workspace prune events are attributable in the audit log."""
    from contentops.cli.commands.apply_support import _build_audit_record
    rec = _build_audit_record(
        ActionResult(
            asset_id="r1", asset_kind="sentinel_analytic",
            action=PlanAction.DELETE, status="deleted",
        ),
        envelope_id="r1",
        asset_value="sentinel_analytic",
        workspace="law-prod",
        success_detail="pruned",
    )
    assert rec.workspace == "law-prod"
    assert rec.snippet_digest is None


def test_build_prune_audit_record_default_workspace_is_none() -> None:
    """Backwards compat: the workspace kwarg is optional."""
    from contentops.cli.commands.apply_support import _build_audit_record
    rec = _build_audit_record(
        ActionResult(
            asset_id="r2", asset_kind="sentinel_analytic",
            action=PlanAction.DELETE, status="deleted",
        ),
        envelope_id="r2",
        asset_value="sentinel_analytic",
        success_detail="pruned",
    )
    assert rec.workspace is None


# ---------------------------------------------------------------------------
# tenant.yml safeguards (purgeAllowed / maxDelete)
# ---------------------------------------------------------------------------


def _synthetic_tenant_config(
    *,
    sentinel_purge_allowed: bool = False,
    sentinel_max_delete: int = 25,
    defender_block: bool = False,
    defender_purge_allowed: bool = False,
    defender_max_delete: int = 25,
):
    """Build a TenantConfig instance the safeguard test can pin against."""
    from contentops.config import (
        DefenderConfig,
        SentinelWorkspaceConfig,
        TenantConfig,
    )
    return TenantConfig(
        name="test-tenant",
        tenantId="aad-test-guid",
        defender=(
            DefenderConfig(
                purgeAllowed=defender_purge_allowed,
                maxDelete=defender_max_delete,
            )
            if defender_block
            else None
        ),
        sentinelWorkspaces=[
            SentinelWorkspaceConfig(
                role="prod",
                subscriptionId="sub-1", resourceGroup="rg-1",
                workspaceName="ws-prod",
                purgeAllowed=sentinel_purge_allowed,
                maxDelete=sentinel_max_delete,
            ),
        ],
    )


def test_prune_refuses_when_purge_not_allowed(tmp_path: Path, monkeypatch) -> None:
    """When tenant.yml is loadable and the active Sentinel workspace
    has ``purgeAllowed: false``, prune must exit 2 before opening any
    Azure connections. The error names the offending workspace so the
    operator knows which entry to edit.

    Gate only fires on ``--no-dry-run --yes`` — dry-run bypasses so
    operators can still preview against a locked env."""
    detections = tmp_path / "detections"
    detections.mkdir()
    cfg = _synthetic_tenant_config(sentinel_purge_allowed=False)
    monkeypatch.setattr(
        "contentops.config.load_tenant_config",
        lambda *_a, **_kw: cfg,
    )

    result = CliRunner().invoke(
        cli, ["prune", "--path", str(detections),
              "--asset", "sentinel_analytic",
              "--no-dry-run", "--yes"],
    )
    assert result.exit_code == 2, result.output
    assert "purgeAllowed=False" in result.output
    assert "ws-prod" in result.output


def test_prune_dry_run_bypasses_purge_gate(tmp_path: Path, monkeypatch) -> None:
    """Dry-run must let operators preview against a workspace with
    ``purgeAllowed: false``. Same semantics as apply --dry-run; the
    gate's purpose is preventing destructive ops, not blocking
    previews."""
    detections = tmp_path / "detections"
    detections.mkdir()
    cfg = _synthetic_tenant_config(sentinel_purge_allowed=False)
    monkeypatch.setattr(
        "contentops.config.load_tenant_config",
        lambda *_a, **_kw: cfg,
    )
    fake = _FakeAnalyticHandler([])
    _register_only(Asset.SENTINEL_ANALYTIC, fake)

    result = CliRunner().invoke(
        cli, ["prune", "--path", str(detections),
              "--asset", "sentinel_analytic"],
        # default --dry-run (no --no-dry-run, no --yes)
    )
    assert result.exit_code == 0, result.output
    assert "purgeAllowed=False" not in result.output  # no refusal


def test_prune_passes_when_purge_allowed(tmp_path: Path, monkeypatch) -> None:
    """``purgeAllowed: true`` lets the prune proceed through to the
    handler-walk phase (which then exits cleanly because the synthetic
    handler reports zero orphans)."""
    detections = tmp_path / "detections"
    detections.mkdir()
    cfg = _synthetic_tenant_config(
        sentinel_purge_allowed=True, sentinel_max_delete=500,
    )
    monkeypatch.setattr(
        "contentops.config.load_tenant_config",
        lambda *_a, **_kw: cfg,
    )
    fake = _FakeAnalyticHandler([])  # zero orphans
    _register_only(Asset.SENTINEL_ANALYTIC, fake)

    result = CliRunner().invoke(
        cli, ["prune", "--path", str(detections),
              "--asset", "sentinel_analytic"],
    )
    assert result.exit_code == 0, result.output
    assert "purgeAllowed" not in result.output  # no refusal message


def test_prune_max_delete_clamps_cli_value_down(tmp_path: Path, monkeypatch) -> None:
    """When the workspace's ``maxDelete`` is lower than the CLI's
    ``--max-deletes``, the workspace cap wins. Test: workspace=3,
    CLI=10, 5 orphans → exit 1 with the max_deletes_exceeded error."""
    detections = tmp_path / "detections"
    detections.mkdir()
    cfg = _synthetic_tenant_config(
        sentinel_purge_allowed=True, sentinel_max_delete=3,
    )
    monkeypatch.setattr(
        "contentops.config.load_tenant_config",
        lambda *_a, **_kw: cfg,
    )
    fake = _FakeAnalyticHandler([{"name": f"orphan-{i}"} for i in range(5)])
    _register_only(Asset.SENTINEL_ANALYTIC, fake)

    result = CliRunner().invoke(
        cli, ["prune", "--path", str(detections),
              "--asset", "sentinel_analytic",
              "--no-dry-run", "--yes", "--max-deletes", "10"],
    )
    assert result.exit_code == 1, result.output
    assert "exceeds --max-deletes" in result.output
    assert "clamped 10 -> 3" in result.output


def test_prune_defender_safeguard_blocks_when_only_defender_targeted(
    tmp_path: Path, monkeypatch,
) -> None:
    """``--asset defender_custom_detection`` consults ONLY the Defender
    safeguard, ignoring the Sentinel workspace's safeguard. Verifies
    the source-routing in _resolve_safeguards_for_target. Requires
    non-dry-run so the gate actually fires."""
    detections = tmp_path / "detections"
    detections.mkdir()
    cfg = _synthetic_tenant_config(
        sentinel_purge_allowed=True,       # Sentinel is allowed
        defender_block=True,
        defender_purge_allowed=False,      # Defender is locked
    )
    monkeypatch.setattr(
        "contentops.config.load_tenant_config",
        lambda *_a, **_kw: cfg,
    )

    result = CliRunner().invoke(
        cli, ["prune", "--path", str(detections),
              "--asset", "defender_custom_detection",
              "--no-dry-run", "--yes"],
    )
    assert result.exit_code == 2, result.output
    assert "Defender XDR" in result.output
    assert "purgeAllowed=False" in result.output


def test_prune_role_integration_absent_skips_gracefully(
    tmp_path: Path, monkeypatch,
) -> None:
    """``--role integration`` on a tenant with NO integration workspace must
    skip gracefully (exit 0), not hard-fail at the workspace resolver. Honours
    the operator rule that a tenant without an integration env never fails the
    pipeline. (drift / collect / rollback share the identical wiring.)"""
    detections = tmp_path / "detections"
    detections.mkdir()
    cfg = _synthetic_tenant_config(sentinel_purge_allowed=True)  # prod-only
    monkeypatch.setattr(
        "contentops.config.load_tenant_config", lambda *a, **k: cfg,
    )
    fake = _FakeAnalyticHandler([{"name": "orphan-1"}])
    _register_only(Asset.SENTINEL_ANALYTIC, fake)

    result = CliRunner().invoke(
        cli, ["prune", "--path", str(detections),
              "--asset", "sentinel_analytic",
              "--role", "integration", "--no-dry-run", "--yes"],
    )
    assert result.exit_code == 0, result.output
    assert "role=integration" in result.output
    assert fake.deleted == []
