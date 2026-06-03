# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the multi-workspace iteration logic in
``contentops.devex.doctor._check_handler_matrix``.

On a multi-Sentinel-workspace tenant, the matrix should run each Sentinel
handler once per workspace (emitting ``handler:<kind>@<workspaceName>`` row
names) and run the Defender handler exactly once. When the operator pins
a workspace via ``PIPELINE_WORKSPACE_NAME`` (set by ``doctor --role`` /
``--workspace``), only that workspace is iterated and the ``@<ws>`` suffix
is dropped — keeping the single-workspace output shape unchanged.

These tests use fakes for the handler registry and ``load_tenant_config``
so they don't touch live Azure.
"""

from __future__ import annotations

import os

import pytest

from contentops.config import SentinelWorkspaceConfig, TenantConfig
from contentops.core.asset import Asset
from contentops.core.registry import default_registry


@pytest.fixture(autouse=True)
def _clean_registry():
    """Each test starts and ends with an empty registry so factory
    registrations from one test don't leak into the next."""
    default_registry.reset_all()
    yield
    default_registry.reset_all()


class _FakeSentinelHandler:
    """Stand-in for ``SentinelAnalyticHandler`` that records which workspace
    ``list_remote()`` saw via ``PIPELINE_WORKSPACE_NAME``.

    The ``asset`` attribute + ``list_remote`` / ``to_envelope`` methods are
    enough to satisfy ``DriftCapable`` (runtime-checkable Protocol)."""

    asset = Asset.SENTINEL_ANALYTIC

    def __init__(self) -> None:
        self.seen_workspaces: list[str] = []

    def list_remote(self) -> list[dict]:
        ws = os.environ.get("PIPELINE_WORKSPACE_NAME", "<unset>")
        self.seen_workspaces.append(ws)
        return [{"id": f"r1@{ws}"}, {"id": f"r2@{ws}"}]

    def to_envelope(self, remote: dict) -> dict | None:
        return {"envelope": True}

    def close(self) -> None:  # iteration loop calls this between workspaces
        pass


class _FakeDefenderHandler:
    """Workspace-independent stand-in for ``DefenderCustomDetectionHandler``."""

    asset = Asset.DEFENDER_CUSTOM_DETECTION

    def __init__(self) -> None:
        self.call_count = 0

    def list_remote(self) -> list[dict]:
        self.call_count += 1
        return [{"id": "g1"}, {"id": "g2"}, {"id": "g3"}]

    def to_envelope(self, remote: dict) -> dict | None:
        return {"envelope": True}

    def close(self) -> None:
        pass


def _ws(role: str, name: str) -> SentinelWorkspaceConfig:
    return SentinelWorkspaceConfig(
        role=role,
        subscriptionId="00000000-0000-0000-0000-000000000000",
        resourceGroup=f"rg-{name.lower()}",
        workspaceName=name,
        location="westeurope",
    )


def _cfg(workspaces: list[SentinelWorkspaceConfig]) -> TenantConfig:
    return TenantConfig(
        name="test",
        tenantId="00000000-0000-0000-0000-000000000000",
        sentinelWorkspaces=workspaces,
    )


def _patch_for_matrix(
    monkeypatch: pytest.MonkeyPatch,
    *,
    workspaces: list[SentinelWorkspaceConfig],
) -> None:
    """Install the standard test patches: a fake tenant config and a
    no-op ``register_default_handlers``. The caller registers handlers
    directly on ``default_registry`` after this."""
    monkeypatch.setattr(
        "contentops.config.load_tenant_config", lambda: _cfg(workspaces),
    )
    monkeypatch.setattr(
        "contentops.cli.handler_factories.register_default_handlers",
        lambda: None,
    )


def test_multi_workspace_auto_picks_prod_and_emits_note(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Two workspaces → matrix auto-picks the prod-role workspace and
    emits one ``handler_matrix_workspace`` note explaining the choice.
    Sentinel handler runs once against the prod workspace; Defender
    runs once (workspace-independent). No ``@<ws>`` suffix.

    Behaviour changed 2026-05-18 (adopter-friction task #29): the
    previous handler × workspace iteration produced N × M rows of
    near-identical output that drowned out the real signals. The
    matrix is a reachability probe — pick one workspace, say which
    one, and let the operator pass ``--workspace`` to target others.
    """
    monkeypatch.delenv("PIPELINE_WORKSPACE_NAME", raising=False)
    _patch_for_matrix(
        monkeypatch,
        workspaces=[_ws("prod", "LAW-A"), _ws("integration", "LAW-B")],
    )

    sentinel = _FakeSentinelHandler()
    defender = _FakeDefenderHandler()
    default_registry.register(Asset.SENTINEL_ANALYTIC, lambda: sentinel)
    default_registry.register(
        Asset.DEFENDER_CUSTOM_DETECTION, lambda: defender,
    )

    from contentops.devex.doctor import _check_handler_matrix
    results = _check_handler_matrix()

    names = {r.name: r for r in results}
    # One auto-pick note naming the chosen workspace.
    assert "handler_matrix_workspace" in names
    assert "LAW-A" in names["handler_matrix_workspace"].detail
    # Handler rows have no @<ws> suffix anymore.
    assert "handler:sentinel_analytic" in names
    assert "handler:sentinel_analytic@LAW-A" not in names
    assert "handler:sentinel_analytic@LAW-B" not in names
    assert "handler:defender_custom_detection" in names
    # Defender ran exactly once (unchanged behaviour).
    assert defender.call_count == 1
    # Sentinel handler observed only the prod workspace.
    assert sentinel.seen_workspaces == ["LAW-A"]
    # Handler rows are PASS; the auto-pick note is WARN (the
    # informational slot in the doctor Status enum).
    for r in results:
        if r.name.startswith("handler:"):
            assert r.status == "PASS", f"{r.name} = {r.status}: {r.detail}"
    # Iteration restored the env-var state it found on entry.
    assert "PIPELINE_WORKSPACE_NAME" not in os.environ


def test_single_workspace_keeps_legacy_row_shape(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Single-workspace tenant → no ``@<ws>`` suffix; the row name stays
    ``handler:<kind>`` for backward compatibility with downstream parsers."""
    monkeypatch.delenv("PIPELINE_WORKSPACE_NAME", raising=False)
    _patch_for_matrix(monkeypatch, workspaces=[_ws("prod", "LAW-ONLY")])

    default_registry.register(
        Asset.SENTINEL_ANALYTIC, lambda: _FakeSentinelHandler(),
    )
    default_registry.register(
        Asset.DEFENDER_CUSTOM_DETECTION, lambda: _FakeDefenderHandler(),
    )

    from contentops.devex.doctor import _check_handler_matrix
    results = _check_handler_matrix()

    names = [r.name for r in results]
    assert "handler:sentinel_analytic" in names
    assert "handler:defender_custom_detection" in names
    assert not any("@" in n for n in names), (
        f"single-workspace rows must not carry @<ws>; got {names}"
    )


def test_pinned_workspace_targets_only_that_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``PIPELINE_WORKSPACE_NAME`` already set (operator passed --role /
    --workspace) → matrix iterates that one workspace, drops the suffix,
    and restores the same pinned value on exit."""
    monkeypatch.setenv("PIPELINE_WORKSPACE_NAME", "LAW-B")
    _patch_for_matrix(
        monkeypatch,
        workspaces=[_ws("prod", "LAW-A"), _ws("integration", "LAW-B")],
    )

    sentinel = _FakeSentinelHandler()
    default_registry.register(Asset.SENTINEL_ANALYTIC, lambda: sentinel)
    default_registry.register(
        Asset.DEFENDER_CUSTOM_DETECTION, lambda: _FakeDefenderHandler(),
    )

    from contentops.devex.doctor import _check_handler_matrix
    results = _check_handler_matrix()

    names = [r.name for r in results]
    assert "handler:sentinel_analytic" in names
    assert not any("@" in n for n in names)
    assert sentinel.seen_workspaces == ["LAW-B"]
    # Caller's pinned value preserved.
    assert os.environ.get("PIPELINE_WORKSPACE_NAME") == "LAW-B"


def test_defender_only_tenant_skips_sentinel_iteration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No Sentinel workspaces configured → only the Defender row appears,
    Sentinel handler (if somehow registered) is silently skipped — there's
    no workspace to target."""
    monkeypatch.delenv("PIPELINE_WORKSPACE_NAME", raising=False)
    _patch_for_matrix(monkeypatch, workspaces=[])

    sentinel = _FakeSentinelHandler()
    default_registry.register(Asset.SENTINEL_ANALYTIC, lambda: sentinel)
    default_registry.register(
        Asset.DEFENDER_CUSTOM_DETECTION, lambda: _FakeDefenderHandler(),
    )

    from contentops.devex.doctor import _check_handler_matrix
    results = _check_handler_matrix()

    names = [r.name for r in results]
    assert "handler:defender_custom_detection" in names
    assert not any(n.startswith("handler:sentinel_") for n in names), (
        f"Sentinel handlers should be skipped on a Defender-only tenant; got {names}"
    )
    assert sentinel.seen_workspaces == []
