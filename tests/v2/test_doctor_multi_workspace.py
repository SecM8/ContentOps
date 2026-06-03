# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Test for the doctor --matrix multi-workspace noise reduction (task #29).

Adopter test on 2026-05-18: a tenant.yml with 2 Sentinel workspaces
caused doctor --matrix to emit 25+ duplicate "Tenant has 2 Sentinel
workspaces; specify --role or --workspace" lines that drowned out the
real signals (auth failure, RBAC gap).

Fix: when no workspace is pinned via --role/--workspace, the matrix
picks the role=prod workspace (or the first listed if no prod role)
and emits ONE info line stating which was tested. Avoids the per-
handler duplicate.

This test verifies the workspace-picking logic via the public
_check_handler_matrix() function with a 2-workspace tenant config.
"""

from __future__ import annotations

from unittest.mock import patch


def _mock_workspace(name: str, role: str) -> object:
    """Minimal duck-typed workspace object matching what _check_handler_matrix reads."""
    return type("WS", (), {"workspaceName": name, "role": role})()


def test_multi_workspace_picks_prod_and_emits_one_note(monkeypatch) -> None:
    """Two workspaces (one prod, one integration), no env pin →
    matrix picks the prod workspace and emits exactly one info note
    in results."""
    monkeypatch.delenv("PIPELINE_WORKSPACE_NAME", raising=False)

    cfg = type("Cfg", (), {
        "sentinelWorkspaces": [
            _mock_workspace("law-int", "integration"),
            _mock_workspace("law-prod", "prod"),
        ],
    })()

    from contentops.devex import doctor

    with patch("contentops.config.load_tenant_config", return_value=cfg), \
         patch("contentops.cli.handler_factories.register_default_handlers"), \
         patch("contentops.core.registry.default_registry") as reg:
        reg.assets.return_value = []  # No handlers to actually invoke.
        results = doctor._check_handler_matrix()

    notes = [r for r in results if r.name == "handler_matrix_workspace"]
    assert len(notes) == 1, (
        f"expected exactly one workspace pick note, got {len(notes)}: "
        f"{[r.detail for r in notes]}"
    )
    assert "law-prod" in notes[0].detail
    assert "role='prod'" in notes[0].detail or "prod" in notes[0].detail


def test_single_workspace_no_pick_note(monkeypatch) -> None:
    """Only one workspace configured → no auto-pick note (would be noise)."""
    monkeypatch.delenv("PIPELINE_WORKSPACE_NAME", raising=False)

    cfg = type("Cfg", (), {
        "sentinelWorkspaces": [_mock_workspace("law-only", "prod")],
    })()

    from contentops.devex import doctor

    with patch("contentops.config.load_tenant_config", return_value=cfg), \
         patch("contentops.cli.handler_factories.register_default_handlers"), \
         patch("contentops.core.registry.default_registry") as reg:
        reg.assets.return_value = []
        results = doctor._check_handler_matrix()

    notes = [r for r in results if r.name == "handler_matrix_workspace"]
    assert notes == [], (
        f"single-workspace tenant should not emit the pick note: "
        f"{[r.detail for r in notes]}"
    )


def test_pinned_workspace_overrides_auto_pick(monkeypatch) -> None:
    """When PIPELINE_WORKSPACE_NAME is set (e.g. --role /
    --workspace was passed), no auto-pick note is emitted — the
    operator already chose."""
    monkeypatch.setenv("PIPELINE_WORKSPACE_NAME", "law-int")

    cfg = type("Cfg", (), {
        "sentinelWorkspaces": [
            _mock_workspace("law-int", "integration"),
            _mock_workspace("law-prod", "prod"),
        ],
    })()

    from contentops.devex import doctor

    with patch("contentops.config.load_tenant_config", return_value=cfg), \
         patch("contentops.cli.handler_factories.register_default_handlers"), \
         patch("contentops.core.registry.default_registry") as reg:
        reg.assets.return_value = []
        results = doctor._check_handler_matrix()

    notes = [r for r in results if r.name == "handler_matrix_workspace"]
    assert notes == []
