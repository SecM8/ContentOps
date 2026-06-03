# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for the tenant.yml ``writeAllowed`` safeguard on ``contentops apply``.

The safeguard is the fourth physical brake on destructive ops
(after ``workflow_dispatch``, the workflow's CONFIRM input, and the
GitHub Environment reviewer gate). It must fail-closed BEFORE any
handler registration or Azure connection — a denied workspace
should never open a single API call.

Three semantic contracts pinned here:

* A workspace with ``writeAllowed: false`` refuses apply with a
  clear error naming the offending workspace.
* ``--dry-run`` bypasses the gate so operators can preview an
  apply against a write-locked env.
* The Defender XDR ``writeAllowed`` is checked independently and
  only when the apply would touch Defender content (``--asset``
  unset or names a ``defender_*`` kind).
"""

from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner

from contentops.cli import cli
from contentops.core.registry import default_registry


def _synthetic_tenant_config(
    *,
    sentinel_write_allowed: bool = True,
    defender_block: bool = False,
    defender_write_allowed: bool = True,
):
    from contentops.config import (
        DefenderConfig,
        SentinelWorkspaceConfig,
        TenantConfig,
    )
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
                role="prod",
                subscriptionId="sub-1", resourceGroup="rg-1",
                workspaceName="ws-prod",
                writeAllowed=sentinel_write_allowed,
            ),
        ],
    )


@pytest.fixture(autouse=True)
def _clean_registry():
    saved_factories = dict(default_registry._factories)
    saved_instances = dict(default_registry._instances)
    default_registry._factories.clear()
    default_registry._instances.clear()
    yield
    default_registry._factories.clear()
    default_registry._instances.clear()
    default_registry._factories.update(saved_factories)
    default_registry._instances.update(saved_instances)


def test_apply_refuses_when_write_not_allowed(
    tmp_path: Path, monkeypatch,
) -> None:
    detections = tmp_path / "detections"
    detections.mkdir()
    cfg = _synthetic_tenant_config(sentinel_write_allowed=False)
    monkeypatch.setattr(
        "contentops.config.load_tenant_config",
        lambda *_a, **_kw: cfg,
    )

    result = CliRunner().invoke(
        cli, ["apply", "--path", str(detections), "--role", "prod"],
    )
    assert result.exit_code == 2, result.output
    assert "writeAllowed=False" in result.output
    assert "ws-prod" in result.output


def test_apply_dry_run_bypasses_write_gate(
    tmp_path: Path, monkeypatch,
) -> None:
    """Dry-run must let the operator preview against a write-locked
    workspace. Without this, the safeguard would make it impossible
    to even REVIEW what an apply would do, which is the opposite of
    the intended user experience."""
    detections = tmp_path / "detections"
    detections.mkdir()
    cfg = _synthetic_tenant_config(sentinel_write_allowed=False)
    monkeypatch.setattr(
        "contentops.config.load_tenant_config",
        lambda *_a, **_kw: cfg,
    )

    result = CliRunner().invoke(
        cli, ["apply", "--path", str(detections),
              "--role", "prod", "--dry-run"],
    )
    # Either succeeds (no envelopes -> no-op) or exits with a
    # non-safeguard reason; the safeguard refusal text must not appear.
    assert "writeAllowed=False" not in result.output


def test_apply_allowed_when_write_true(
    tmp_path: Path, monkeypatch,
) -> None:
    detections = tmp_path / "detections"
    detections.mkdir()
    cfg = _synthetic_tenant_config(sentinel_write_allowed=True)
    monkeypatch.setattr(
        "contentops.config.load_tenant_config",
        lambda *_a, **_kw: cfg,
    )

    result = CliRunner().invoke(
        cli, ["apply", "--path", str(detections), "--role", "prod"],
    )
    # Apply proceeds past the gate. Exit code depends on downstream
    # state (empty detections -> usually 0); the safeguard must not
    # fire.
    assert "writeAllowed=False" not in result.output


def test_apply_defender_safeguard_blocks_when_unfiltered(
    tmp_path: Path, monkeypatch,
) -> None:
    """No ``--asset`` filter → defender is in-scope → its writeAllowed
    is checked. With defender_write_allowed=False, the apply refuses
    even though the Sentinel workspace is writable."""
    detections = tmp_path / "detections"
    detections.mkdir()
    cfg = _synthetic_tenant_config(
        sentinel_write_allowed=True,
        defender_block=True,
        defender_write_allowed=False,
    )
    monkeypatch.setattr(
        "contentops.config.load_tenant_config",
        lambda *_a, **_kw: cfg,
    )

    result = CliRunner().invoke(
        cli, ["apply", "--path", str(detections), "--role", "prod"],
    )
    assert result.exit_code == 2, result.output
    assert "Defender XDR" in result.output
    assert "writeAllowed=False" in result.output


def test_apply_defender_safeguard_skipped_when_sentinel_only(
    tmp_path: Path, monkeypatch,
) -> None:
    """``--asset sentinel_analytic`` → defender is out-of-scope → its
    safeguard is NOT consulted. The locked Defender block does not
    block a Sentinel-only apply."""
    detections = tmp_path / "detections"
    detections.mkdir()
    cfg = _synthetic_tenant_config(
        sentinel_write_allowed=True,
        defender_block=True,
        defender_write_allowed=False,
    )
    monkeypatch.setattr(
        "contentops.config.load_tenant_config",
        lambda *_a, **_kw: cfg,
    )

    result = CliRunner().invoke(
        cli, ["apply", "--path", str(detections),
              "--role", "prod",
              "--asset", "sentinel_analytic"],
    )
    # The Defender refusal text must NOT appear when the apply scope
    # is filtered to a Sentinel asset kind.
    assert "Defender XDR" not in result.output
