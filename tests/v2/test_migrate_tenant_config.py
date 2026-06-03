# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for the legacy → v3 tenant-config migrator.

(``scripts/migrate_tenant_config.py`` — DESIGN §6).
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from textwrap import dedent

import yaml

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "migrate_tenant_config.py"


def _run(path: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), str(path), *args],
        capture_output=True, text=True, check=False,
    )


def test_migrates_legacy_single_workspace(tmp_path: Path) -> None:
    src = tmp_path / "tenant.yml"
    src.write_text(dedent("""
        tenant:
          name: production
          tenantId: aad-guid
          sentinel:
            subscriptionId: sub-1
            resourceGroup: rg-1
            workspaceName: ws-1
            location: westeurope
          defender:
            enabled: true
    """).lstrip())

    result = _run(src)
    assert result.returncode == 0, result.stderr

    new = yaml.safe_load(src.read_text())["tenant"]
    assert "sentinel" not in new
    assert new["sentinelWorkspaces"] == [{
        "role": "prod",
        "subscriptionId": "sub-1",
        "resourceGroup": "rg-1",
        "workspaceName": "ws-1",
        "location": "westeurope",
    }]
    assert new["defender"] == {"enabled": True}


def test_dry_run_does_not_write(tmp_path: Path) -> None:
    src = tmp_path / "tenant.yml"
    original = dedent("""
        tenant:
          name: production
          tenantId: aad-guid
          sentinel:
            subscriptionId: sub-1
            resourceGroup: rg-1
            workspaceName: ws-1
            location: westeurope
    """).lstrip()
    src.write_text(original)

    result = _run(src, "--dry-run")
    assert result.returncode == 0
    # File on disk unchanged.
    assert src.read_text() == original
    # New shape printed to stdout.
    assert "sentinelWorkspaces" in result.stdout


def test_idempotent_on_already_migrated_file(tmp_path: Path) -> None:
    src = tmp_path / "tenant.yml"
    src.write_text(dedent("""
        tenant:
          name: production
          tenantId: aad-guid
          defender:
            enabled: true
          sentinelWorkspaces:
            - role: prod
              subscriptionId: sub-1
              resourceGroup: rg-1
              workspaceName: ws-1
              location: westeurope
    """).lstrip())
    before = src.read_text()
    result = _run(src)
    assert result.returncode == 0
    # File on disk unchanged.
    assert src.read_text() == before
    assert "already in v3 shape" in result.stderr


def test_handles_tenant_without_sentinel_block(tmp_path: Path) -> None:
    """Defender-only tenants (no `sentinel:` block) are already valid v3.

    The migrator treats them as already-migrated (no rewrite needed);
    the loader's schema defaults ``sentinelWorkspaces`` to ``[]``.
    """
    src = tmp_path / "tenant.yml"
    src.write_text(dedent("""
        tenant:
          name: defender-only
          tenantId: aad-guid
          defender:
            enabled: true
    """).lstrip())
    result = _run(src)
    assert result.returncode == 0
    assert "already in v3 shape" in result.stderr

    # And the loader is happy with the resulting shape.
    from contentops.config import load_tenant_config
    cfg = load_tenant_config(path=src)
    assert cfg.sentinelWorkspaces == []
    assert cfg.defender is not None
    assert cfg.defender.enabled is True
