# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for multi-env tenant config resolution."""

from __future__ import annotations

from pathlib import Path
from textwrap import dedent

import pytest

from contentops.config import load_tenant_config, resolve_config_path


def _write(p: Path, name: str) -> None:
    p.write_text(dedent(f"""
        tenant:
          name: {name}
          tenantId: "00000000-0000-0000-0000-000000000000"
          defender:
            enabled: true
          sentinelWorkspaces:
            - role: prod
              subscriptionId: "11111111-1111-1111-1111-111111111111"
              resourceGroup: rg
              workspaceName: ws
              location: westeurope
    """).lstrip())


def test_resolve_default_when_no_env(monkeypatch: pytest.MonkeyPatch) -> None:
    import contentops.config as config

    monkeypatch.delenv("PIPELINE_ENV", raising=False)
    # With no env, resolution returns the configured default path
    # (CONFIG_PATH) — assert against the module global rather than a
    # hardcoded filename so the test is robust to the v2 conftest's
    # isolation redirect of CONFIG_PATH.
    assert resolve_config_path() == config.CONFIG_PATH


def test_resolve_uses_pipeline_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PIPELINE_ENV", "dev")
    assert resolve_config_path().name == "tenant.dev.yml"


def test_explicit_env_overrides_pipeline_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PIPELINE_ENV", "dev")
    assert resolve_config_path("prod").name == "tenant.prod.yml"


def test_load_picks_up_env_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cfg_dir = tmp_path / "config"
    cfg_dir.mkdir()
    _write(cfg_dir / "tenant.yml", "default")
    _write(cfg_dir / "tenant.dev.yml", "dev-tenant")

    monkeypatch.setattr("contentops.config.CONFIG_DIR", cfg_dir)
    monkeypatch.setattr("contentops.config.CONFIG_PATH", cfg_dir / "tenant.yml")

    monkeypatch.delenv("PIPELINE_ENV", raising=False)
    assert load_tenant_config().name == "default"

    monkeypatch.setenv("PIPELINE_ENV", "dev")
    assert load_tenant_config().name == "dev-tenant"


def test_explicit_path_wins(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cfg_dir = tmp_path / "config"
    cfg_dir.mkdir()
    _write(cfg_dir / "tenant.yml", "default")
    _write(cfg_dir / "tenant.staging.yml", "staging")
    monkeypatch.setenv("PIPELINE_ENV", "dev")  # would point at a missing file

    cfg = load_tenant_config(path=cfg_dir / "tenant.staging.yml")
    assert cfg.name == "staging"


def test_load_falls_back_to_base_when_env_file_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Single-tenant.yml model: PIPELINE_ENV selects tenant.<env>.yml, but
    operators who keep ONE role-tagged tenant.yml have no per-env file —
    load must fall back to the base tenant.yml instead of raising. This is
    what unblocks prune / rollback (which set PIPELINE_ENV=<env>) on a
    single-file tenant."""
    cfg_dir = tmp_path / "config"
    cfg_dir.mkdir()
    _write(cfg_dir / "tenant.yml", "single-file")
    # NOTE: no tenant.prod.yml written.
    monkeypatch.setattr("contentops.config.CONFIG_DIR", cfg_dir)
    monkeypatch.setattr("contentops.config.CONFIG_PATH", cfg_dir / "tenant.yml")
    monkeypatch.setenv("PIPELINE_ENV", "prod")
    assert load_tenant_config().name == "single-file"


def test_load_still_raises_when_neither_env_nor_base_exists(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The fallback must not paper over a genuinely absent config: with no
    tenant.<env>.yml AND no base tenant.yml, load still raises."""
    cfg_dir = tmp_path / "config"
    cfg_dir.mkdir()
    monkeypatch.setattr("contentops.config.CONFIG_DIR", cfg_dir)
    monkeypatch.setattr("contentops.config.CONFIG_PATH", cfg_dir / "tenant.yml")
    monkeypatch.setenv("PIPELINE_ENV", "prod")
    with pytest.raises(FileNotFoundError):
        load_tenant_config()
