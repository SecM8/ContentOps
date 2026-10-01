# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""``contentops status`` reads the per-env state file by default.

Regression for "every asset shows unmanaged": apply / ``state sync
pull`` write ``state/<env>/state.json`` (``<env>`` = tenant.yml's
``name``), but a flag-less ``status deployments`` / ``status all``
read the env-less ``state/state.json``, which nothing writes. The
status commands now default ``--env`` the same way ``state sync`` does.

The v2 conftest chdirs every test into its own ``tmp_path``.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner

from contentops.cli import cli
from contentops.cli.commands import status as status_mod
from contentops.state import EnvState, save_state

ENV = "contoso-prod"


def _write_envelope(envelope_id: str) -> None:
    d = Path("detections") / "sentinel_analytic"
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{envelope_id}.yml").write_text(yaml.safe_dump({
        "id": envelope_id,
        "version": "0.1.0",
        "asset": "sentinel_analytic",
        "status": "production",
        "legacy": True,
        "payload": {
            "kind": "Scheduled",
            "displayName": envelope_id,
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


def _save(env: str | None, envelope_id: str) -> None:
    state = EnvState(env=env or "")
    state.remember("sentinel_analytic", envelope_id, sha="abc12345")
    save_state(state)


@pytest.fixture
def tenant_env(monkeypatch: pytest.MonkeyPatch) -> str:
    """Pretend tenant.yml's ``name`` is ENV (same seam as ``state sync``)."""
    monkeypatch.setattr(
        "contentops.cli.commands.state._state_env_default", lambda: ENV,
    )
    return ENV


def _deployments(*extra: str) -> str:
    result = CliRunner().invoke(
        cli, ["status", "deployments", "--out", "-", *extra],
    )
    assert result.exit_code == 0, result.output
    return result.output


def test_defaults_to_tenant_env_state_file(tenant_env: str) -> None:
    _write_envelope("rule-a")
    _save(ENV, "rule-a")

    out = _deployments()

    assert f"**Env:** `{ENV}`" in out
    assert "1 in-sync" in out
    assert "0 unmanaged" in out


def test_explicit_env_wins_over_tenant_default(tenant_env: str) -> None:
    _write_envelope("rule-a")
    _save(ENV, "rule-a")
    _save("other", "rule-z")

    out = _deployments("--env", "other")

    assert "`other`" in out
    assert "1 unmanaged" in out  # rule-a is not in the "other" state
    assert "1 orphan" in out     # rule-z is in state but not in git


def test_falls_back_to_legacy_file_when_env_file_absent(tenant_env: str) -> None:
    """An old local clone with only state/state.json keeps working."""
    _write_envelope("rule-a")
    _save(None, "rule-a")

    out = _deployments()

    assert "1 in-sync" in out


def test_env_file_preferred_over_legacy_file(tenant_env: str) -> None:
    _write_envelope("rule-a")
    _write_envelope("rule-b")
    _save(None, "rule-a")
    _save(ENV, "rule-b")

    state = status_mod._load_status_state(None)

    assert state.env == ENV
    assert set(state.managed_assets["sentinel_analytic"]) == {"rule-b"}


def test_no_tenant_yml_reads_legacy_path(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "contentops.cli.commands.state._state_env_default", lambda: "",
    )
    _save(None, "rule-a")

    state = status_mod._load_status_state(None)

    assert state.is_managed("sentinel_analytic", "rule-a")


def test_status_all_uses_tenant_env(tenant_env: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """``status all`` (what status-refresh.yml runs, with no --env) must
    read the env-scoped file too."""
    _write_envelope("rule-a")
    _save(ENV, "rule-a")
    # Skip the conformance page -- this test is about the state file.
    monkeypatch.setattr(status_mod, "run_conformance", lambda **_: None)
    monkeypatch.setattr(status_mod, "render_configuration", lambda _r: "x\n")

    result = CliRunner().invoke(cli, ["status", "all"])

    assert result.exit_code == 0, result.output
    page = Path("docs/status/deployments.md").read_text(encoding="utf-8")
    assert "1 in-sync" in page
    assert "0 unmanaged" in page


def test_tenant_yml_name_drives_default(monkeypatch: pytest.MonkeyPatch) -> None:
    """End-to-end through the real ``load_tenant_config`` seam."""
    class _Cfg:
        name = ENV

    monkeypatch.setattr("contentops.config.load_tenant_config", lambda *a, **k: _Cfg())
    _save(ENV, "rule-a")

    state = status_mod._load_status_state(None)

    assert state.env == ENV
    assert state.is_managed("sentinel_analytic", "rule-a")


def test_undeployed_rules_defaults_to_tenant_env_state_file(tenant_env: str) -> None:
    """Same bug as the status page: `undeployed-rules` without --env read
    state/state.json, so every rule looked undeployed."""
    _write_envelope("rule-a")
    _write_envelope("rule-b")
    _save(ENV, "rule-a")
    result = CliRunner().invoke(
        cli, ["undeployed-rules", "--path", "detections", "--format", "json"],
    )
    assert result.exit_code == 0, result.output
    assert "rule-b" in result.output
    assert "rule-a" not in result.output
