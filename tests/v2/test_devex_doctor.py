# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for `contentops doctor` (W4-9)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from contentops.cli import cli
from contentops.devex import doctor as doctor_mod
from contentops.devex.doctor import (
    CheckResult,
    aggregate_exit_code,
    format_results,
    run_checks,
)


def _make_repo(tmp_path: Path, *, with_tenant: bool = True) -> Path:
    (tmp_path / "detections").mkdir()
    (tmp_path / "detections" / "sentinel_analytic").mkdir()
    if with_tenant:
        (tmp_path / "config").mkdir()
        (tmp_path / "config" / "tenant.yml").write_text(
            "tenant:\n"
            "  name: test\n"
            "  tenantId: 00000000-0000-0000-0000-000000000000\n"
            "  defender:\n"
            "    enabled: true\n"
            "  sentinelWorkspaces:\n"
            "    - role: prod\n"
            "      subscriptionId: 11111111-1111-1111-1111-111111111111\n"
            "      resourceGroup: rg\n"
            "      workspaceName: ws\n"
            "      location: westeurope\n",
            encoding="utf-8",
        )
    return tmp_path


def test_missing_tenant_yml_warns_not_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A *missing* tenant.yml is WARN (offline / author-only path works
    # without it) so a fresh public-mirror clone running `doctor` exits
    # 0 instead of surfacing a red FAIL. Tenant-touching paths still
    # fail-closed (--auth checks, conformance L2).
    _make_repo(tmp_path, with_tenant=False)
    monkeypatch.chdir(tmp_path)
    # Force the loader to look at the cwd config.
    monkeypatch.setattr(
        "contentops.config.CONFIG_PATH", tmp_path / "config" / "tenant.yml",
    )
    results = run_checks(with_auth=False)
    by_name = {r.name: r for r in results}
    assert by_name["tenant_yml"].status == "WARN"
    assert "not found" in by_name["tenant_yml"].detail
    # WARN-only (plus other PASS/WARN) means a clean exit on a fresh clone.
    assert aggregate_exit_code(results) == 0


def test_malformed_tenant_yml_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A *present-but-broken* tenant.yml is still FAIL — softening the
    # missing case to WARN must not mask a genuinely corrupt config.
    _make_repo(tmp_path, with_tenant=False)
    (tmp_path / "config").mkdir(exist_ok=True)
    # Missing the required top-level `tenant:` key -> ValueError on load.
    (tmp_path / "config" / "tenant.yml").write_text(
        "not_a_tenant_block: true\n", encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        "contentops.config.CONFIG_PATH", tmp_path / "config" / "tenant.yml",
    )
    results = run_checks(with_auth=False)
    by_name = {r.name: r for r in results}
    assert by_name["tenant_yml"].status == "FAIL"
    assert aggregate_exit_code(results) == 1


def test_full_pass_with_env_and_tenant(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _make_repo(tmp_path, with_tenant=True)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        "contentops.config.CONFIG_PATH", tmp_path / "config" / "tenant.yml",
    )
    monkeypatch.setenv("AZURE_TENANT_ID", "x")
    monkeypatch.setenv("AZURE_CLIENT_ID", "y")
    monkeypatch.setenv("AZURE_CLIENT_SECRET", "z")
    results = run_checks(with_auth=False)
    by_name = {r.name: r for r in results}
    assert by_name["tenant_yml"].status == "PASS"
    assert by_name["detections_dir"].status == "PASS"
    assert by_name["detections_parse"].status == "PASS"
    assert by_name["python_version"].status == "PASS"
    assert by_name["python_deps"].status == "PASS"
    assert by_name["auth_env"].status == "PASS"
    # Token acquisition is skipped (WARN) when --auth not passed.
    assert by_name["token_acquisition"].status == "WARN"
    assert "skipped" in by_name["token_acquisition"].detail
    # All-PASS-or-WARN exits 0.
    assert aggregate_exit_code(results) == 0


def test_auth_env_warn_when_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _make_repo(tmp_path, with_tenant=True)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        "contentops.config.CONFIG_PATH", tmp_path / "config" / "tenant.yml",
    )
    monkeypatch.delenv("AZURE_TENANT_ID", raising=False)
    monkeypatch.delenv("AZURE_CLIENT_ID", raising=False)
    monkeypatch.delenv("AZURE_CLIENT_SECRET", raising=False)
    monkeypatch.setattr(doctor_mod, "_az_signed_in", lambda: False)
    results = run_checks(with_auth=False)
    by_name = {r.name: r for r in results}
    # Missing auth env => WARN, never FAIL.
    assert by_name["auth_env"].status == "WARN"


def test_aggregate_exit_code_only_fail_triggers_one() -> None:
    results = [
        CheckResult("a", "PASS"),
        CheckResult("b", "WARN"),
    ]
    assert aggregate_exit_code(results) == 0
    results.append(CheckResult("c", "FAIL"))
    assert aggregate_exit_code(results) == 1


def test_format_results_json_shape() -> None:
    results = [
        CheckResult("a", "PASS", "ok"),
        CheckResult("b", "FAIL", "boom"),
    ]
    out = format_results(results, json_out=True)
    parsed = json.loads(out)
    assert parsed["exit_code"] == 1
    names = {c["name"] for c in parsed["checks"]}
    assert names == {"a", "b"}
    assert all({"name", "status", "detail"} <= set(c.keys()) for c in parsed["checks"])


def test_format_results_text_includes_summary() -> None:
    results = [CheckResult("a", "PASS", "ok"), CheckResult("b", "WARN", "meh")]
    out = format_results(results, json_out=False, color=False)
    assert "[PASS]" in out
    assert "[WARN]" in out
    assert "summary:" in out


def test_with_auth_flag_runs_token_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _make_repo(tmp_path, with_tenant=True)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        "contentops.config.CONFIG_PATH", tmp_path / "config" / "tenant.yml",
    )
    # Force the token check to short-circuit deterministically.
    monkeypatch.setattr(
        doctor_mod, "_check_token_acquisition",
        lambda: CheckResult("token_acquisition", "WARN", "stub"),
    )
    results = run_checks(with_auth=True)
    by_name = {r.name: r for r in results}
    assert by_name["token_acquisition"].detail == "stub"


def test_cli_doctor_command_exit_code(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _make_repo(tmp_path, with_tenant=True)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        "contentops.config.CONFIG_PATH", tmp_path / "config" / "tenant.yml",
    )
    runner = CliRunner()
    result = runner.invoke(cli, ["doctor", "--format", "json"])
    parsed = json.loads(result.output)
    assert "checks" in parsed
    assert "exit_code" in parsed
    # exit_code should reflect aggregate; CLI exits with same value.
    assert result.exit_code == parsed["exit_code"]
