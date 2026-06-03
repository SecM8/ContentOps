# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for `contentops doctor --fix` (F17).

The fixers are deliberately conservative — only `dotenv`,
`detections_dir`, and `python_deps` are safe to autofix. Anything
credential-related or YAML-content-related is OUT of scope. These
tests assert both the happy paths and the explicit "refuse to
mutate" cases.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from click.testing import CliRunner

from contentops.cli import cli
from contentops.devex.doctor import (
    CheckResult,
    FixResult,
    apply_safe_fixes,
)


# ---------------------------------------------------------------------------
# apply_safe_fixes — pure-function unit tests
# ---------------------------------------------------------------------------


def _check(name: str, status: str = "FAIL", detail: str = "") -> CheckResult:
    return CheckResult(name=name, status=status, detail=detail)  # type: ignore[arg-type]


def test_apply_safe_fixes_pass_status_skips_fixer(
    tmp_path: Path, monkeypatch,
) -> None:
    """A fixer never runs against a PASS check."""
    monkeypatch.chdir(tmp_path)
    results = [_check("dotenv", "PASS"), _check("detections_dir", "PASS")]
    out = apply_safe_fixes(results)
    assert out == []


def test_apply_safe_fixes_dotenv_no_example_returns_no_fix(
    tmp_path: Path, monkeypatch,
) -> None:
    """No .env.example present → dotenv fixer reports 'no fix' without writing."""
    monkeypatch.chdir(tmp_path)
    out = apply_safe_fixes([_check("dotenv", "WARN")])
    assert len(out) == 1
    assert out[0].name == "dotenv"
    assert out[0].applied is False
    assert "not present" in out[0].action


def test_apply_safe_fixes_dotenv_copies_example(
    tmp_path: Path, monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    Path(".env.example").write_text(
        "AZURE_TENANT_ID=replace-me\n", encoding="utf-8",
    )
    assert not Path(".env").exists()
    out = apply_safe_fixes([_check("dotenv", "WARN")])
    assert out[0].applied is True
    assert "copied" in out[0].action
    assert Path(".env").read_text(encoding="utf-8") == "AZURE_TENANT_ID=replace-me\n"


def test_apply_safe_fixes_dotenv_dry_run_does_not_write(
    tmp_path: Path, monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    Path(".env.example").write_text("X=y\n", encoding="utf-8")
    out = apply_safe_fixes([_check("dotenv", "WARN")], dry_run=True)
    assert out[0].applied is False
    assert not Path(".env").exists()


def test_apply_safe_fixes_dotenv_already_present_is_noop(
    tmp_path: Path, monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    Path(".env").write_text("ORIGINAL=1\n", encoding="utf-8")
    Path(".env.example").write_text("DIFFERENT=1\n", encoding="utf-8")
    out = apply_safe_fixes([_check("dotenv", "WARN")])
    assert out[0].applied is False
    # .env still has its original content — fixer must not overwrite.
    assert "ORIGINAL=1" in Path(".env").read_text(encoding="utf-8")


def test_apply_safe_fixes_detections_dir_creates_canonical_subdirs(
    tmp_path: Path, monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    out = apply_safe_fixes([_check("detections_dir", "FAIL")])
    assert out[0].applied is True
    # Real taxonomy dirs — NOT the historical sentinel/defender folders.
    assert Path("detections/sentinel_analytic").is_dir()
    assert Path("detections/defender_custom_detection").is_dir()
    assert not Path("detections/sentinel").is_dir()
    assert not Path("detections/defender").is_dir()


def test_apply_safe_fixes_detections_dir_already_present_is_noop(
    tmp_path: Path, monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    Path("detections").mkdir()
    out = apply_safe_fixes([_check("detections_dir", "PASS")])
    # PASS skips entirely (no fix attempted).
    assert out == []


def test_apply_safe_fixes_does_not_touch_credential_or_config_checks() -> None:
    """auth_env / tenant_yml / detections_parse are NOT in the whitelist."""
    out = apply_safe_fixes([
        _check("auth_env", "FAIL"),
        _check("tenant_yml", "FAIL"),
        _check("detections_parse", "FAIL"),
    ])
    # None of these are whitelisted, so no fixers run.
    assert out == []


def test_apply_safe_fixes_python_deps_whitelisted_but_safe(
    tmp_path: Path, monkeypatch,
) -> None:
    """python_deps IS dispatched (whitelisted), but with no pyproject.toml
    in cwd it refuses to run pip — proving the dispatch wiring without
    mutating the environment."""
    monkeypatch.chdir(tmp_path)  # no pyproject.toml here
    out = apply_safe_fixes([_check("python_deps", "FAIL")])
    assert len(out) == 1
    assert out[0].name == "python_deps"
    assert out[0].applied is False
    assert "pyproject.toml not found" in out[0].action


# ---------------------------------------------------------------------------
# CLI integration
# ---------------------------------------------------------------------------


def test_cli_doctor_fix_dry_run(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    Path(".env.example").write_text("X=y\n", encoding="utf-8")
    # No detections/ dir, no .env file — both fixers should fire in dry-run.
    runner = CliRunner()
    result = runner.invoke(cli, ["doctor", "--fix", "--dry-run"])
    # Dry-run still reports failures (since they're not mutated).
    # Verify: the output references the would-fix actions.
    combined = result.output
    assert "would" in combined or "[fix]" in combined or "[dry-run]" in combined
    # Crucially: no mutation.
    assert not Path(".env").exists()


def test_cli_doctor_fix_real_creates_detections_dirs(
    tmp_path: Path, monkeypatch,
) -> None:
    """detections_dir fix runs reliably from any cwd because detections/
    is checked relative to cwd. The dotenv fix is environmentally
    dependent (find_dotenv walks upward) so we don't assert it from
    the CLI; the unit tests above cover its behaviour."""
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()
    result = runner.invoke(cli, ["doctor", "--fix"])
    assert Path("detections/sentinel_analytic").is_dir()
    assert Path("detections/defender_custom_detection").is_dir()
    # The output mentions the fix.
    assert "fix" in result.output.lower() or "[fix]" in result.output


def test_cli_doctor_no_fix_flag_is_passive(
    tmp_path: Path, monkeypatch,
) -> None:
    """Without --fix, doctor never mutates disk."""
    monkeypatch.chdir(tmp_path)
    Path(".env.example").write_text("X=y\n", encoding="utf-8")
    runner = CliRunner()
    runner.invoke(cli, ["doctor"])
    assert not Path(".env").exists()
    assert not Path("detections").exists()


# ---------------------------------------------------------------------------
# python_deps fixer — mutates the environment, so it's mocked here
# ---------------------------------------------------------------------------


def test_fix_python_deps_no_pyproject_is_no_fix(
    tmp_path: Path, monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)  # no pyproject.toml
    from contentops.devex.doctor import _fix_python_deps

    out = _fix_python_deps(dry_run=False)
    assert out.applied is False
    assert "pyproject.toml not found" in out.action


def test_fix_python_deps_dry_run_does_not_run_pip(
    tmp_path: Path, monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    Path("pyproject.toml").write_text("[project]\nname = 'x'\n", encoding="utf-8")

    def _boom(*a, **k):  # pragma: no cover — must never be called
        raise AssertionError("pip must not run in --dry-run")

    monkeypatch.setattr("subprocess.run", _boom)
    from contentops.devex.doctor import _fix_python_deps

    out = _fix_python_deps(dry_run=True)
    assert out.applied is False
    assert "would run" in out.action
    assert "pip install -e .[dev]" in out.action


def test_fix_python_deps_runs_pip_and_reports_success(
    tmp_path: Path, monkeypatch,
) -> None:
    import sys

    monkeypatch.chdir(tmp_path)
    Path("pyproject.toml").write_text("[project]\nname = 'x'\n", encoding="utf-8")

    calls: list = []

    class _Proc:
        returncode = 0
        stdout = "Successfully installed"
        stderr = ""

    def _fake_run(cmd, **kwargs):
        calls.append(cmd)
        return _Proc()

    monkeypatch.setattr("subprocess.run", _fake_run)
    from contentops.devex.doctor import _fix_python_deps

    out = _fix_python_deps(dry_run=False)
    assert out.applied is True
    assert calls and calls[0][:4] == [sys.executable, "-m", "pip", "install"]


def test_fix_python_deps_reports_pip_failure(
    tmp_path: Path, monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    Path("pyproject.toml").write_text("[project]\nname = 'x'\n", encoding="utf-8")

    class _Proc:
        returncode = 1
        stdout = ""
        stderr = "ERROR: could not resolve dependency boom\n"

    monkeypatch.setattr("subprocess.run", lambda *a, **k: _Proc())
    from contentops.devex.doctor import _fix_python_deps

    out = _fix_python_deps(dry_run=False)
    assert out.applied is False
    assert "failed" in out.action
    assert "boom" in out.detail
