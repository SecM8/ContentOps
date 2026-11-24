# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""The commands that edit a rule file bump its version.

``disable``, ``enable``, ``lock``, ``unlock`` and ``lifecycle promote``
change a rule file but left ``version`` alone, and the version check in
``validate`` refuses a changed file whose version did not change. So every
PR these commands made failed ``validate``, the emergency-disable PR
included: the break-glass path was blocked by its own check until someone
bumped the version by hand. Seen in the lab on a ``contentops lock`` PR.
"""

from __future__ import annotations

import importlib.util
import os
import subprocess
from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner

from contentops.cli import cli

REPO_ROOT = Path(__file__).resolve().parents[2]

_RULE = """\
id: rule-a
version: 1.2.3  # bumped on every change
asset: sentinel_analytic
status: {status}
metadata:
  owner: soc@example.com
payload:
  kind: Scheduled
  displayName: Rule A
  severity: Low
  query: SecurityEvent | take 1
  queryFrequency: PT1H
  queryPeriod: PT1H
  triggerOperator: GreaterThan
  triggerThreshold: 0
"""


def _git(cwd: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(cwd), *args], check=True,
                          capture_output=True, text=True).stdout.strip()


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    _git(tmp_path, "init", "-q", "-b", "main")
    _git(tmp_path, "config", "user.email", "t@example.com")
    _git(tmp_path, "config", "user.name", "t")
    _git(tmp_path, "config", "commit.gpgsign", "false")
    return tmp_path


def _write(repo: Path, status: str = "production") -> Path:
    path = repo / "detections" / "sentinel_analytic" / "rule-a.yml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_RULE.format(status=status), encoding="utf-8")
    return path


def _version(path: Path) -> str:
    return str(yaml.safe_load(path.read_text(encoding="utf-8"))["version"])


def _run(repo: Path, args: list[str]):
    prev = os.getcwd()
    try:
        os.chdir(repo)
        return CliRunner().invoke(cli, args)
    finally:
        os.chdir(prev)


def _version_check(repo: Path, base: str) -> int:
    spec = importlib.util.spec_from_file_location("cvb", REPO_ROOT / "scripts" / "check_version_bump.py")
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    prev = os.getcwd()
    try:
        os.chdir(repo)
        return mod.main(base)
    finally:
        os.chdir(prev)


@pytest.mark.parametrize(("args", "status"), [
    (["disable", "rule-a", "--reason", "noisy", "--path", "detections"], "production"),
    (["enable", "rule-a", "--path", "detections"], "deprecated"),
    (["lock", "rule-a", "--path", "detections"], "production"),
])
def test_the_pr_a_command_makes_passes_the_version_check(repo: Path, args: list[str], status: str) -> None:
    path = _write(repo, status)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "base")
    base = _git(repo, "rev-parse", "HEAD")

    result = _run(repo, args)
    assert result.exit_code == 0, result.output
    assert _version(path) == "1.2.4"
    _git(repo, "add", "detections")
    _git(repo, "commit", "-q", "-m", "change")
    assert _version_check(repo, base) == 0


def test_unlock_bumps_too(repo: Path) -> None:
    path = _write(repo)
    assert _run(repo, ["lock", "rule-a", "--path", "detections"]).exit_code == 0
    assert _run(repo, ["unlock", "rule-a", "--path", "detections"]).exit_code == 0
    assert _version(path) == "1.2.5"


def test_a_command_that_changes_nothing_does_not_bump(repo: Path) -> None:
    path = _write(repo, "deprecated")
    assert _run(repo, ["disable", "rule-a", "--path", "detections"]).exit_code == 0
    assert _version(path) == "1.2.3"


def test_the_version_line_keeps_its_comment_and_quotes() -> None:
    from contentops.utils.version_text import bump_patch_in_text

    assert bump_patch_in_text("id: a\nversion: 1.2.3  # note\n") == "id: a\nversion: 1.2.4  # note\n"
    assert bump_patch_in_text('version: "0.1.9"\n') == 'version: "0.1.10"\n'
    # Only the top-level key; a nested one and a non-semver value are left.
    assert bump_patch_in_text("payload:\n  version: 2\n") == "payload:\n  version: 2\n"
    assert bump_patch_in_text("version: v1\n") == "version: v1\n"


def test_lifecycle_promote_bumps(repo: Path) -> None:
    path = _write(repo, "experimental")
    result = _run(repo, ["lifecycle", "promote", "rule-a", "--path", "detections",
                         "--no-workspace-query", "--force"])
    assert result.exit_code == 0, result.output
    assert "status: production" in path.read_text(encoding="utf-8")
    assert _version(path) == "1.2.4"
