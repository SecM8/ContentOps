# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for scripts/check_mitre_ids.py.

Sentinel rejects an analytic rule whose ``techniques`` hold anything but
parent technique ids ("The technique 'T1003.001' is invalid. The
expected format is 'T####'"). ``plan`` does not see that, so the rule is
merged and then fails at deploy. The script checks the ids of the rules
a pull request adds or changes, before the merge.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

SCRIPTS_DIR = Path(__file__).resolve().parents[2] / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

import check_mitre_ids as cmi  # noqa: E402


def _rule(techniques: str, sub_techniques: str = "[]", asset: str = "sentinel_analytic") -> str:
    return (
        "id: my-rule\n"
        "version: 1.0.0\n"
        f"asset: {asset}\n"
        "status: production\n"
        "payload:\n"
        "  displayName: My Rule\n"
        "  tactics: [CredentialAccess]\n"
        f"  techniques: {techniques}\n"
        f"  subTechniques: {sub_techniques}\n"
    )


def test_parent_ids_and_sub_technique_ids_in_their_own_lists_pass() -> None:
    assert cmi.problems(_rule("[T1003, T1053]", "[T1003.001, T1053.005]")) == []


def test_empty_and_missing_lists_pass() -> None:
    assert cmi.problems(_rule("[]")) == []
    assert cmi.problems("id: x\nasset: sentinel_analytic\npayload:\n  displayName: X\n") == []


def test_a_sub_technique_id_under_techniques_is_a_problem() -> None:
    found = cmi.problems(_rule("[T1003.001, T1059]"))
    assert found == ["techniques: 'T1003.001' is not a technique id (expected T####)"]


@pytest.mark.parametrize("bad", ["T1003", "T1003.1", "1003.001", "T1003.0011", "t1003.001"])
def test_a_wrong_id_under_sub_techniques_is_a_problem(bad: str) -> None:
    found = cmi.problems(_rule("[T1003]", f"['{bad}']"))
    assert found == [f"subTechniques: '{bad}' is not a sub-technique id (expected T####.###)"]


@pytest.mark.parametrize("bad", ["T10033", "TA0006", "T100", " T1003", "T1003\n"])
def test_a_malformed_technique_id_is_a_problem(bad: str) -> None:
    text = _rule("[placeholder]").replace("[placeholder]", repr([bad]))
    assert len(cmi.problems(text)) == 1


def test_only_sentinel_analytic_rules_are_checked() -> None:
    """Defender rules keep their ids under ``tactics``; other kinds have
    no such list. A file that cannot be parsed is another check's job."""
    assert cmi.problems(_rule("[T1003.001]", asset="defender_custom_detection")) == []
    assert cmi.problems("not: [valid") == []
    assert cmi.problems("- just\n- a list\n") == []


def test_a_sub_technique_without_its_parent_is_noted_not_failed() -> None:
    """Every rule the tenant returns lists the parent next to its
    sub-technique, but nothing documents that the service requires it."""
    text = _rule("[T1059]", "[T1003.001]")
    assert cmi.problems(text) == []
    assert cmi.notes(text) == ["subTechniques: 'T1003.001' is listed without its parent T1003 under techniques"]


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True)


@pytest.fixture
def repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    _git(tmp_path, "init", "-q", "-b", "main")
    _git(tmp_path, "config", "user.email", "t@example.com")
    _git(tmp_path, "config", "user.name", "t")
    _git(tmp_path, "config", "commit.gpgsign", "false")
    rules = tmp_path / "detections" / "sentinel_analytic"
    rules.mkdir(parents=True)
    (rules / "old-bad.yml").write_text(_rule("[T1003.001]"), encoding="utf-8")
    (rules / "edited.yml").write_text(_rule("[T1003]"), encoding="utf-8")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-q", "-m", "base")
    _git(tmp_path, "checkout", "-q", "-b", "work")
    monkeypatch.chdir(tmp_path)
    return tmp_path


def test_main_checks_added_and_changed_rules_only(repo: Path, capsys: pytest.CaptureFixture) -> None:
    """A rule that was already wrong on the base branch must not fail
    every other pull request; one this pull request adds or edits must."""
    rules = repo / "detections" / "sentinel_analytic"
    assert cmi.main("main") == 0  # nothing changed; the old bad file is not this PR's

    (rules / "edited.yml").write_text(_rule("[T1003, T1053.005]"), encoding="utf-8")
    (rules / "added.yml").write_text(_rule("[T1558.003]"), encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "change")
    assert cmi.main("main") == 1
    err = capsys.readouterr().err
    assert "edited.yml" in err and "added.yml" in err
    assert "old-bad.yml" not in err


def test_main_passes_when_the_change_fixes_the_ids(repo: Path) -> None:
    rules = repo / "detections" / "sentinel_analytic"
    (rules / "old-bad.yml").write_text(_rule("[T1003]", "[T1003.001]"), encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "fix")
    assert cmi.main("main") == 0


def test_main_reports_a_git_failure_as_exit_2(repo: Path) -> None:
    assert cmi.main("no-such-ref") == 2
