# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for the changed-since git-diff helper."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from contentops.utils.git_diff import GitDiffError, changed_paths


def _run(args: list[str], cwd: Path) -> None:
    subprocess.run(args, cwd=cwd, check=True, capture_output=True)


def _init_repo(tmp_path: Path) -> Path:
    """Bootstrap a tiny repo with one initial commit on `main`."""
    if shutil.which("git") is None:
        pytest.skip("git not available on PATH")
    repo = tmp_path / "repo"
    repo.mkdir()
    _run(["git", "init", "-q", "-b", "main"], repo)
    _run(["git", "config", "user.email", "t@example.com"], repo)
    _run(["git", "config", "user.name", "test"], repo)
    _run(["git", "config", "commit.gpgsign", "false"], repo)
    (repo / "base.txt").write_text("seed")
    _run(["git", "add", "."], repo)
    _run(["git", "commit", "-q", "-m", "seed"], repo)
    return repo


def test_unchanged_repo_returns_empty(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path)
    assert changed_paths("HEAD", repo=repo) == set()


def test_committed_change_is_detected(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path)
    _run(["git", "checkout", "-q", "-b", "feat"], repo)
    (repo / "new.yml").write_text("x: 1")
    _run(["git", "add", "."], repo)
    _run(["git", "commit", "-q", "-m", "add"], repo)

    diff = changed_paths("main", repo=repo)
    assert (repo / "new.yml").resolve() in diff


def test_unstaged_change_is_detected(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path)
    (repo / "base.txt").write_text("changed")
    diff = changed_paths("HEAD", repo=repo)
    assert (repo / "base.txt").resolve() in diff


def test_untracked_file_is_detected(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path)
    (repo / "untracked.yml").write_text("y: 1")
    diff = changed_paths("HEAD", repo=repo)
    assert (repo / "untracked.yml").resolve() in diff


def test_unknown_ref_raises(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path)
    with pytest.raises(GitDiffError):
        changed_paths("does-not-exist", repo=repo)
