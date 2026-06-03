# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for `contentops state sync push|pull|status` (F19).

Uses real git plumbing in a temp repo so we exercise the full
hash-object/mktree/commit-tree/update-ref chain.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from contentops.state_sync import (
    PullResult,
    PushResult,
    StateSyncError,
    StatusResult,
    pull,
    push,
    status,
)


# ---------------------------------------------------------------------------
# git repo fixture
# ---------------------------------------------------------------------------


def _git(cwd: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(cwd), *args],
        capture_output=True, text=True, check=True,
    )
    return result.stdout.strip()


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    _git(tmp_path, "init", "-q", "-b", "main")
    _git(tmp_path, "config", "user.email", "test@example.com")
    _git(tmp_path, "config", "user.name", "test")
    _git(tmp_path, "config", "commit.gpgsign", "false")
    # Initial commit so HEAD exists.
    (tmp_path / "README.md").write_text("init\n", encoding="utf-8")
    _git(tmp_path, "add", "README.md")
    _git(tmp_path, "commit", "-q", "-m", "init")
    return tmp_path


# ---------------------------------------------------------------------------
# push (local-only — no real remote)
# ---------------------------------------------------------------------------


def test_push_creates_local_ref_and_returns_commit_sha(repo: Path) -> None:
    state_file = repo / "state" / "state.json"
    state_file.parent.mkdir(parents=True)
    state_file.write_text(json.dumps({"env": "production"}), encoding="utf-8")

    result = push("production", state_file, repo=repo, push_remote=False)
    assert isinstance(result, PushResult)
    assert result.ref == "refs/heads/state/production"
    assert len(result.commit_sha) == 40
    assert result.pushed_remote is False

    # Local ref should now resolve.
    sha = _git(repo, "rev-parse", result.ref)
    assert sha == result.commit_sha


def test_push_sanitises_env_name(repo: Path) -> None:
    state_file = repo / "state" / "state.json"
    state_file.parent.mkdir(parents=True)
    state_file.write_text("{}", encoding="utf-8")
    # Whitespace + casing should normalise.
    result = push("Production ", state_file, repo=repo, push_remote=False)
    assert result.ref == "refs/heads/state/production"


def test_push_missing_state_file_raises(repo: Path) -> None:
    with pytest.raises(StateSyncError):
        push("production", repo / "no-state.json",
             repo=repo, push_remote=False)


def test_push_orphan_commit_has_no_parent(repo: Path) -> None:
    state_file = repo / "state" / "state.json"
    state_file.parent.mkdir(parents=True)
    state_file.write_text("{}", encoding="utf-8")
    result = push("production", state_file, repo=repo, push_remote=False)
    # rev-list <commit> --parents: the line should have only the commit
    # SHA followed by no parent SHAs.
    parents = _git(repo, "rev-list", result.commit_sha, "--parents", "-n", "1")
    parts = parents.split()
    assert parts == [result.commit_sha], (
        f"orphan commit must have no parent; got: {parts}"
    )


def test_push_replaces_ref_on_subsequent_push(repo: Path) -> None:
    state_file = repo / "state" / "state.json"
    state_file.parent.mkdir(parents=True)
    state_file.write_text("{}", encoding="utf-8")
    first = push("production", state_file, repo=repo, push_remote=False)
    state_file.write_text(json.dumps({"v": 2}), encoding="utf-8")
    second = push("production", state_file, repo=repo, push_remote=False)
    assert first.commit_sha != second.commit_sha
    assert _git(repo, "rev-parse", second.ref) == second.commit_sha


# ---------------------------------------------------------------------------
# pull
# ---------------------------------------------------------------------------


def test_pull_writes_state_from_ref(repo: Path) -> None:
    state_file = repo / "state" / "state.json"
    state_file.parent.mkdir(parents=True)
    state_file.write_text(json.dumps({"v": 1}), encoding="utf-8")
    push("production", state_file, repo=repo, push_remote=False)

    # Simulate a fresh clone losing the local state file.
    state_file.unlink()
    assert not state_file.exists()

    result = pull("production", state_file, repo=repo, fetch_remote=False)
    assert isinstance(result, PullResult)
    assert result.written_path == state_file
    assert state_file.exists()
    assert json.loads(state_file.read_text(encoding="utf-8")) == {"v": 1}


def test_pull_missing_ref_returns_empty_result(repo: Path) -> None:
    state_file = repo / "state" / "state.json"
    result = pull("never-pushed", state_file, repo=repo, fetch_remote=False)
    assert result.written_path is None
    assert "does not exist" in result.detail or "no state.json" in result.detail


# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------


def test_status_in_sync_after_push(repo: Path) -> None:
    state_file = repo / "state" / "state.json"
    state_file.parent.mkdir(parents=True)
    state_file.write_text(json.dumps({"v": 1}), encoding="utf-8")
    push("production", state_file, repo=repo, push_remote=False)

    result = status("production", state_file, repo=repo)
    assert isinstance(result, StatusResult)
    assert result.local_present and result.remote_present
    assert result.local_sha == result.remote_sha
    assert result.in_sync is True


def test_status_diverges_when_local_changes(repo: Path) -> None:
    state_file = repo / "state" / "state.json"
    state_file.parent.mkdir(parents=True)
    state_file.write_text(json.dumps({"v": 1}), encoding="utf-8")
    push("production", state_file, repo=repo, push_remote=False)
    # Mutate local without pushing.
    state_file.write_text(json.dumps({"v": 2}), encoding="utf-8")

    result = status("production", state_file, repo=repo)
    assert result.in_sync is False
    assert result.local_sha != result.remote_sha


def test_status_remote_missing_when_never_pushed(repo: Path) -> None:
    state_file = repo / "state" / "state.json"
    state_file.parent.mkdir(parents=True)
    state_file.write_text("{}", encoding="utf-8")
    result = status("never-pushed", state_file, repo=repo)
    assert result.local_present is True
    assert result.remote_present is False
    assert result.in_sync is False
