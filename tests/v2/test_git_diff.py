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


def test_a_path_name_is_not_accepted_as_a_ref(tmp_path: Path) -> None:
    """``git diff <x>`` reads ``x`` as a path when it is not a revision but
    is the name of a file or folder. A mistyped ref that happens to be a
    folder name would then return "nothing changed" instead of an error,
    and a deploy limited to changes since that ref would apply nothing."""
    repo = _init_repo(tmp_path)
    (repo / "detections").mkdir()
    (repo / "detections" / "rule.yml").write_text("x: 1")
    _run(["git", "add", "."], repo)
    _run(["git", "commit", "-q", "-m", "add a folder"], repo)
    (repo / "detections" / "rule.yml").write_text("x: 2")  # a real change

    with pytest.raises(GitDiffError):
        changed_paths("detections", repo=repo)


def test_a_change_to_a_playbook_definition_alone_selects_the_playbook(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A playbook keeps its Logic App definition in a ``.workflow.json``
    next to the envelope. ``--changed-since`` compared only envelope
    paths, so an edit to the definition alone was never deployed. Seen in
    a deployment repo: six of seven edited objects were selected."""
    import json

    import yaml

    from contentops.cli.commands._shared import _filter_changed_since
    from contentops.core.discovery import iter_loaded_assets

    repo = _init_repo(tmp_path)
    pb = repo / "detections" / "sentinel_playbook"
    pb.mkdir(parents=True)
    definition = {"triggers": {"t": {"type": "Request"}}, "actions": {"a": {"type": "Compose", "inputs": "v1"}}}
    (pb / "pb.workflow.json").write_text(json.dumps(definition), encoding="utf-8")
    (pb / "pb.yml").write_text(yaml.safe_dump({
        "id": "pb", "version": "1.0.0", "asset": "sentinel_playbook", "status": "production",
        "payload": {"definitionFile": "pb.workflow.json"},
    }), encoding="utf-8")
    _run(["git", "add", "."], repo)
    _run(["git", "commit", "-q", "-m", "add a playbook"], repo)
    definition["actions"]["a"]["inputs"] = "v2"
    (pb / "pb.workflow.json").write_text(json.dumps(definition), encoding="utf-8")

    monkeypatch.chdir(repo)
    loaded = list(iter_loaded_assets(Path("detections")))
    assert [la.envelope.id for la in _filter_changed_since(loaded, "HEAD")] == ["pb"]
