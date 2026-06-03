# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""`contentops state sync push|pull|status` — durable cross-runner state.

Closes G15. The state file at ``state/state.json`` is per-clone
today, so two CI runners produce divergent state and a fresh
checkout loses the state every time.

This module wires the orphan-branch convention DESIGN §13
promised: state lives on its own branch ``state/<env>`` whose
history is independent of main, audit-trailing every state
mutation without polluting main's commit log.

Pure git plumbing (no working-tree side effects):

* ``push``  — stages the local state/state.json onto an orphan
  commit on ``refs/heads/state/<env>``, then pushes to remote.
  Uses ``git hash-object`` + ``git mktree`` + ``git commit-tree``
  so the working tree stays clean.
* ``pull``  — fetches ``refs/heads/state/<env>`` from remote,
  reads the JSON blob via ``git show``, writes to local
  state/state.json.
* ``status`` — compares the local state hash against the remote
  ref's tree hash and prints divergence.

Concurrency is the operator's responsibility — pair this with a
``concurrency:`` group on the workflow that calls it so two
parallel applies queue rather than race. The CLI doesn't lock.
"""

from __future__ import annotations

import hashlib
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path


class StateSyncError(RuntimeError):
    """Raised on git plumbing failures."""


def _git() -> str:
    g = shutil.which("git")
    if g is None:
        raise StateSyncError("git is not on PATH")
    return g


def _run(args: list[str], *, cwd: Path) -> str:
    """Run a git command and return stripped stdout. Raises on non-zero."""
    try:
        result = subprocess.run(
            [_git(), "-C", str(cwd), *args],
            capture_output=True, text=True, check=False, timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise StateSyncError(f"git invocation failed: {exc}") from exc
    if result.returncode != 0:
        msg = (result.stderr or result.stdout or "").strip()
        raise StateSyncError(
            f"git {' '.join(args)} failed (exit {result.returncode}): {msg}"
        )
    return result.stdout.strip()


def _run_with_input(args: list[str], *, cwd: Path, stdin: str) -> str:
    """Run git with stdin. Uses BYTES so Windows doesn't translate
    LF->CRLF on the way in (mktree treats the trailing \\r as part of
    the filename otherwise — observed on Python 3.12 Windows)."""
    try:
        result = subprocess.run(
            [_git(), "-C", str(cwd), *args],
            input=stdin.encode("utf-8"),
            capture_output=True, check=False, timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise StateSyncError(f"git invocation failed: {exc}") from exc
    if result.returncode != 0:
        msg = (result.stderr or result.stdout or b"").decode(
            "utf-8", errors="replace",
        ).strip()
        raise StateSyncError(
            f"git {' '.join(args)} failed (exit {result.returncode}): {msg}"
        )
    return result.stdout.decode("utf-8", errors="replace").strip()


def _ref_name(env: str) -> str:
    """Canonical ref for an env's state branch.

    e.g. 'production' -> 'refs/heads/state/production'.
    """
    import re as _re
    safe = env.strip().lower() or "default"
    if not _re.fullmatch(r"[a-z0-9][a-z0-9\-_]{0,62}", safe):
        raise StateSyncError(
            f"env name {env!r} is not a valid identifier for a state branch "
            "(expected alphanumeric + hyphen/underscore, 1-63 chars)"
        )
    return f"refs/heads/state/{safe}"


@dataclass
class PushResult:
    env: str
    ref: str
    commit_sha: str
    pushed_remote: bool
    detail: str = ""


@dataclass
class PullResult:
    env: str
    ref: str
    fetched: bool
    written_path: Path | None
    detail: str = ""


@dataclass
class StatusResult:
    env: str
    ref: str
    local_present: bool
    local_sha: str | None
    remote_present: bool
    remote_sha: str | None
    in_sync: bool


# ---------------------------------------------------------------------------
# Push
# ---------------------------------------------------------------------------


def push(
    env: str,
    state_file: Path,
    *,
    repo: Path,
    remote: str = "origin",
    push_remote: bool = True,
    actor: str = "pipeline",
) -> PushResult:
    """Push the local state file onto ``refs/heads/state/<env>``.

    The orphan commit has no parent (each push replaces the ref
    head). The local ref is updated even when ``push_remote=False``,
    so unit tests can exercise the plumbing without a real remote.
    """
    if not state_file.is_file():
        raise StateSyncError(f"state file not found: {state_file}")

    ref = _ref_name(env)

    # 1. Stage the file as a blob in git's object store.
    blob_sha = _run([
        "hash-object", "-w", str(state_file),
    ], cwd=repo)

    # 2. Build a tree containing just state.json -> blob.
    tree_input = f"100644 blob {blob_sha}\tstate.json\n"
    tree_sha = _run_with_input(
        ["mktree"], cwd=repo, stdin=tree_input,
    )

    # 3. Commit the tree with no parent (orphan).
    msg = f"[state] {env} {state_file.read_text(encoding='utf-8')[:200]}"
    # Keep the commit message tight — first 200 chars of the JSON
    # blob is enough to grep the ref's history later.
    commit_sha = _run_with_input(
        ["commit-tree", tree_sha, "-m", f"[state] {env} sync from {actor}"],
        cwd=repo, stdin="",
    )

    # 4. Update the local ref to point at the new commit.
    _run(["update-ref", ref, commit_sha], cwd=repo)

    pushed = False
    detail = ""
    if push_remote:
        try:
            _run(["push", "--force", remote, f"{ref}:{ref}"], cwd=repo)
            pushed = True
        except StateSyncError as exc:
            detail = f"local ref updated; remote push failed: {exc}"
            # Local update succeeded, so don't re-raise — let caller
            # decide whether to fail.
    return PushResult(
        env=env, ref=ref, commit_sha=commit_sha,
        pushed_remote=pushed, detail=detail,
    )


# ---------------------------------------------------------------------------
# Pull
# ---------------------------------------------------------------------------


def pull(
    env: str,
    state_file: Path,
    *,
    repo: Path,
    remote: str = "origin",
    fetch_remote: bool = True,
) -> PullResult:
    """Pull the remote state ref into ``state_file``.

    Tolerates missing ref (returns ``fetched=False``) so a first-
    run workflow can call ``pull`` unconditionally.
    """
    ref = _ref_name(env)
    fetched = False
    if fetch_remote:
        try:
            _run(["fetch", remote, f"+{ref}:{ref}"], cwd=repo)
            fetched = True
        except StateSyncError:
            # Remote doesn't have the ref yet; treat as empty state.
            pass

    # Check if the local ref exists.
    try:
        _run(["rev-parse", "--verify", ref], cwd=repo)
    except StateSyncError:
        return PullResult(
            env=env, ref=ref, fetched=fetched, written_path=None,
            detail=f"ref {ref} does not exist locally — empty state",
        )

    # Read the state.json blob from the ref.
    try:
        body = _run([
            "show", f"{ref}:state.json",
        ], cwd=repo)
    except StateSyncError as exc:
        return PullResult(
            env=env, ref=ref, fetched=fetched, written_path=None,
            detail=f"ref {ref} has no state.json: {exc}",
        )

    state_file.parent.mkdir(parents=True, exist_ok=True)
    state_file.write_text(body + ("\n" if not body.endswith("\n") else ""), encoding="utf-8")
    return PullResult(
        env=env, ref=ref, fetched=fetched, written_path=state_file,
        detail=f"wrote {state_file}",
    )


# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------


def _file_blob_sha(path: Path) -> str:
    """Compute the SHA git would assign to a blob containing this file.

    Uses SHA-1 because that is the hash function git itself uses for
    object identity; the value of this function is to match git's
    own blob hash, not to provide cryptographic guarantees. The
    ``usedforsecurity=False`` flag tells bandit (B324) and similar
    security scanners that this is a content-addressable hash, not
    a primitive in a security boundary.
    """
    body = path.read_bytes()
    header = f"blob {len(body)}\0".encode("utf-8")
    return hashlib.sha1(header + body, usedforsecurity=False).hexdigest()


def status(
    env: str,
    state_file: Path,
    *,
    repo: Path,
) -> StatusResult:
    """Compare local state file against remote ref."""
    ref = _ref_name(env)
    local_present = state_file.is_file()
    local_sha = _file_blob_sha(state_file) if local_present else None

    remote_sha: str | None = None
    remote_present = False
    try:
        remote_sha = _run([
            "rev-parse", f"{ref}:state.json",
        ], cwd=repo)
        remote_present = True
    except StateSyncError:
        pass

    in_sync = (
        local_present and remote_present
        and local_sha == remote_sha
    )
    return StatusResult(
        env=env, ref=ref,
        local_present=local_present, local_sha=local_sha,
        remote_present=remote_present, remote_sha=remote_sha,
        in_sync=in_sync,
    )


__all__ = [
    "StateSyncError",
    "PushResult", "PullResult", "StatusResult",
    "push", "pull", "status",
]
