# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Rollback machinery — replay the YAML at a prior git SHA against the tenant.

The CLI command (`contentops rollback <sha>`) is in
`contentops/cli/commands.py`; this module is the side-effect-free
plumbing it depends on:

* ``resolve_sha(short_or_full)`` — full git SHA via ``git rev-parse``.
* ``materialize_at_sha(sha, source, dest)`` — copy the contents of
  ``source/`` at ``sha`` into ``dest/`` (cross-platform; uses
  ``git ls-tree`` + ``git show`` so it works on Windows where ``tar``
  is unreliable).
* ``rollback_audit_message(sha)`` — canonical free-text marker that
  audit queries can grep for.

Rollback is "apply the YAML at SHA X against the tenant." This is
deliberately *not* a delta: a rule that exists today but didn't at
SHA X is **left alone** (rollback is non-destructive — operators
can `contentops prune` afterwards if they want full reset semantics).
The tradeoff is documented in the CLI docstring.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path


class RollbackError(RuntimeError):
    """Raised when git plumbing fails. The CLI maps this to exit 1."""


def _git() -> str:
    g = shutil.which("git")
    if g is None:
        raise RollbackError("git is not on PATH")
    return g


def resolve_sha(sha: str, *, repo: Path | None = None) -> str:
    """Resolve a short or full SHA to the full 40-char SHA.

    Raises ``RollbackError`` on unknown ref / git failure.
    """
    if not sha:
        raise RollbackError("rollback target SHA is empty")
    cwd = (repo or Path.cwd()).resolve()
    try:
        result = subprocess.run(
            [_git(), "-C", str(cwd), "rev-parse", "--verify", f"{sha}^{{commit}}"],
            capture_output=True, text=True, check=True, timeout=10,
        )
    except subprocess.CalledProcessError as exc:
        msg = (exc.stderr or exc.stdout or "").strip() or str(exc)
        raise RollbackError(f"could not resolve {sha!r}: {msg}") from exc
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RollbackError(f"git rev-parse failed: {exc}") from exc
    full = result.stdout.strip()
    if len(full) != 40:
        raise RollbackError(f"git returned a non-40-char SHA: {full!r}")
    return full


def list_files_at(
    sha: str, source: str, *, repo: Path | None = None,
) -> list[str]:
    """Return every file path under ``source/`` at ``sha`` (relative paths).

    Uses ``git ls-tree -r --name-only <sha> -- <source>``; pass
    forward-slash paths even on Windows (git speaks them natively).
    """
    cwd = (repo or Path.cwd()).resolve()
    try:
        result = subprocess.run(
            [_git(), "-C", str(cwd), "ls-tree", "-r", "--name-only", sha, "--", source],
            capture_output=True, text=True, check=True, timeout=30,
        )
    except subprocess.CalledProcessError as exc:
        msg = (exc.stderr or exc.stdout or "").strip() or str(exc)
        raise RollbackError(f"git ls-tree {sha}:{source} failed: {msg}") from exc
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RollbackError(f"git ls-tree failed: {exc}") from exc
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def show_blob(
    sha: str, path: str, *, repo: Path | None = None,
) -> bytes:
    """Return the bytes of ``path`` at ``sha`` via ``git show <sha>:<path>``."""
    cwd = (repo or Path.cwd()).resolve()
    try:
        result = subprocess.run(
            [_git(), "-C", str(cwd), "show", f"{sha}:{path}"],
            capture_output=True, check=True, timeout=30,
        )
    except subprocess.CalledProcessError as exc:
        msg = (exc.stderr or b"").decode("utf-8", errors="replace").strip() or str(exc)
        raise RollbackError(f"git show {sha}:{path} failed: {msg}") from exc
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RollbackError(f"git show failed: {exc}") from exc
    return result.stdout


def materialize_at_sha(
    sha: str, source: str, dest: Path, *, repo: Path | None = None,
) -> int:
    """Copy ``source/`` at ``sha`` into ``dest/``. Returns file count.

    Cross-platform: uses ``git ls-tree`` + ``git show``. ``dest`` must
    already exist and is populated in-place. The ``source`` prefix is
    preserved in the copied paths (so ``materialize_at_sha(sha,
    "detections", tmp)`` writes to ``tmp/detections/<...>``).
    """
    if not dest.is_dir():
        raise RollbackError(f"destination {dest} is not a directory")
    files = list_files_at(sha, source, repo=repo)
    for rel in files:
        # ``rel`` always uses forward-slash because git emits it that
        # way; convert when joining with a Path.
        target = dest / Path(*rel.split("/"))
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(show_blob(sha, rel, repo=repo))
    return len(files)


def rollback_audit_message(sha: str) -> str:
    """Canonical audit ``message`` for rollback records.

    All rollback records carry a message starting with this exact
    prefix so audit queries can find them with one substring match.
    """
    return f"rollback to {sha}"


__all__ = [
    "RollbackError",
    "resolve_sha",
    "list_files_at",
    "show_blob",
    "materialize_at_sha",
    "rollback_audit_message",
]
