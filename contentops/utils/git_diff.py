# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Resolve which files have changed since a git ref.

Used by ``plan`` and ``apply`` to support a "smart deploy" mode that
restricts the action set to assets whose YAML actually changed —
the same idea Sentinel-as-Code Wave 2 calls "smart deployment".

The lookup is intentionally tolerant:

  * If git is unavailable, the ref is unknown, or the call fails for
    any other reason, the function raises ``GitDiffError``. Callers
    should surface a clear message and refuse to filter (rather than
    silently fall back to "no changes" — that would deploy nothing).
  * Paths are returned as absolute, resolved ``Path`` objects so they
    can be compared directly to ``LoadedAsset.path``.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path


class GitDiffError(RuntimeError):
    pass


def changed_paths(ref: str, *, repo: Path | None = None) -> set[Path]:
    """Return the set of paths that differ between ``ref`` and the working tree.

    Includes staged, unstaged, and untracked files. Returned paths are
    absolute and resolved.
    """
    git = shutil.which("git")
    if git is None:
        raise GitDiffError("git is not on PATH")

    cwd = (repo or Path.cwd()).resolve()

    # `git diff --name-only <ref>` covers committed + staged + unstaged
    # changes vs. the ref. `git ls-files --others --exclude-standard`
    # covers brand-new untracked files (which a tree diff cannot see).
    try:
        diff_out = subprocess.run(
            [git, "-C", str(cwd), "diff", "--name-only", ref],
            capture_output=True, text=True, check=True, timeout=10,
        ).stdout
        untracked_out = subprocess.run(
            [git, "-C", str(cwd), "ls-files", "--others", "--exclude-standard"],
            capture_output=True, text=True, check=True, timeout=10,
        ).stdout
    except subprocess.CalledProcessError as exc:
        msg = (exc.stderr or exc.stdout or "").strip() or str(exc)
        raise GitDiffError(f"git diff failed: {msg}") from exc
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise GitDiffError(f"git invocation failed: {exc}") from exc

    paths: set[Path] = set()
    for line in (diff_out + untracked_out).splitlines():
        line = line.strip()
        if not line:
            continue
        paths.add((cwd / line).resolve())
    return paths


__all__ = ["GitDiffError", "changed_paths"]
