# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Snippet file loader.

Snippet files live under ``overrides/`` and have the shape::

    description: "Comma separated array of users excluded from the rule"
    content: |-
      "alice@corp", "bob@corp"

``description`` is operator-facing documentation (optional). ``content``
is the literal text spliced into the KQL where the placeholder appears.

The loader:

* validates the YAML shape (``content`` is a required string),
* normalises CRLF -> LF in ``content`` (Windows authors otherwise
  produce different deploy-hash bytes than *nix authors),
* caches by absolute path within a process (snippets are read many
  times across rules + workspaces inside one apply run).
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import yaml


class SnippetFormatError(ValueError):
    """Raised when a snippet file is malformed (missing ``content`` etc.)."""


@lru_cache(maxsize=512)
def _read_snippet(abs_path: str) -> str:
    """Read and return ``content`` from the snippet at ``abs_path``.

    Cached by absolute path string (Path is unhashable in some 3.12
    edge cases; str is unambiguous and stable). The cache lives for the
    process; for the apply/plan loop that's the right granularity.
    """
    raw = Path(abs_path).read_text(encoding="utf-8")
    try:
        parsed = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise SnippetFormatError(
            f"snippet {abs_path}: not valid YAML ({exc})"
        ) from exc
    if not isinstance(parsed, dict):
        raise SnippetFormatError(
            f"snippet {abs_path}: top-level must be a mapping with a "
            f"'content:' key, got {type(parsed).__name__}"
        )
    if "content" not in parsed:
        raise SnippetFormatError(
            f"snippet {abs_path}: missing required 'content:' key"
        )
    content = parsed["content"]
    if not isinstance(content, str):
        raise SnippetFormatError(
            f"snippet {abs_path}: 'content' must be a string, got "
            f"{type(content).__name__}"
        )
    return content.replace("\r\n", "\n").replace("\r", "\n")


def resolve_snippet(
    overrides_root: Path,
    rel_path: str,
    workspace_name: str | None,
) -> str | None:
    """Three-tier snippet resolution.

    Returns the snippet content string when one of the two candidate
    files exists, ``None`` when neither does (caller is expected to
    drop the line).

    Resolution order:

    1. ``overrides_root / workspace_name / rel_path`` (when
       ``workspace_name`` is set)
    2. ``overrides_root / rel_path``
    3. ``None``

    ``rel_path`` is expected to use ``/`` separators (the placeholder
    parser normalises ``\\`` -> ``/`` upstream).

    Both candidate paths are validated against ``overrides_root`` -
    if either resolves outside the root (via ``..`` segments in
    ``workspace_name`` or via a symlink that escapes), the call
    raises ``SnippetFormatError``. ``rel_path`` is also lint-checked
    by ``KQLOVERRIDE002``; this runtime check is defence-in-depth
    against the ``workspace_name`` dimension which the lint pass
    doesn't cover.
    """
    if not overrides_root.exists():
        return None

    root_resolved = overrides_root.resolve()

    if workspace_name:
        ws_path = overrides_root / workspace_name / rel_path
        _assert_under_root(ws_path, root_resolved)
        if ws_path.is_file():
            return _read_snippet(str(ws_path.resolve()))

    generic = overrides_root / rel_path
    _assert_under_root(generic, root_resolved)
    if generic.is_file():
        return _read_snippet(str(generic.resolve()))

    return None


def _assert_under_root(candidate: Path, root_resolved: Path) -> None:
    """Raise SnippetFormatError if ``candidate`` resolves outside ``root_resolved``."""
    try:
        candidate.resolve().relative_to(root_resolved)
    except ValueError:
        raise SnippetFormatError(
            f"snippet path {candidate} escapes overrides root "
            f"{root_resolved} (check workspace name for '..' segments "
            "or stray separators)"
        ) from None


def clear_cache() -> None:
    """Drop the per-process snippet content cache.

    Tests that mutate snippet files between assertions need this; the
    apply/plan path itself never calls it (one cache per process is the
    intended granularity).
    """
    _read_snippet.cache_clear()


__all__ = [
    "SnippetFormatError",
    "clear_cache",
    "resolve_snippet",
]
