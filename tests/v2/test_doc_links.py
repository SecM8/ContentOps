# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Internal documentation link checker (CI gate).

Walks every hand-maintained Markdown doc and asserts that each relative
*file* link resolves to a real path on disk. This catches the class of
drift where a doc points at a deleted or renamed file — e.g. the
``v1-retirement-plan.md`` / ``v1-to-v2-migration-guide.md`` links and the
``lint.yml`` workflow link that were removed in the doc-reconciliation
sweep, or a stale ``contentops/sentinel/`` module path.

Scope / non-goals:

* **Generated docs are excluded** (``docs/status/`` and
  ``docs/detections/``). They are emitted by ``contentops status`` /
  ``contentops detection-docs`` and gated by their own byte-identical
  drift tests; their links are the generators' responsibility, not a
  hand-editing concern.
* **External links** (``http(s)://``, ``mailto:``, ``tel:``) and **pure
  anchors** (``#section``) are out of scope.
* Only the *file* part of a link is validated; an ``#anchor`` fragment on
  a file link is stripped before the existence check (heading-slug
  validation is intentionally not attempted — it is a separate, higher-
  false-positive concern).
* **Gitignored targets are skipped.** A doc may legitimately link to a
  file that is intentionally absent from a clean checkout — e.g.
  ``config/tenant.yml``, which is gitignored and materialised from a
  secret in CI (CLAUDE.md invariant 3). Those are not broken links.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

from contentops.config import is_operator_source_repo

REPO_ROOT = Path(__file__).resolve().parents[2]

# Internal-doc-link integrity is a source-repo maintenance gate: the
# public mirror + adopter clones strip operator-only files (e.g.
# config/lifecycle.yml) that committed docs legitimately link to, so the
# checker can only run against the full source-of-truth file set. It
# skips off-source so cloning the public mirror is green out of the box.
source_only = pytest.mark.skipif(
    not is_operator_source_repo(REPO_ROOT),
    reason="source-repo maintenance gate; skipped off-source "
           "(public mirror / adopter clone — no public-sync.yml)",
)

# Inline Markdown link: ``[text](target)``. Also matches image links
# ``![alt](target)`` (the leading ``!`` is simply not captured).
_LINK_RE = re.compile(r"\[[^\]]*\]\(([^)]+)\)")

_EXTERNAL_PREFIXES = ("http://", "https://", "mailto:", "tel:", "#")

# Generated doc trees — emitted by a CLI command and gated by their own
# drift tests; not hand-maintained, so excluded from this checker.
_EXCLUDED_PREFIXES = ("docs/status/", "docs/detections/")


def _rel(path: Path) -> str:
    return str(path.relative_to(REPO_ROOT)).replace("\\", "/")


def _doc_files() -> list[Path]:
    docs_dir = REPO_ROOT / "docs"
    files = [
        p
        for p in docs_dir.rglob("*.md")
        if not any(_rel(p).startswith(pre) for pre in _EXCLUDED_PREFIXES)
    ]
    for extra in ("README.md", "CLAUDE.md", "CONTRIBUTING.md"):
        candidate = REPO_ROOT / extra
        if candidate.exists():
            files.append(candidate)
    return sorted(files)


def _is_git_ignored(abs_path: Path) -> bool:
    """True if git intentionally ignores ``abs_path``.

    A doc may legitimately link to a gitignored file (e.g. the
    operator-local ``config/tenant.yml``, materialised from a secret in
    CI per CLAUDE.md invariant 3). Such a target is *expected* to be
    absent from a clean checkout, so it must not be flagged as broken.
    Only invoked for already-missing targets, so this shells out to git
    at most a handful of times. Falls back to "not ignored" if the path
    is outside the repo or git is unavailable.
    """
    try:
        rel = abs_path.relative_to(REPO_ROOT)
    except ValueError:
        return False
    try:
        result = subprocess.run(
            ["git", "check-ignore", "-q", str(rel)],
            cwd=REPO_ROOT,
            capture_output=True,
            check=False,
        )
    except OSError:
        return False
    return result.returncode == 0


def _broken_links_in(md: Path) -> list[str]:
    out: list[str] = []
    text = md.read_text(encoding="utf-8", errors="replace")
    for match in _LINK_RE.finditer(text):
        # Drop an optional ``"title"`` after the URL: ``(path "title")``.
        target = match.group(1).strip().split()[0]
        if target.startswith(_EXTERNAL_PREFIXES):
            continue
        path_part = target.split("#", 1)[0]
        if not path_part:  # pure in-page anchor
            continue
        resolved = (md.parent / path_part).resolve()
        if not resolved.exists() and not _is_git_ignored(resolved):
            out.append(target)
    return out


@source_only
def test_no_broken_internal_doc_links() -> None:
    """Every relative file link in a hand-maintained doc must resolve.

    Fix: correct the link, or restore/rename the target file. If the
    target is intentionally generated under ``docs/status/`` or
    ``docs/detections/``, it is already excluded here.
    """
    broken: list[str] = []
    for md in _doc_files():
        rel = _rel(md)
        for target in _broken_links_in(md):
            broken.append(f"{rel} -> {target}")
    assert not broken, (
        "Broken internal documentation link(s) found (target file does "
        "not exist):\n  " + "\n  ".join(broken)
    )
