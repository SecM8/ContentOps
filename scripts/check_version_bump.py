# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Fail CI when a detection envelope changed but its ``version`` field did not.

DESIGN §4 requires reviewers to bump ``version`` on every meaningful
change, but nothing enforced it — so the entire corpus has ``version:
0.0.0`` and the field is dead weight. This script closes the gap: for
every YAML file under ``detections/`` whose content differs from the
merge base, parse the envelope, parse the same envelope at the merge
base, and refuse the change if both sides report the identical version.

Limitations (intentional, to keep CI fast):
  * Pure semver comparison; no ordering check beyond "must differ".
  * Files that are added (no base version) are exempt.
  * Files that are deleted are exempt.
  * Cosmetic-only diffs are exempt: the envelope is YAML-parsed on both
    sides and compared by content (the ``version`` key set aside), so a
    semantically-identical edit (whitespace, key reorder, comment, CRLF)
    does not demand a version bump.

Exit codes:
  0 — every changed file has a bumped version (or is new / deleted).
  1 — at least one file changed without a version bump.
  2 — git plumbing failed (unexpected; surfaces as CI red).
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import yaml

DETECTIONS_ROOT = "detections/"


def _run(*args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout


def _changed_files(base_ref: str) -> list[str]:
    out = _run("diff", "--name-only", f"{base_ref}...HEAD", "--", DETECTIONS_ROOT)
    return [line for line in out.splitlines() if line.endswith((".yml", ".yaml"))]


def _parse_doc(text: str) -> dict | None:
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError:
        return None
    return doc if isinstance(doc, dict) else None


def _requires_bump(head_text: str, base_text: str) -> str | None:
    """Return a failure message if ``head_text`` changed semantically from
    ``base_text`` without a version bump, else ``None``.

    The envelope is YAML-parsed on both sides and the ``version`` key is
    set aside; the remaining bodies are compared by ``dict`` equality,
    which ignores key order, indentation, comments, and line endings. So a
    cosmetic-only edit compares equal and demands no bump. Unparseable
    input is exempt — the validate step owns that failure.
    """
    head_doc = _parse_doc(head_text)
    base_doc = _parse_doc(base_text)
    if head_doc is None or base_doc is None:
        return None
    head_body = {k: v for k, v in head_doc.items() if k != "version"}
    base_body = {k: v for k, v in base_doc.items() if k != "version"}
    if head_body == base_body:
        return None  # semantically identical — cosmetic edit, no bump needed
    head_v = head_doc.get("version")
    base_v = base_doc.get("version")
    if head_v is None or base_v is None:
        return None
    if str(head_v) == str(base_v):
        return f"version unchanged ({head_v}) but content changed"
    return None


def _file_at_ref(ref: str, path: str) -> str | None:
    try:
        return _run("show", f"{ref}:{path}")
    except subprocess.CalledProcessError:
        return None  # File didn't exist at base ref → newly added, exempt.


def main(base_ref: str) -> int:
    try:
        changed = _changed_files(base_ref)
    except subprocess.CalledProcessError as exc:
        print(f"git diff failed: {exc.stderr}", file=sys.stderr)
        return 2

    failures: list[str] = []
    for path in changed:
        head_text = Path(path).read_text(encoding="utf-8") if Path(path).exists() else None
        if head_text is None:
            continue  # Deletion.
        base_text = _file_at_ref(base_ref, path)
        if base_text is None:
            continue  # New file.
        msg = _requires_bump(head_text, base_text)
        if msg:
            failures.append(f"{path}: {msg}")

    if failures:
        print("Version-bump check failed:", file=sys.stderr)
        for line in failures:
            print(f"  - {line}", file=sys.stderr)
        print(
            "\nBump the `version` field in each changed envelope before merge.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    base = sys.argv[1] if len(sys.argv) > 1 else "origin/main"
    sys.exit(main(base))
