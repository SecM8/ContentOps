# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Fail CI when a Sentinel analytic rule carries MITRE ids Sentinel rejects.

Sentinel keeps parent techniques and sub-techniques in two lists. A
sub-technique id under ``techniques`` is refused at deploy:

    Invalid data model. [: The technique 'T1003.001' is invalid.
    The expected format is 'T####', where '#' represents a digit.]

``contentops plan`` does not see that (both lists are plain strings in
the payload model), so such a rule passes review, is merged, and fails
when it is deployed. This script moves the failure to the pull request.

Checked, for every ``sentinel_analytic`` YAML under ``detections/`` that
the pull request adds or changes against the merge base:

  * every entry of ``payload.techniques`` is ``T`` and four digits;
  * every entry of ``payload.subTechniques`` is ``T``, four digits, a
    dot and three digits.

Noted, without failing: a sub-technique whose parent is not listed under
``techniques``. Every rule a tenant returns lists the parent, but that
the service requires it is not documented.

Only added and changed files are checked, so a rule that is already
wrong on the base branch does not fail every other pull request.

Exit codes:
  0 — nothing to report.
  1 — at least one added or changed rule has an id in the wrong list or
      in the wrong format.
  2 — git plumbing failed (unexpected; surfaces as CI red).
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import yaml

DETECTIONS_ROOT = "detections/"
_TECHNIQUE = re.compile(r"T[0-9]{4}")
_SUB_TECHNIQUE = re.compile(r"T[0-9]{4}\.[0-9]{3}")


def _run(*args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout


def _changed_files(base_ref: str) -> list[str]:
    # --diff-filter=d leaves deletions out; added and modified files stay.
    out = _run(
        "diff", "--name-only", "--diff-filter=d", f"{base_ref}...HEAD", "--", DETECTIONS_ROOT,
    )
    return [line for line in out.splitlines() if line.endswith((".yml", ".yaml"))]


def _lists(text: str) -> tuple[list[str], list[str]] | None:
    """``(techniques, subTechniques)`` of a Sentinel analytic rule, else None."""
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError:
        return None  # Unparseable input is the validate step's failure.
    if not isinstance(doc, dict) or doc.get("asset") != "sentinel_analytic":
        return None
    payload = doc.get("payload")
    if not isinstance(payload, dict):
        return None

    def entries(key: str) -> list[str]:
        value = payload.get(key)
        return [str(item) for item in value] if isinstance(value, list) else []

    return entries("techniques"), entries("subTechniques")


def problems(text: str) -> list[str]:
    """Ids of one rule file that Sentinel rejects; empty when it is fine."""
    lists = _lists(text)
    if lists is None:
        return []
    techniques, sub_techniques = lists
    found = [
        f"techniques: {item!r} is not a technique id (expected T####)"
        for item in techniques if not _TECHNIQUE.fullmatch(item)
    ]
    found += [
        f"subTechniques: {item!r} is not a sub-technique id (expected T####.###)"
        for item in sub_techniques if not _SUB_TECHNIQUE.fullmatch(item)
    ]
    return found


def notes(text: str) -> list[str]:
    """Things worth a look that do not fail the check."""
    lists = _lists(text)
    if lists is None:
        return []
    techniques, sub_techniques = lists
    return [
        f"subTechniques: {item!r} is listed without its parent {item.split('.')[0]} under techniques"
        for item in sub_techniques
        if _SUB_TECHNIQUE.fullmatch(item) and item.split(".")[0] not in techniques
    ]


def main(base_ref: str) -> int:
    try:
        changed = _changed_files(base_ref)
    except subprocess.CalledProcessError as exc:
        print(f"git diff failed: {exc.stderr}", file=sys.stderr)
        return 2

    failures: list[str] = []
    remarks: list[str] = []
    for path in changed:
        if not Path(path).exists():
            continue
        text = Path(path).read_text(encoding="utf-8")
        failures += [f"{path}: {line}" for line in problems(text)]
        remarks += [f"{path}: {line}" for line in notes(text)]

    for line in remarks:
        print(f"note: {line}")
    if failures:
        print("MITRE id check failed:", file=sys.stderr)
        for line in failures:
            print(f"  - {line}", file=sys.stderr)
        print(
            "\nSentinel takes parent techniques (T####) under `techniques` and "
            "sub-techniques (T####.###) under `subTechniques`. A rule with an id "
            "in the wrong list is rejected when it is deployed.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    base = sys.argv[1] if len(sys.argv) > 1 else "origin/main"
    sys.exit(main(base))
