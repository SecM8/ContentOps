# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0
"""Add SPDX license headers to every Python file in the repo.

Idempotent: re-running on a tree that already carries headers is a
no-op. CI invokes it with ``--check`` to fail fast when a new Python
file lands without the header.

Run:
  python scripts/add_spdx_headers.py             # write headers
  python scripts/add_spdx_headers.py --check     # exit 1 if any missing
  python scripts/add_spdx_headers.py --diff      # show planned changes
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# Header lines, in order. Two lines so tooling that greps for either
# identifier still finds the file.
HEADER_LINES = (
    "# SPDX-FileCopyrightText: 2026 KustoKing / SecM8",
    "# SPDX-License-Identifier: Apache-2.0",
)

# Directories to scan. Tests + scripts get headers too so a downstream
# fork sees the policy applied uniformly.
SCAN_DIRS = ("contentops", "scripts", "tests")

# Skip patterns. ``__pycache__`` is regenerated; ``.venv`` is local.
SKIP_PARTS = {"__pycache__", ".venv", "venv", ".git"}


def needs_header(text: str) -> bool:
    """True when the file is missing either SPDX line."""
    first_200 = text[:600]
    return not all(line in first_200 for line in HEADER_LINES)


def insert_header(text: str) -> str:
    """Return ``text`` with the SPDX header inserted near the top.

    Insertion rules:
      * Preserve a leading shebang (``#!``) line.
      * Preserve any leading encoding cookie (``# -*- coding: ... -*-``).
      * Place the header BEFORE the module docstring so the docstring
        remains the file's ``__doc__``.
      * No-op when both SPDX lines already appear in the first 600
        characters (idempotent).
    """
    if not needs_header(text):
        return text

    lines = text.splitlines(keepends=True)
    insert_at = 0
    if lines and lines[0].startswith("#!"):
        insert_at = 1
    # Encoding cookie has to be in line 1 or 2 per PEP 263.
    if insert_at < len(lines) and "coding" in lines[insert_at] and lines[insert_at].startswith("#"):
        insert_at += 1

    header_block = [line + "\n" for line in HEADER_LINES]
    # Add a blank line after the header only if the next existing line
    # is not already blank, to avoid double-blank-line drift.
    if insert_at < len(lines) and lines[insert_at].strip():
        header_block.append("\n")

    new_lines = lines[:insert_at] + header_block + lines[insert_at:]
    return "".join(new_lines)


def iter_python_files() -> list[Path]:
    files: list[Path] = []
    for d in SCAN_DIRS:
        for path in (REPO_ROOT / d).rglob("*.py"):
            if any(part in SKIP_PARTS for part in path.parts):
                continue
            files.append(path)
    return sorted(files)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Exit 1 if any file is missing the SPDX header. Do not write.",
    )
    parser.add_argument(
        "--diff",
        action="store_true",
        help="Print the list of files that would be changed and exit 0.",
    )
    args = parser.parse_args()

    missing: list[Path] = []
    written: list[Path] = []
    for path in iter_python_files():
        text = path.read_text(encoding="utf-8")
        if not needs_header(text):
            continue
        missing.append(path)
        if args.check or args.diff:
            continue
        new_text = insert_header(text)
        path.write_text(new_text, encoding="utf-8")
        written.append(path)

    if args.check:
        if missing:
            print(f"{len(missing)} file(s) missing SPDX header:", file=sys.stderr)
            for path in missing:
                print(f"  {path.relative_to(REPO_ROOT)}", file=sys.stderr)
            return 1
        print("All Python files carry the SPDX header.")
        return 0

    if args.diff:
        for path in missing:
            print(path.relative_to(REPO_ROOT))
        return 0

    print(f"Added SPDX header to {len(written)} file(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
