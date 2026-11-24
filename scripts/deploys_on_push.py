# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Exit 0 when ``deploy.yml`` deploys on push, 1 when it does not.

A deployment repository may run Deploy by hand only (its push trigger
commented out). Workflows that tell an operator what happens after a
merge (``emergency-disable.yml``) ask this script instead of assuming
the push deploy.

Usage: ``python scripts/deploys_on_push.py [path/to/deploy.yml]``
"""

from __future__ import annotations

import sys
from pathlib import Path

import yaml

DEFAULT = Path(".github/workflows/deploy.yml")


def deploys_on_push(workflow: Path = DEFAULT) -> bool:
    """True when ``workflow`` has an active ``push`` trigger. A missing or
    unreadable file reads as False (the safe answer: deploy by hand)."""
    try:
        doc = yaml.safe_load(workflow.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError):
        return False
    if not isinstance(doc, dict):
        return False
    # PyYAML reads the bare key `on` as the boolean True.
    on = doc.get("on", doc.get(True))
    if isinstance(on, str):
        return on == "push"
    if isinstance(on, (list, dict)):
        return "push" in on
    return False


def main(argv: list[str]) -> int:
    path = Path(argv[1]) if len(argv) > 1 else DEFAULT
    return 0 if deploys_on_push(path) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
