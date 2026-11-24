# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Bump an envelope's version in its text.

The commands that edit a rule file by hand-written text substitution
(``disable``, ``enable``, ``lock``, ``unlock``, ``lifecycle promote``) keep
the file's comments and layout, so they cannot re-dump it as YAML. The
version check in ``validate`` refuses a changed file whose ``version`` did
not change; these commands bump the patch number in place.
"""

from __future__ import annotations

import re

# The top-level ``version:`` key (no indentation), a plain ``X.Y.Z`` value,
# optionally quoted, optionally followed by a comment.
_VERSION_LINE_RE = re.compile(
    r"^(version:[ \t]*)([\"']?)(\d+)\.(\d+)\.(\d+)\2([ \t]*(?:#.*)?)$",
    re.MULTILINE,
)


def bump_patch_in_text(text: str) -> str:
    """``version: X.Y.Z`` -> ``version: X.Y.(Z+1)``, keeping quotes and a
    trailing comment. Text without a plain semver top-level version is
    returned unchanged."""
    def _bump(m: re.Match[str]) -> str:
        return (f"{m.group(1)}{m.group(2)}{m.group(3)}.{m.group(4)}."
                f"{int(m.group(5)) + 1}{m.group(2)}{m.group(6)}")

    return _VERSION_LINE_RE.sub(_bump, text, count=1)
