# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Pure-Python KQL linter for detection rules."""

from __future__ import annotations

from contentops.lint.kql import LintFinding, lint_kql
from contentops.lint.runner import LintedFile, lint_assets

__all__ = [
    "LintFinding",
    "lint_kql",
    "LintedFile",
    "lint_assets",
]
