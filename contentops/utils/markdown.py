# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Markdown helpers — safe interpolation of untrusted strings."""

from __future__ import annotations


def gfm_cell(value: object) -> str:
    """Escape a value for safe inclusion in a GitHub-Flavored-Markdown table cell.

    Replaces pipe characters and collapses newlines so untrusted strings
    (e.g. detection display names) cannot break table structure or inject
    markdown into PR comments / step summaries.
    """
    text = "" if value is None else str(value)
    return text.replace("\\", "\\\\").replace("|", "\\|").replace("\r", " ").replace("\n", " ")


__all__ = ["gfm_cell"]
