# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Workspace-aware KQL snippet substitution.

A detection's KQL may embed placeholders of the form ``{{folder/file.yml}}``
(``\\`` accepted too). At apply / plan time the resolver picks:

1. ``overrides/<workspaceName>/<path>`` if it exists, else
2. ``overrides/<path>`` if it exists, else
3. **drops the entire line** containing the placeholder.

The same snippet file may be referenced by many rules (e.g. one
``common/domainadmins.yml`` reused by every "domain admin activity"
rule). Substitution happens *before* the handler builds the ARM body
so the deploy-time hash chain stays deterministic per (rule x
workspace).

See ``docs/operations/multi-workspace.md`` for the operator-facing
contract; the lint rules in ``contentops/lint/snippets.py`` (KQLOVERRIDE
001-004) enforce the syntax + safety constraints.
"""

from __future__ import annotations

from contentops.snippets.apply import (
    DEFAULT_OVERRIDES_ROOT,
    PLACEHOLDER_RE,
    SnippetError,
    apply_snippets,
    find_placeholders,
)

__all__ = [
    "DEFAULT_OVERRIDES_ROOT",
    "PLACEHOLDER_RE",
    "SnippetError",
    "apply_snippets",
    "find_placeholders",
]
