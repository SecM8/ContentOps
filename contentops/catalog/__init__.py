# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Code-driven catalog generator.

Generates ``docs/reference/generated-catalog.md`` from the live
codebase: the Click command tree, the Asset taxonomy, the lint rule
registry, the handler files, the workflow files, and the test files.

The generator is the answer to "where is the catalog the source of
truth?" Answer: nowhere. The code is the source of truth; this module
projects the code into a markdown view of itself, and a CI gate
(``contentops catalog check``) fails the build when the committed
markdown disagrees with what the code would currently produce.

Public surface kept intentionally small:

* :func:`contentops.catalog.inspect.inspect_all` — pure introspection,
  returns an :class:`~contentops.catalog.inspect.Inventory` dataclass.
* :func:`contentops.catalog.render.render_markdown` — pure rendering,
  takes an Inventory and returns the canonical markdown string.

Both functions are deterministic: same input → byte-identical output.
The CLI lives in ``contentops/cli/commands/catalog.py``.
"""

from __future__ import annotations

from contentops.catalog.inspect import (
    AssetSpec,
    CommandSpec,
    HandlerSpec,
    Inventory,
    LintRuleSpec,
    TestSpec,
    WorkflowSpec,
    inspect_all,
)
from contentops.catalog.render import GENERATED_FILE, render_markdown

__all__ = [
    "AssetSpec",
    "CommandSpec",
    "GENERATED_FILE",
    "HandlerSpec",
    "Inventory",
    "LintRuleSpec",
    "TestSpec",
    "WorkflowSpec",
    "inspect_all",
    "render_markdown",
]
