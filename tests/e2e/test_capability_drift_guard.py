# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Drift guard for the e2e capability registry.

Walks the live Click tree via ``contentops.catalog.inspect.inspect_cli``
and asserts that every leaf command is either:

  * referenced by at least one Capability in ``CAPABILITIES``
    (via the ``catalog_path`` field), OR
  * listed in ``INTENTIONALLY_UNCOVERED`` with a justification.

When this test fires, a CLI command has been added without registering
a matching capability. The fix is one of:

  1. Add a Capability entry to ``tests/e2e/_capabilities.py`` and
     extend ``COVERED_LEAVES`` to include the new path.
  2. Add the new path to ``INTENTIONALLY_UNCOVERED`` with a one-line
     reason.

The guard runs in normal CI (it does NOT require the e2e activation
flag — it's a quick metadata check, not a heavy CLI invocation).
"""

from __future__ import annotations

import pytest

from contentops.catalog.inspect import inspect_cli
from tests.e2e._capabilities import (
    CAPABILITIES,
    COVERED_LEAVES,
    INTENTIONALLY_UNCOVERED,
)


def test_registry_matches_click_tree() -> None:
    """Every Click leaf command must be covered or explicitly skipped."""
    specs = inspect_cli()
    live_paths = {s.name for s in specs}
    registered_paths = {
        cap.catalog_path for cap in CAPABILITIES if cap.catalog_path
    }
    covered = set(COVERED_LEAVES) | registered_paths | set(INTENTIONALLY_UNCOVERED)

    missing = live_paths - covered
    if missing:
        pytest.fail(
            "New CLI commands found without an e2e capability entry:\n  "
            + "\n  ".join(sorted(missing))
            + "\n\nFix: add a Capability to tests/e2e/_capabilities.py "
            "(and update COVERED_LEAVES), OR add the path to "
            "INTENTIONALLY_UNCOVERED with a justification.",
        )

    stale = covered - live_paths
    if stale:
        pytest.fail(
            "Registry references CLI commands that no longer exist:\n  "
            + "\n  ".join(sorted(stale))
            + "\n\nFix: remove the stale entries from COVERED_LEAVES / "
            "INTENTIONALLY_UNCOVERED / Capability.catalog_path.",
        )


def test_every_capability_has_unique_id() -> None:
    """Catch copy-paste bugs in the registry."""
    ids = [c.id for c in CAPABILITIES]
    dupes = {i for i in ids if ids.count(i) > 1}
    assert not dupes, f"duplicate capability ids: {sorted(dupes)}"
