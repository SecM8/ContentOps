# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Doc-drift gate for ``docs/assets/README.md`` (P3-1).

Pins the invariant that the per-asset index points only at the six
canonical asset kinds defined in :class:`contentops.core.asset.Asset`.
Prevents recurrence of the staleness that P1-1 cleaned up — historically
the README listed 20+ handler modules for surfaces removed in the
asset-taxonomy reduction (PR #122 / #129).

If a future PR adds a row referencing ``contentops.handlers.<removed>``,
this test fails at PR time rather than after operators have followed
broken links.
"""

from __future__ import annotations

import re
from pathlib import Path

from contentops.core.asset import Asset

_README = Path(__file__).resolve().parents[2] / "docs" / "assets" / "README.md"

# Pattern that matches a fully-qualified handler module reference like
# ``contentops.handlers.sentinel_analytic`` or
# ``contentops.handlers.sentinel_workbook`` (whether or not it's inside a
# Markdown code span or table cell).
_HANDLER_REF = re.compile(r"pipeline\.handlers\.([A-Za-z_][A-Za-z0-9_]*)")


def _canonical_handler_names() -> set[str]:
    """The six handler module suffixes derived from the Asset enum."""
    return {asset.value for asset in Asset}


def test_readme_lists_only_canonical_handler_modules() -> None:
    """Every ``contentops.handlers.X`` reference in docs/assets/README.md
    must point at a module backing a current asset kind. Catches
    references to removed handlers (sentinel_automation, sentinel_workbook,
    sentinel_ti_indicator, defender_ti_indicator, etc.)."""
    assert _README.is_file(), f"missing {_README}"
    text = _README.read_text(encoding="utf-8")
    referenced = set(_HANDLER_REF.findall(text))
    canonical = _canonical_handler_names()
    stale = referenced - canonical
    assert not stale, (
        f"docs/assets/README.md references handler modules that don't "
        f"exist: {sorted(stale)}. Either delete the rows or extend the "
        f"Asset enum if the kind is being re-introduced."
    )


def test_readme_does_not_mention_legacy_per_asset_doc_pages() -> None:
    """The per-asset doc pages for removed handlers were deleted in P2-3.
    Asserting the README doesn't link to them prevents 404s if a future
    PR accidentally re-introduces a stale link."""
    text = _README.read_text(encoding="utf-8")
    legacy_files = (
        "sentinel_singletons.md",
        "sentinel_collect_only.md",
        "sentinel_ti_indicator.md",
        "sentinel_workbook_connector_summary_solution.md",
        "defender_ti_indicator.md",
    )
    referenced = [f for f in legacy_files if f in text]
    assert not referenced, (
        f"docs/assets/README.md references deleted per-asset doc pages: "
        f"{referenced}. Remove the links or restore the pages."
    )
