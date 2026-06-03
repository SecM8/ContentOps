# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for `contentops.upstream.whatsnew.render_markdown`."""

from __future__ import annotations

from contentops.upstream.manifest import ManifestDiff, compute_diff
from contentops.upstream.whatsnew import render_markdown


def _entry(name: str, version: str = "1.0.0", display: str | None = None) -> dict:
    return {"name": name, "displayName": display or name.title(), "version": version}


def test_render_empty_diff_shows_no_changes() -> None:
    body = render_markdown("2026-05-21", {"Content Packages": ManifestDiff()})
    assert "Upstream catalog changes — 2026-05-21" in body
    assert "## Content Packages" in body
    assert "_No changes._" in body


def test_render_added_section() -> None:
    diff = compute_diff([], [_entry("alpha"), _entry("beta", "2.0.0")])
    body = render_markdown("2026-05-21", {"Content Packages": diff})
    assert "### Added (2)" in body
    assert "Alpha" in body
    assert "Beta" in body
    assert "version `2.0.0`" in body


def test_render_changed_shows_version_pair() -> None:
    diff = compute_diff([_entry("alpha", "1.0.0")], [_entry("alpha", "1.1.0")])
    body = render_markdown("2026-05-21", {"Alert Rule Templates": diff})
    assert "### Changed (1)" in body
    assert "version `1.0.0` → `1.1.0`" in body


def test_render_removed_section() -> None:
    diff = compute_diff([_entry("alpha"), _entry("beta")], [_entry("alpha")])
    body = render_markdown("2026-05-21", {"Content Packages": diff})
    assert "### Removed (1)" in body
    assert "Beta" in body


def test_render_two_sources_in_order() -> None:
    body = render_markdown("2026-05-21", {
        "Content Packages": compute_diff([], [_entry("pkg-a")]),
        "Alert Rule Templates": compute_diff([], [_entry("tpl-a")]),
    })
    # Section order matches dict insertion order (Python 3.7+).
    pkg_pos = body.index("## Content Packages")
    tpl_pos = body.index("## Alert Rule Templates")
    assert pkg_pos < tpl_pos


def test_render_emits_trailing_newline() -> None:
    body = render_markdown("2026-05-21", {"Content Packages": ManifestDiff()})
    assert body.endswith("\n")
    assert not body.endswith("\n\n\n")


def test_byline_names_only_the_command_that_produced_the_diff() -> None:
    """A `check-schemas`-only run shouldn't claim to be from check-marketplace
    (which is what the original byline hardcoded). The byline is now derived
    from the diff source labels."""
    body = render_markdown(
        "2026-05-21",
        {"KQL workspace schemas": compute_diff([], [_entry("AuditLogs")])},
    )
    assert "contentops upstream check-schemas" in body
    assert "check-marketplace" not in body
    assert "check-templates" not in body


def test_byline_lists_multiple_commands_when_multi_source() -> None:
    body = render_markdown(
        "2026-05-21",
        {
            "Content Packages": compute_diff([], [_entry("pkg-a")]),
            "Alert Rule Templates": compute_diff([], [_entry("tpl-a")]),
        },
    )
    assert "contentops upstream check-marketplace" in body
    assert "contentops upstream check-templates" in body


def test_byline_falls_back_to_generic_when_source_unknown() -> None:
    """Forward-compat: a future source label not in the mapping still gets
    a reasonable byline."""
    body = render_markdown(
        "2026-05-21",
        {"Some Future Source": ManifestDiff()},
    )
    assert "contentops upstream" in body
    # Doesn't name any specific subcommand for an unknown source.
    assert "check-marketplace" not in body
