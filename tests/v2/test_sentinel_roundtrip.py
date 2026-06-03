# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for the Sentinel roundtrip-diff diagnostic (Phase 5).

Covers:

* Per-handler ``_strip_server_fields`` correctness for analytic,
  hunting, parser, watchlist, and data_connector.
* Dispatch from asset kind -> right handler's helpers via
  ``contentops.sentinel_roundtrip.dispatch_for_asset``.
* Shared diff/render helpers (extracted to
  ``contentops.utils.roundtrip_diff``) work for the Sentinel side
  too (the Defender tests already pin the renderer's basic shape).

The CLI command itself (``sentinel-roundtrip-diff``) requires a
live ARM provider for end-to-end testing; the dispatch + strip +
diff are unit-tested here without network.
"""

from __future__ import annotations

import pytest

from contentops.core.asset import Asset
from contentops.handlers.sentinel_analytic import (
    _strip_server_fields as analytic_strip,
)
from contentops.handlers.sentinel_data_connector import (
    _strip_server_fields as connector_strip,
)
from contentops.handlers.sentinel_hunting import (
    _strip_server_fields as hunting_strip,
)
from contentops.handlers.sentinel_parser import (
    _strip_server_fields as parser_strip,
)
from contentops.handlers.sentinel_watchlist import (
    _strip_server_fields as watchlist_strip,
)
from contentops.sentinel_roundtrip import dispatch_for_asset
from contentops.utils.roundtrip_diff import diff_bodies, render_diff


# ---------------------------------------------------------------------------
# Per-handler strip
# ---------------------------------------------------------------------------


def test_analytic_strip_removes_server_fields() -> None:
    remote = {
        "etag": "abc",
        "type": "Microsoft.SecurityInsights/alertRules",
        "systemData": {"createdAt": "2026-05-13T10:00:00Z"},
        "properties": {
            "displayName": "X", "query": "SecurityEvent | take 1",
            "lastModifiedUtc": "2026-05-13T10:00:00Z",
        },
    }
    cleaned = analytic_strip(remote)
    assert "etag" not in cleaned
    assert "type" not in cleaned
    assert "systemData" not in cleaned
    assert "lastModifiedUtc" not in cleaned["properties"]
    # Authored fields preserved.
    assert cleaned["properties"]["displayName"] == "X"
    # Original is not mutated.
    assert "etag" in remote
    assert "lastModifiedUtc" in remote["properties"]


def test_hunting_strip_removes_server_fields() -> None:
    remote = {
        "etag": "abc", "type": "T", "systemData": {},
        "properties": {"displayName": "Q", "etag": "x"},
    }
    cleaned = hunting_strip(remote)
    assert cleaned == {"properties": {"displayName": "Q"}}


def test_parser_strip_removes_server_fields() -> None:
    remote = {
        "etag": "abc", "type": "T", "systemData": {},
        "properties": {"displayName": "P", "etag": "x", "version": 5},
    }
    cleaned = parser_strip(remote)
    assert cleaned == {"properties": {"displayName": "P"}}


def test_watchlist_strip_removes_server_fields() -> None:
    remote = {
        "etag": "abc", "type": "T", "systemData": {},
        "properties": {
            "displayName": "W", "etag": "x", "created": "...",
            "updated": "...", "createdBy": "...", "updatedBy": "...",
            "watchlistId": "g", "tenantId": "t",
            "watchlistAlias": "a", "isDeleted": False,
            "provisioningState": "Succeeded",
            "itemsSearchKey": "Name",
        },
    }
    cleaned = watchlist_strip(remote)
    # Every server property is stripped.
    assert cleaned["properties"] == {"displayName": "W", "itemsSearchKey": "Name"}
    # Top-level server fields stripped too.
    assert "etag" not in cleaned and "systemData" not in cleaned


def test_data_connector_strip_removes_server_fields() -> None:
    remote = {
        "etag": "x", "type": "T", "systemData": {},
        "kind": "Office365",
        "properties": {
            "tenantId": "t", "etag": "x",
            "lastModifiedUtc": "2026-05-13T10:00:00Z",
            "connectorUiConfig": {"title": "Office 365"},
            "dataTypes": {"Exchange": {"state": "enabled"}},
        },
    }
    cleaned = connector_strip(remote)
    assert "connectorUiConfig" not in cleaned["properties"]
    assert "lastModifiedUtc" not in cleaned["properties"]
    assert cleaned["properties"]["dataTypes"] == {
        "Exchange": {"state": "enabled"},
    }
    assert cleaned["kind"] == "Office365"


def test_strip_is_pure_does_not_mutate_input() -> None:
    """Defensive-copy guarantee across all 5 strip functions."""
    cases = [
        (analytic_strip, {"etag": "a", "properties": {"lastModifiedUtc": "x"}}),
        (hunting_strip, {"etag": "a", "properties": {"etag": "x"}}),
        (parser_strip, {"etag": "a", "properties": {"version": 1}}),
        (watchlist_strip, {"etag": "a", "properties": {"etag": "x"}}),
        (connector_strip, {"etag": "a", "properties": {"etag": "x"}}),
    ]
    for strip, body in cases:
        snapshot = {k: dict(v) if isinstance(v, dict) else v for k, v in body.items()}
        strip(body)
        assert body == snapshot, f"{strip.__name__} mutated its input"


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------


def test_dispatch_for_analytic() -> None:
    d = dispatch_for_asset(Asset.SENTINEL_ANALYTIC)
    assert d.resource == "alertRules"
    # Analytic dispatches on kind.
    fields = d.hashed_fields({"kind": "Scheduled"})
    assert "properties.query" in fields
    nrt_fields = d.hashed_fields({"kind": "NRT"})
    # NRT projection is shorter than Scheduled.
    assert len(nrt_fields) < len(fields)


def test_dispatch_for_hunting() -> None:
    d = dispatch_for_asset(Asset.SENTINEL_HUNTING)
    assert d.resource == "savedSearches"
    fields = d.hashed_fields({})
    assert "properties.query" in fields
    assert "properties.category" in fields


def test_dispatch_for_parser() -> None:
    d = dispatch_for_asset(Asset.SENTINEL_PARSER)
    assert d.resource == "savedSearches"
    fields = d.hashed_fields({})
    assert "properties.functionAlias" in fields


def test_dispatch_for_watchlist() -> None:
    d = dispatch_for_asset(Asset.SENTINEL_WATCHLIST)
    assert d.resource == "watchlists"
    fields = d.hashed_fields({})
    assert "properties.itemsSearchKey" in fields


def test_dispatch_rejects_data_connector() -> None:
    """Data connector uses _projection() not _HASHED_FIELDS; the
    diagnostic doesn't currently support it. Exit cleanly with a
    clear ValueError."""
    with pytest.raises(ValueError, match="data_connector"):
        dispatch_for_asset(Asset.SENTINEL_DATA_CONNECTOR)


def test_dispatch_rejects_defender() -> None:
    """Defender has its own diagnostic; the Sentinel dispatch should
    refuse cleanly rather than silently dispatch to nothing."""
    with pytest.raises(ValueError, match="defender-roundtrip-diff"):
        dispatch_for_asset(Asset.DEFENDER_CUSTOM_DETECTION)


# ---------------------------------------------------------------------------
# H1 regression: hunting + parser must dispatch via la_resource_url, not
# get_resource (the SecurityInsights namespace path 404s for savedSearches)
# ---------------------------------------------------------------------------


def test_hunting_dispatch_uses_la_path() -> None:
    """Regression: hunting savedSearches live under the LA workspace
    path (`Microsoft.OperationalInsights/...`), not the SecurityInsights
    namespace. Without ``use_la_path=True`` the diagnostic 404s for
    every hunting rule. PR #142 review H1."""
    d = dispatch_for_asset(Asset.SENTINEL_HUNTING)
    assert d.use_la_path is True


def test_parser_dispatch_uses_la_path() -> None:
    """Regression: parsers are also savedSearches; same URL-base bug
    as hunting. PR #142 review H1."""
    d = dispatch_for_asset(Asset.SENTINEL_PARSER)
    assert d.use_la_path is True


def test_analytic_dispatch_uses_securityinsights_path() -> None:
    """Counterpart to the H1 regression tests: alertRules are under
    the SecurityInsights namespace, so analytic must NOT use the LA
    path. ``use_la_path`` defaults False -- pin it."""
    d = dispatch_for_asset(Asset.SENTINEL_ANALYTIC)
    assert d.use_la_path is False


def test_watchlist_dispatch_uses_securityinsights_path() -> None:
    """Watchlists are also under SecurityInsights."""
    d = dispatch_for_asset(Asset.SENTINEL_WATCHLIST)
    assert d.use_la_path is False


# ---------------------------------------------------------------------------
# M1: provisioningState consistency across analytic / hunting / parser /
# watchlist strip sets
# ---------------------------------------------------------------------------


def test_analytic_strip_removes_provisioningState() -> None:
    """PR #142 review M1: provisioningState is in watchlist strip set;
    add it to analytic for consistency."""
    remote = {"properties": {"displayName": "X", "provisioningState": "Succeeded"}}
    cleaned = analytic_strip(remote)
    assert "provisioningState" not in cleaned["properties"]


def test_hunting_strip_removes_provisioningState() -> None:
    """PR #142 review M1."""
    remote = {"properties": {"displayName": "X", "provisioningState": "Succeeded"}}
    cleaned = hunting_strip(remote)
    assert "provisioningState" not in cleaned["properties"]


def test_parser_strip_removes_provisioningState() -> None:
    """PR #142 review M1."""
    remote = {"properties": {"displayName": "X", "provisioningState": "Succeeded"}}
    cleaned = parser_strip(remote)
    assert "provisioningState" not in cleaned["properties"]


# ---------------------------------------------------------------------------
# M2: watchlist strip set covers itemsCount + numberOfLinesToSkip
# ---------------------------------------------------------------------------


def test_watchlist_strip_removes_itemsCount_and_numberOfLinesToSkip() -> None:
    """PR #142 review M2: itemsCount is server-computed, not authored;
    numberOfLinesToSkip's no-op default is dropped at to_envelope time;
    both should be in the strip set so a future _HASHED_FIELDS
    addition can't silently produce false positives."""
    remote = {
        "properties": {
            "displayName": "W", "itemsSearchKey": "Name",
            "itemsCount": 42, "numberOfLinesToSkip": 0,
        },
    }
    cleaned = watchlist_strip(remote)
    assert "itemsCount" not in cleaned["properties"]
    assert "numberOfLinesToSkip" not in cleaned["properties"]
    # Authored fields preserved.
    assert cleaned["properties"]["displayName"] == "W"
    assert cleaned["properties"]["itemsSearchKey"] == "Name"


# ---------------------------------------------------------------------------
# L3: defender envelope rejection includes pointer to defender-roundtrip-diff
# ---------------------------------------------------------------------------


def test_defender_rejection_message_points_to_defender_command() -> None:
    """PR #142 review L3: an operator who runs sentinel-roundtrip-diff
    on a Defender envelope should be told which command to use
    instead, not just 'unsupported'."""
    with pytest.raises(ValueError, match="defender-roundtrip-diff"):
        dispatch_for_asset(Asset.DEFENDER_CUSTOM_DETECTION)


# ---------------------------------------------------------------------------
# End-to-end diff via shared renderer
# ---------------------------------------------------------------------------


def test_diff_clean_when_no_field_drift() -> None:
    """When local and remote agree under the projection, no field
    differs -- the render output reports round-trip OK."""
    body = {
        "properties": {
            "displayName": "X", "query": "SecurityEvent | take 1",
            "severity": "Medium", "tactics": ["Execution"],
            "queryFrequency": "PT5M", "queryPeriod": "PT5M",
            "triggerOperator": "GreaterThan", "triggerThreshold": 0,
            "enabled": True,
        },
    }
    d = dispatch_for_asset(Asset.SENTINEL_ANALYTIC)
    fields = d.hashed_fields(body)
    diffs = diff_bodies(body, body, fields)
    out = render_diff(
        diffs,
        envelope_id="x",
        remote_id="x",
        remote_id_label="ARM name",
        fix_hint_module="contentops/handlers/sentinel_analytic.py",
    )
    assert "round-trip OK" in out
    assert "[DIFF]" not in out
    assert "ARM name" in out


def test_diff_flags_field_drift() -> None:
    """A field that differs after the strip is reported as [DIFF]."""
    base = {
        "properties": {
            "displayName": "X", "query": "Q", "severity": "Medium",
            "tactics": [], "queryFrequency": "PT5M", "queryPeriod": "PT5M",
            "triggerOperator": "GreaterThan", "triggerThreshold": 0,
            "enabled": True,
        },
    }
    drifted = {
        "properties": {**base["properties"], "severity": "High"},
    }
    d = dispatch_for_asset(Asset.SENTINEL_ANALYTIC)
    fields = d.hashed_fields(base)
    diffs = diff_bodies(base, drifted, fields)
    severity_diff = next(d for d in diffs if d.field == "properties.severity")
    assert severity_diff.differs
    assert "Medium" in severity_diff.local_repr
    assert "High" in severity_diff.remote_repr


# ---------------------------------------------------------------------------
# Shared renderer used by Defender continues to work via the shim
# ---------------------------------------------------------------------------


def test_defender_roundtrip_module_re_exports_renderer() -> None:
    """The shim at contentops.defender_roundtrip preserves the import
    surface that the existing Defender diagnostic relies on."""
    from contentops.defender_roundtrip import (
        FieldDiff as ShimFieldDiff,
        diff_bodies as shim_diff,
        render_diff as shim_render,
    )
    from contentops.utils.roundtrip_diff import (
        FieldDiff as CanonicalFieldDiff,
        diff_bodies as canonical_diff,
        render_diff as canonical_render,
    )
    assert ShimFieldDiff is CanonicalFieldDiff
    assert shim_diff is canonical_diff
    assert shim_render is canonical_render
