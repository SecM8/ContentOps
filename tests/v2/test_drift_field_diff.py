# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for `contentops.core.drift.field_diff` (G2 diagnostics)."""

from __future__ import annotations

from contentops.core.drift import FieldDiff, field_diff


def test_field_diff_returns_empty_for_equal_payloads() -> None:
    a = {"x": 1, "y": [1, 2, 3]}
    assert field_diff(a, dict(a)) == []


def test_field_diff_normalises_strings_before_comparing() -> None:
    """Trailing whitespace and CRLF should not produce false diffs."""
    local = {"q": "line1\nline2\n"}
    remote = {"q": "line1  \r\nline2\r\n"}
    assert field_diff(local, remote) == []


def test_field_diff_flags_added_keys() -> None:
    diffs = field_diff({"a": 1}, {"a": 1, "b": 2})
    assert diffs == [FieldDiff("b", "added", "", "2")]


def test_field_diff_flags_removed_keys() -> None:
    diffs = field_diff({"a": 1, "b": 2}, {"a": 1})
    assert diffs == [FieldDiff("b", "removed", "2", "")]


def test_field_diff_flags_modified_scalars() -> None:
    diffs = field_diff({"a": 1}, {"a": 2})
    assert diffs == [FieldDiff("a", "modified", "1", "2")]


def test_field_diff_walks_nested_dicts() -> None:
    local = {"outer": {"inner": "old"}}
    remote = {"outer": {"inner": "new"}}
    assert field_diff(local, remote) == [
        FieldDiff("outer.inner", "modified", "'old'", "'new'"),
    ]


def test_field_diff_reports_added_inside_nested_dict() -> None:
    local = {"outer": {"a": 1}}
    remote = {"outer": {"a": 1, "b": 2}}
    assert field_diff(local, remote) == [
        FieldDiff("outer.b", "added", "", "2"),
    ]


def test_field_diff_treats_lists_as_opaque_at_their_path() -> None:
    """Lists with different elements report a single modified entry,
    not per-index diffs. Trade-off: simpler output, no insert/delete
    confusion."""
    diffs = field_diff({"items": [1, 2]}, {"items": [1, 2, 3]})
    assert len(diffs) == 1
    assert diffs[0].key == "items"
    assert diffs[0].kind == "modified"


def test_field_diff_truncates_long_repr() -> None:
    long_value = "x" * 500
    diffs = field_diff({"a": ""}, {"a": long_value})
    assert len(diffs) == 1
    assert len(diffs[0].remote_repr) <= 80
    assert diffs[0].remote_repr.endswith("...")


def test_field_diff_g2_simulation_extra_remote_field() -> None:
    """Reproduce the G2 shape: remote returns a key the local YAML
    doesn't have. The diff should surface exactly that key."""
    local = {
        "displayName": "Suspicious LDAP Queries",
        "isEnabled": True,
        "schedule": {"period": "1H"},
    }
    remote = {
        "displayName": "Suspicious LDAP Queries",
        "isEnabled": True,
        "schedule": {"period": "1H"},
        # A field returned by the API that v1 collect didn't strip
        # but the v2 to_envelope also doesn't strip — drift goldfish.
        "tenantId": "deadbeef-0000-0000-0000-000000000000",
    }
    diffs = field_diff(local, remote)
    assert len(diffs) == 1
    assert diffs[0].key == "tenantId"
    assert diffs[0].kind == "added"
