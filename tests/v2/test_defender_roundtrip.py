# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for the Defender round-trip diagnostic (pure functions)."""

from __future__ import annotations

from contentops.defender_roundtrip import (
    FieldDiff,
    diff_bodies,
    render_diff,
)


_FIELDS = [
    "displayName",
    "queryCondition.queryText",
    "schedule",
    "actions",
    "alertTemplate.severity",
    "alertTemplate.title",
    "alertTemplate.category",
]


def _base_body() -> dict:
    return {
        "displayName": "Suspicious LDAP Queries",
        "queryCondition": {"queryText": "DeviceEvents | where ActionType == 'LdapSearch'"},
        "schedule": {"period": "1H"},
        "actions": [],
        "alertTemplate": {
            "severity": "medium",
            "title": "Suspicious LDAP Queries",
            "category": "Discovery",
        },
    }


def test_diff_identical_bodies_reports_zero_differences() -> None:
    body = _base_body()
    diffs = diff_bodies(body, body, _FIELDS)
    assert all(not d.differs for d in diffs)
    assert {d.field for d in diffs} == set(_FIELDS)


def test_diff_detects_simple_string_mismatch() -> None:
    local = _base_body()
    remote = _base_body()
    remote["displayName"] = "Suspicious LDAP Queries (renamed)"
    diffs = diff_bodies(local, remote, _FIELDS)
    differing = [d for d in diffs if d.differs]
    assert [d.field for d in differing] == ["displayName"]
    assert "Suspicious LDAP Queries" in differing[0].local_repr
    assert "renamed" in differing[0].remote_repr


def test_diff_detects_nested_field_mismatch() -> None:
    local = _base_body()
    remote = _base_body()
    remote["alertTemplate"]["severity"] = "high"
    diffs = diff_bodies(local, remote, _FIELDS)
    differing = [d for d in diffs if d.differs]
    assert [d.field for d in differing] == ["alertTemplate.severity"]


def test_diff_treats_schedule_iso_normalization_as_a_difference() -> None:
    """A common server normalization: schedule.period '1H' → 'PT1H'.

    This test pins the diagnostic's job: it MUST show the divergence
    so the operator can identify the field to normalize or strip.
    """
    local = _base_body()
    remote = _base_body()
    remote["schedule"] = {"period": "PT1H"}
    diffs = diff_bodies(local, remote, _FIELDS)
    differing = [d for d in diffs if d.differs]
    assert [d.field for d in differing] == ["schedule"]
    assert "1H" in differing[0].local_repr
    assert "PT1H" in differing[0].remote_repr


def test_diff_ignores_dict_key_ordering() -> None:
    """Canonical JSON sorts keys, so ordering differences must NOT
    register as a diff (otherwise every Defender rule would be
    flagged regardless of what the server actually changed)."""
    local = {"alertTemplate": {"severity": "low", "title": "x", "category": "y"}}
    remote = {"alertTemplate": {"category": "y", "title": "x", "severity": "low"}}
    diffs = diff_bodies(local, remote, _FIELDS)
    differing = [d for d in diffs if d.differs]
    assert differing == []


def test_diff_handles_missing_field_on_one_side() -> None:
    local = _base_body()
    remote = _base_body()
    del remote["alertTemplate"]["category"]
    diffs = diff_bodies(local, remote, _FIELDS)
    differing = [d for d in diffs if d.differs]
    assert [d.field for d in differing] == ["alertTemplate.category"]
    assert differing[0].remote_repr == "None"  # _get_path returns None on miss


def test_render_diff_with_no_differences() -> None:
    body = _base_body()
    diffs = diff_bodies(body, body, _FIELDS)
    out = render_diff(diffs, envelope_id="x")
    assert "round-trip OK" in out
    assert "[DIFF]" not in out


def test_render_diff_with_differences_shows_fix_hints() -> None:
    local = _base_body()
    remote = _base_body()
    remote["schedule"] = {"period": "PT1H"}
    diffs = diff_bodies(local, remote, _FIELDS)
    out = render_diff(
        diffs,
        envelope_id="suspicious-ldap-queries",
        display_name="Suspicious LDAP Queries",
        remote_id="17552",
        remote_id_label="Graph ID",
        fix_hint_module="contentops/handlers/defender_custom_detection.py",
    )
    assert "suspicious-ldap-queries" in out
    assert "Suspicious LDAP Queries" in out
    assert "17552" in out
    assert "Graph ID" in out
    assert "[DIFF] schedule" in out
    assert "[OK]" in out  # other fields still pass
    assert "_HASHED_FIELDS" in out  # fix hint
    assert "defender_custom_detection.py" in out  # fix hint module
    assert "1 of 7 field(s) differ" in out


def test_long_value_is_truncated_in_repr() -> None:
    huge_query = "DeviceEvents | " + "where 1==1 | " * 100
    local = _base_body()
    remote = _base_body()
    remote["queryCondition"]["queryText"] = huge_query
    diffs = diff_bodies(local, remote, _FIELDS)
    differing = [d for d in diffs if d.differs]
    assert len(differing) == 1
    # repr should not run away with hundreds of chars
    assert len(differing[0].remote_repr) <= 240


def test_fields_in_order_in_output() -> None:
    body = _base_body()
    diffs = diff_bodies(body, body, _FIELDS)
    assert [d.field for d in diffs] == _FIELDS
