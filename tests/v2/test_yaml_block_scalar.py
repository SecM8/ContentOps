# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Block-scalar contract for collected YAMLs.

Multi-line strings dump as ``|`` literal block scalars (readable +
copy-pasteable into the portal KQL editor). Without this, PyYAML
falls back to double-quoted ``"...\\n..."`` which is unreadable.
"""

from __future__ import annotations

import yaml

from contentops.utils.yaml_io import dump_envelope_yaml


def test_dump_uses_block_scalar_for_multiline() -> None:
    envelope = {
        "id": "a-user-added-an-account-to-a-privileged-role",
        "version": "0.1.0",
        "asset": "sentinel_analytic",
        "status": "production",
        "legacy": True,
        "payload": {
            "query": (
                "let PrivlegedRoles = datatable(displayName:string, id:string)["
                "\n    \"Application Administrator\","
                "\n    \"Cloud Application Administrator\""
                "\n];"
                "\nAuditLogs"
                "\n| where ingestion_time() >= ago(1h)"
            ),
        },
    }
    out = dump_envelope_yaml(envelope)
    assert "query: |" in out
    # No \n escapes anywhere — that would mean double-quoted style.
    assert "\\n" not in out
    # Loads back to the same content (round-trip).
    raw = yaml.safe_load(out)
    assert raw["payload"]["query"].strip().startswith("let PrivlegedRoles")
    assert "Cloud Application Administrator" in raw["payload"]["query"]


def test_dump_round_trip_preserves_special_chars() -> None:
    """KQL with embedded quotes / dollar / backslash / indented blocks
    survives a YAML round-trip in literal block style."""
    payload = {
        "query": (
            "let s = \"a $var with 'mixed' quotes and \\\\path\";\n"
            "T\n"
            "| where col1 == 'x' and col2 == \"y\"\n"
            "| extend z = strcat($s, '-suffix')\n"
        )
    }
    envelope = {
        "id": "test", "version": "0.1.0", "asset": "sentinel_analytic",
        "status": "production", "legacy": True, "payload": payload,
    }
    out = dump_envelope_yaml(envelope)
    assert "query: |" in out
    raw = yaml.safe_load(out)
    # Trailing newline is stripped by the dumper (literal block uses
    # ``|-`` semantics implicitly via PyYAML when the input has no
    # trailing newline). The substantive content must round-trip.
    expected_lines = payload["query"].rstrip().splitlines()
    actual_lines = raw["payload"]["query"].rstrip().splitlines()
    assert expected_lines == actual_lines


def test_dump_strips_trailing_whitespace_per_line() -> None:
    """Trailing spaces on a line block PyYAML from emitting block-style;
    the dumper strips them so block style still applies and the
    payload is unchanged after load."""
    payload = {"query": "line one    \nline two\t\nline three"}
    envelope = {
        "id": "test", "version": "0.1.0", "asset": "sentinel_analytic",
        "status": "production", "legacy": True, "payload": payload,
    }
    out = dump_envelope_yaml(envelope)
    assert "query: |" in out
    raw = yaml.safe_load(out)
    assert raw["payload"]["query"].splitlines() == [
        "line one", "line two", "line three",
    ]


def test_dump_short_string_stays_plain() -> None:
    envelope = {
        "id": "x", "version": "0.1.0", "asset": "sentinel_analytic",
        "status": "production", "legacy": True,
        "payload": {"displayName": "Short", "severity": "Medium"},
    }
    out = dump_envelope_yaml(envelope)
    assert "displayName: Short" in out
    assert "severity: Medium" in out
