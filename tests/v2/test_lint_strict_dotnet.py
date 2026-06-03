# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""End-to-end tests for the Kusto.Language strict-lint wrapper (G1 / F1.1).

These tests only run when both the `dotnet` CLI and the wrapper DLL at
`tools/kql_strict.dll` are present (`is_available()`). Locally that
means an operator who built the wrapper via `scripts/build_kql_strict`;
on CI the lint.yml and validate.yml workflows publish the DLL before
pytest runs. Without the wrapper, the whole module skips so the suite
stays green on machines without .NET.

F1.1 also ships a schemas.json baseline at `tools/schemas.json` (copied
next to the DLL by `dotnet publish`). When that file is present the
wrapper builds a Kusto.Language GlobalState and promotes findings to
the upstream severity; when missing it falls back to no-schema mode +
warning-only severity. We test both paths.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest

from contentops.lint.strict import is_available, run_strict


if not is_available():
    pytest.skip(
        reason="Kusto.Language wrapper not installed; build via "
               "scripts/build_kql_strict.sh to exercise these tests.",
        allow_module_level=True,
    )


def _write_kql(tmp_path: Path, body: str) -> Path:
    target = tmp_path / "rule.kql"
    target.write_text(body, encoding="utf-8")
    return target


def _wrapper_findings(findings: list) -> list:
    """Filter to wrapper-emitted findings — upstream KS* codes, NOT KQL101 etc."""
    return [f for f in findings if f.rule_id.startswith("KS")]


def test_wrapper_finds_undefined_column(tmp_path: Path) -> None:
    """A reference to a column that doesn't exist on a known table should
    produce a finding from the parser.

    With schemas.json loaded the finding is at the upstream severity
    (typically `error`). Without schemas, the wrapper falls back to
    warning-only and the assertion below allows that too — the schema
    file shouldn't be the blocker for the test running anywhere.
    """
    kql = "SecurityEvent | where NonExistentColumnXYZ == 1"
    path = _write_kql(tmp_path, kql)
    findings = run_strict(path, kql)
    wrapper_findings = _wrapper_findings(findings)
    assert wrapper_findings, (
        f"expected at least one upstream KS* finding for "
        f"NonExistentColumnXYZ; got {findings}"
    )
    severities = {f.severity for f in wrapper_findings}
    assert severities <= {"error", "warning", "info"}, (
        f"unexpected severities: {severities}"
    )


def test_wrapper_clean_query_produces_no_findings(tmp_path: Path) -> None:
    """A trivially-valid KQL query should not emit any wrapper findings."""
    kql = "print 1"
    path = _write_kql(tmp_path, kql)
    findings = run_strict(path, kql)
    assert _wrapper_findings(findings) == [], (
        f"unexpected findings on `print 1`: {findings}"
    )


def test_wrapper_preserves_upstream_rule_code(tmp_path: Path) -> None:
    """The C# wrapper emits the upstream Kusto.Language diagnostic code
    (KSxxx) rather than collapsing every diagnostic to KQL000."""
    kql = "SecurityEvent | where NonExistentColumnXYZ == 1"
    path = _write_kql(tmp_path, kql)
    findings = run_strict(path, kql)
    upstream_codes = {f.rule_id for f in findings if f.rule_id.startswith("KS")}
    assert upstream_codes, (
        "wrapper should emit at least one upstream KS* diagnostic; got "
        f"{[(f.rule_id, f.message) for f in findings]}"
    )


def test_wrapper_resolves_known_sentinel_table_with_schemas(
    tmp_path: Path,
) -> None:
    """When schemas.json is loaded, a real Sentinel table should not
    produce a KS204 'unknown table' finding.

    Skipped when the published DLL has no sibling schemas.json (the
    no-schema fallback path). On CI the publish step copies schemas.json
    next to the DLL so this test exercises the schema-loaded path.
    """
    from contentops.lint.strict import _resolve_wrapper
    wrapper = _resolve_wrapper(Path.cwd())
    if wrapper is None:
        pytest.skip("wrapper not on disk")
    schemas_next_to_dll = wrapper.parent / "schemas.json"
    if not schemas_next_to_dll.exists() or schemas_next_to_dll.stat().st_size == 0:
        pytest.skip("schemas.json not present next to the wrapper DLL")

    kql = "SecurityEvent | take 1"
    path = _write_kql(tmp_path, kql)
    findings = run_strict(path, kql)
    ks204_on_known_table = [
        f for f in findings
        if f.rule_id == "KS204" and "SecurityEvent" in (f.message or "")
    ]
    assert ks204_on_known_table == [], (
        "SecurityEvent is in schemas.json baseline so KS204 should not "
        f"fire; got {ks204_on_known_table}"
    )


def test_wrapper_graceful_degrade_when_schemas_missing(
    tmp_path: Path, monkeypatch,
) -> None:
    """If schemas.json is moved aside, the wrapper still parses and
    emits findings at warning severity (no schema-resolution gating).

    The test temporarily renames the sibling schemas.json so the
    wrapper takes the no-schema fallback path, then restores it.
    """
    from contentops.lint.strict import _resolve_wrapper
    wrapper = _resolve_wrapper(Path.cwd())
    if wrapper is None:
        pytest.skip("wrapper not on disk")
    schemas_next_to_dll = wrapper.parent / "schemas.json"
    if not schemas_next_to_dll.exists():
        # Already in no-schema mode — verify only the warning fallback.
        kql = "SecurityEvent | take 1"
        path = _write_kql(tmp_path, kql)
        findings = run_strict(path, kql)
        for f in _wrapper_findings(findings):
            assert f.severity == "warning", (
                f"no-schema mode expected warning severity; got {f.severity}"
            )
        return

    moved = schemas_next_to_dll.with_suffix(".json.test-moved")
    shutil.move(str(schemas_next_to_dll), str(moved))
    try:
        kql = "SecurityEvent | take 1"
        path = _write_kql(tmp_path, kql)
        findings = run_strict(path, kql)
        # In no-schema fallback mode, SecurityEvent IS an unknown
        # table (KS204) and the wrapper downgrades the finding to
        # warning severity. We assert any wrapper finding stays at
        # warning, not error.
        for f in _wrapper_findings(findings):
            assert f.severity == "warning", (
                f"no-schema fallback expected warning severity; got "
                f"{(f.rule_id, f.severity, f.message)}"
            )
    finally:
        shutil.move(str(moved), str(schemas_next_to_dll))
