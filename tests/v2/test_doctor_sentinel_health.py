# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for the SentinelHealth diagnostic probe in `contentops doctor`."""

from __future__ import annotations

import pytest

from contentops.devex import doctor as doctor_mod
from contentops.devex.doctor import CheckResult


def test_sentinel_health_check_exists() -> None:
    """The check function must be importable from the doctor module."""
    assert callable(getattr(doctor_mod, "_check_sentinel_health"))


def test_sentinel_health_runs_when_auth_enabled(monkeypatch) -> None:
    """`run_checks(with_auth=True)` includes the SentinelHealth probe.

    Stubs all the auth-requiring checks so we don't actually hit Azure.
    The point is to verify the registration, not the probe behaviour.
    """
    stub = CheckResult("stub", "WARN", "stub")
    monkeypatch.setattr(doctor_mod, "_check_token_acquisition", lambda: stub)
    monkeypatch.setattr(doctor_mod, "_check_workspace_reachable", lambda: stub)
    monkeypatch.setattr(doctor_mod, "_check_sentinel_health",
                        lambda: CheckResult("sentinel_health", "PASS", "ok"))
    monkeypatch.setattr(doctor_mod, "_check_graph_reachable", lambda: stub)
    results = doctor_mod.run_checks(with_auth=True)
    names = [r.name for r in results]
    assert "sentinel_health" in names


def test_sentinel_health_skipped_without_auth() -> None:
    """Without `--auth`, the probe is skipped (just like the others)."""
    results = doctor_mod.run_checks(with_auth=False)
    names = [r.name for r in results]
    assert "sentinel_health" not in names


def test_sentinel_health_handles_import_error(monkeypatch) -> None:
    """Defensive: if `contentops.workspace_kql` can't be imported, the
    check returns WARN rather than raising. Keeps doctor robust on
    minimal installs."""
    import sys
    monkeypatch.setitem(sys.modules, "contentops.workspace_kql", None)
    result = doctor_mod._check_sentinel_health()
    assert result.name == "sentinel_health"
    assert result.status == "WARN"


def test_sentinel_health_warns_on_zero_rows(monkeypatch) -> None:
    """Zero rows means either healthy + diagnostic-on (rare for a
    busy tenant) OR diagnostic off. Default to WARN so operators see
    the prompt to verify."""
    from contentops.workspace_kql import QueryResult

    class _StubCred:
        def get_token(self, *_a, **_kw):
            class _T:
                token = "tok"
            return _T()

    monkeypatch.setattr(
        "contentops.utils.auth.get_credential", lambda: _StubCred(),
    )
    monkeypatch.setattr(
        "contentops.workspace_kql.resolve_workspace_id",
        lambda **kw: "00000000-0000-0000-0000-000000000000",
    )
    monkeypatch.setattr(
        "contentops.workspace_kql.query",
        lambda *a, **kw: QueryResult(rows=[], column_names=[]),
    )
    result = doctor_mod._check_sentinel_health()
    assert result.status == "WARN"
    assert "SentinelHealth" in result.detail
    assert "auto-disabled-rules" in result.detail


def test_sentinel_health_passes_on_data(monkeypatch) -> None:
    from contentops.workspace_kql import QueryResult

    class _StubCred:
        def get_token(self, *_a, **_kw):
            class _T:
                token = "tok"
            return _T()

    monkeypatch.setattr(
        "contentops.utils.auth.get_credential", lambda: _StubCred(),
    )
    monkeypatch.setattr(
        "contentops.workspace_kql.resolve_workspace_id",
        lambda **kw: "00000000-0000-0000-0000-000000000000",
    )
    monkeypatch.setattr(
        "contentops.workspace_kql.query",
        lambda *a, **kw: QueryResult(
            rows=[{"TimeGenerated": "2026-05-21T12:00:00Z"}],
            column_names=["TimeGenerated"],
        ),
    )
    result = doctor_mod._check_sentinel_health()
    assert result.status == "PASS"
    assert "auto-disabled-rules" in result.detail
