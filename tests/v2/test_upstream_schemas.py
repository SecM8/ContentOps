# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for `contentops upstream check-schemas` (F1.1)."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
from click.testing import CliRunner

from contentops.cli import cli
from contentops.upstream.schemas import fetch_schemas


# ---------------------------------------------------------------------------
# fetch_schemas — pure function tests via httpx.MockTransport
# ---------------------------------------------------------------------------


def _mock_transport(handler):
    return httpx.MockTransport(handler)


def _metadata_body(*tables: tuple[str, list[tuple[str, str]]]) -> dict:
    """Build the LA metadata body shape from `(name, [(col, type)])` tuples."""
    return {
        "tables": [
            {
                "name": name,
                "columns": [{"name": c, "type": t} for c, t in cols],
            }
            for name, cols in tables
        ],
    }


def test_fetch_schemas_happy_path() -> None:
    def _h(request: httpx.Request) -> httpx.Response:
        assert request.url.path.endswith("/v1/workspaces/ws-123/metadata")
        assert request.headers["Authorization"] == "Bearer tok"
        return httpx.Response(200, json=_metadata_body(
            ("AuditLogs", [("TimeGenerated", "datetime"), ("OperationName", "string")]),
            ("DeviceEvents", [("Timestamp", "datetime"), ("DeviceId", "string")]),
        ))

    out = fetch_schemas(
        workspace_id="ws-123", token="tok", transport=_mock_transport(_h),
    )
    # Sorted by name.
    assert [t["name"] for t in out] == ["AuditLogs", "DeviceEvents"]
    assert out[0]["columns"][0] == {"name": "TimeGenerated", "type": "datetime"}


def test_fetch_schemas_drops_unnamed_tables_and_columns() -> None:
    def _h(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={
            "tables": [
                {"name": "", "columns": [{"name": "X", "type": "string"}]},  # dropped
                {"name": "GoodTable", "columns": [
                    {"name": "", "type": "string"},          # dropped
                    {"name": "Y", "type": ""},               # dropped (missing type)
                    {"name": "Z", "type": "string"},
                ]},
            ],
        })

    out = fetch_schemas(
        workspace_id="ws", token="t", transport=_mock_transport(_h),
    )
    assert len(out) == 1
    assert out[0]["name"] == "GoodTable"
    assert out[0]["columns"] == [{"name": "Z", "type": "string"}]


def test_fetch_schemas_empty_workspace_id_raises() -> None:
    with pytest.raises(ValueError):
        fetch_schemas(workspace_id="", token="t")


def test_fetch_schemas_propagates_4xx() -> None:
    def _h(request):
        return httpx.Response(403, text="forbidden")

    with pytest.raises(httpx.HTTPStatusError):
        fetch_schemas(
            workspace_id="ws", token="t", transport=_mock_transport(_h),
        )


# ---------------------------------------------------------------------------
# CLI integration via CliRunner — mocks workspace_kql + the LA fetch
# ---------------------------------------------------------------------------


def _patch_auth(monkeypatch) -> None:
    """Replace get_credential() with a stub returning a constant token."""
    import contentops.utils.auth as auth_mod

    class _Tok:
        token = "stub"

    class _Cred:
        def get_token(self, *a, **kw):
            return _Tok()

    monkeypatch.setattr(auth_mod, "get_credential", lambda: _Cred())


def _patch_fetch(monkeypatch, tables: list[dict]) -> None:
    """Replace fetch_schemas() in the CLI module's import scope."""
    import contentops.cli.commands.upstream as upstream_mod
    monkeypatch.setattr(
        upstream_mod, "fetch_schemas",
        lambda *a, **kw: tables,
        raising=False,
    )
    # Also patch the source module so the CLI's lazy import resolves.
    import contentops.upstream.schemas as schemas_mod
    monkeypatch.setattr(schemas_mod, "fetch_schemas", lambda *a, **kw: tables)


def test_cli_falls_back_to_autoderive_when_workspace_id_missing(
    tmp_path: Path, monkeypatch,
) -> None:
    """PR-J: --workspace-id used to be required at parse time; now it
    auto-derives from tenant.yml. Without tenant.yml in the test env
    the resolve_workspace_id helper raises WorkspaceKqlError which the
    CLI surfaces as exit 1."""
    monkeypatch.delenv("PIPELINE_WORKSPACE_ID", raising=False)
    _patch_auth(monkeypatch)
    # No tenant.yml in the test cwd → auto-derive fails.
    result = CliRunner().invoke(cli, ["upstream", "check-schemas"])
    assert result.exit_code == 1
    assert (
        "Tenant config not found" in result.output
        or "auto-derive" in result.output
        or "tenant.yml" in result.output
    )


def test_cli_dry_run_lists_added(
    tmp_path: Path, monkeypatch,
) -> None:
    _patch_auth(monkeypatch)
    _patch_fetch(monkeypatch, [
        {"name": "AuditLogs", "columns": [{"name": "TimeGenerated", "type": "datetime"}]},
    ])
    schemas = tmp_path / "schemas.json"

    result = CliRunner().invoke(cli, [
        "upstream", "check-schemas",
        "--workspace-id", "ws-1",
        "--schemas", str(schemas),
        "--out", str(tmp_path / "whatsnew"),
    ])
    assert result.exit_code == 0, result.output
    assert "added (1)" in result.output
    # Dry-run: schemas.json must not exist.
    assert not schemas.exists()


def test_cli_write_creates_schemas_and_whatsnew(
    tmp_path: Path, monkeypatch,
) -> None:
    _patch_auth(monkeypatch)
    _patch_fetch(monkeypatch, [
        {"name": "AuditLogs", "columns": [{"name": "TimeGenerated", "type": "datetime"}]},
        {"name": "DeviceEvents", "columns": [{"name": "Timestamp", "type": "datetime"}]},
    ])
    schemas = tmp_path / "schemas.json"
    whatsnew = tmp_path / "whatsnew"

    result = CliRunner().invoke(cli, [
        "upstream", "check-schemas", "--write",
        "--workspace-id", "ws-1",
        "--schemas", str(schemas),
        "--out", str(whatsnew),
    ])
    assert result.exit_code == 0, result.output
    assert schemas.exists()

    raw = json.loads(schemas.read_text(encoding="utf-8"))
    assert raw["schema_version"] == 1
    assert raw["database"] == "SentinelDefender"
    assert [t["name"] for t in raw["tables"]] == ["AuditLogs", "DeviceEvents"]
    assert raw["tables"][0]["columns"][0] == {
        "name": "TimeGenerated", "type": "datetime",
    }

    md_files = list(whatsnew.glob("*-schemas.md"))
    assert len(md_files) == 1
    body = md_files[0].read_text(encoding="utf-8")
    assert "KQL workspace schemas" in body


def test_cli_no_diff_is_idempotent(
    tmp_path: Path, monkeypatch,
) -> None:
    _patch_auth(monkeypatch)
    tables = [
        {"name": "AuditLogs", "columns": [{"name": "TimeGenerated", "type": "datetime"}]},
    ]
    schemas = tmp_path / "schemas.json"
    whatsnew = tmp_path / "whatsnew"

    # First run populates.
    _patch_fetch(monkeypatch, tables)
    CliRunner().invoke(cli, [
        "upstream", "check-schemas", "--write",
        "--workspace-id", "ws", "--schemas", str(schemas), "--out", str(whatsnew),
    ])
    first_bytes = schemas.read_bytes()
    first_files = sorted(p.name for p in whatsnew.glob("*-schemas.md"))

    # Second run with identical input writes nothing new.
    _patch_fetch(monkeypatch, tables)
    result = CliRunner().invoke(cli, [
        "upstream", "check-schemas", "--write",
        "--workspace-id", "ws", "--schemas", str(schemas), "--out", str(whatsnew),
    ])
    assert result.exit_code == 0
    assert "no changes" in result.output
    assert schemas.read_bytes() == first_bytes
    assert sorted(p.name for p in whatsnew.glob("*-schemas.md")) == first_files


def test_cli_column_added_shows_as_changed(
    tmp_path: Path, monkeypatch,
) -> None:
    """Adding a column to an existing table surfaces as a `changed` entry."""
    _patch_auth(monkeypatch)
    schemas = tmp_path / "schemas.json"
    whatsnew = tmp_path / "whatsnew"

    # Baseline: one column.
    _patch_fetch(monkeypatch, [{
        "name": "AuditLogs",
        "columns": [{"name": "TimeGenerated", "type": "datetime"}],
    }])
    CliRunner().invoke(cli, [
        "upstream", "check-schemas", "--write",
        "--workspace-id", "ws", "--schemas", str(schemas), "--out", str(whatsnew),
    ])

    # New baseline: one extra column.
    _patch_fetch(monkeypatch, [{
        "name": "AuditLogs",
        "columns": [
            {"name": "TimeGenerated", "type": "datetime"},
            {"name": "OperationName", "type": "string"},
        ],
    }])
    result = CliRunner().invoke(cli, [
        "upstream", "check-schemas",
        "--workspace-id", "ws", "--schemas", str(schemas), "--out", str(whatsnew),
    ])
    assert result.exit_code == 0, result.output
    assert "changed (1)" in result.output


# ---------------------------------------------------------------------------
# filter_excluded_tables — drop operator scratch/test tables
# ---------------------------------------------------------------------------


def test_filter_excluded_tables_drops_matches_case_insensitively() -> None:
    from contentops.upstream.schemas import filter_excluded_tables
    tables = [
        {"name": "SigninLogs", "columns": []},
        {"name": "TestMe_KQL_CL", "columns": []},
        {"name": "SuspiciousUA_CL", "columns": []},
        {"name": "DeviceEvents", "columns": []},
    ]
    kept, dropped = filter_excluded_tables(tables, ("test*", "SuspiciousUA*"))
    assert {t["name"] for t in kept} == {"SigninLogs", "DeviceEvents"}
    assert sorted(dropped) == ["SuspiciousUA_CL", "TestMe_KQL_CL"]


def test_filter_excluded_tables_empty_patterns_is_noop() -> None:
    from contentops.upstream.schemas import filter_excluded_tables
    tables = [{"name": "SigninLogs", "columns": []}]
    kept, dropped = filter_excluded_tables(tables, ())
    assert kept is tables          # no copy when nothing to exclude
    assert dropped == []
