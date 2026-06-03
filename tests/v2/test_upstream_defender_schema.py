# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for contentops/upstream/defender_schema.py + CLI integration."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
from click.testing import CliRunner

from contentops.cli import cli
from contentops.upstream.defender_schema import (
    DefenderSchemaError,
    fetch_defender_schemas,
    fetch_table_schema,
)


def _mock_transport(handler):
    return httpx.MockTransport(handler)


def _getschema_body(rows: list[tuple[str, str]]) -> dict:
    return {
        "schema": [
            {"name": "ColumnName", "type": "String"},
            {"name": "ColumnType", "type": "String"},
        ],
        "results": [{"ColumnName": n, "ColumnType": t} for n, t in rows],
    }


# ---------------------------------------------------------------------------
# fetch_table_schema
# ---------------------------------------------------------------------------


def test_fetch_table_schema_normalises_response() -> None:
    def _h(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/v1.0/security/runHuntingQuery"
        body = json.loads(request.content)
        assert "DeviceEvents | getschema" in body["Query"]
        return httpx.Response(200, json=_getschema_body([
            ("Timestamp", "DateTime"),
            ("DeviceId", "String"),
        ]))

    out = fetch_table_schema(
        "DeviceEvents", token="tok", transport=_mock_transport(_h),
    )
    assert out == [
        {"name": "Timestamp", "type": "datetime"},
        {"name": "DeviceId", "type": "string"},
    ]


def test_fetch_table_schema_empty_name_raises() -> None:
    with pytest.raises(DefenderSchemaError):
        fetch_table_schema("", token="tok")
    with pytest.raises(DefenderSchemaError):
        fetch_table_schema("   ", token="tok")


def test_fetch_table_schema_401_carries_permission_hint() -> None:
    def _h(_request):
        return httpx.Response(401, text="unauthorized")

    with pytest.raises(DefenderSchemaError) as exc_info:
        fetch_table_schema(
            "DeviceEvents", token="tok", transport=_mock_transport(_h),
        )
    assert "ThreatHunting.Read.All" in str(exc_info.value)
    assert "401" in str(exc_info.value)


def test_fetch_table_schema_403_also_carries_permission_hint() -> None:
    def _h(_request):
        return httpx.Response(403, text="forbidden")

    with pytest.raises(DefenderSchemaError) as exc_info:
        fetch_table_schema(
            "DeviceEvents", token="tok", transport=_mock_transport(_h),
        )
    assert "ThreatHunting.Read.All" in str(exc_info.value)


def test_fetch_table_schema_404_distinct_error() -> None:
    """404 carries 'tenant entitlement' wording so the caller can detect-skip."""
    def _h(_request):
        return httpx.Response(404, text="table not found")

    with pytest.raises(DefenderSchemaError) as exc_info:
        fetch_table_schema(
            "DeviceFooBar", token="tok", transport=_mock_transport(_h),
        )
    assert "404" in str(exc_info.value)
    assert "entitlement" in str(exc_info.value)


def test_fetch_table_schema_400_resolve_table_treated_as_entitlement_gap() -> None:
    """Graph returns 400 'Failed to resolve table' for tables the tenant's
    entitlement doesn't include (e.g. Defender Vulnerability Management
    Add-on tables on a base license). Same shape as 404 — skip-and-preserve."""
    def _h(_request):
        return httpx.Response(400, text=(
            '{"error":{"code":"BadRequest","message":'
            '"\'getschema\' operator: Failed to resolve table or column '
            'expression named \'DeviceBaselineComplianceAssessment\'."}}'
        ))

    with pytest.raises(DefenderSchemaError) as exc_info:
        fetch_table_schema(
            "DeviceBaselineComplianceAssessment",
            token="tok", transport=_mock_transport(_h),
        )
    assert "entitlement" in str(exc_info.value)


def test_fetch_defender_schemas_skips_400_resolve_errors() -> None:
    """The fetch-all wrapper treats 400-resolve same as 404: skip + preserve."""
    def fake_fetch(name, **_kw):
        if name == "DeviceBaselineComplianceAssessment":
            raise DefenderSchemaError(
                f"Graph runHuntingQuery returned 400 for {name!r}; "
                "table not reachable in this tenant's Defender entitlement."
            )
        return [{"name": "Col", "type": "string"}]

    refreshed, skipped = fetch_defender_schemas(
        ["DeviceEvents", "DeviceBaselineComplianceAssessment"],
        fetch_fn=fake_fetch,
    )
    assert [r["name"] for r in refreshed] == ["DeviceEvents"]
    assert skipped == ["DeviceBaselineComplianceAssessment"]


def test_fetch_table_schema_drops_unnamed_columns() -> None:
    def _h(_request):
        return httpx.Response(200, json={
            "schema": [],
            "results": [
                {"ColumnName": "", "ColumnType": "String"},     # dropped
                {"ColumnName": "X", "ColumnType": ""},          # dropped
                {"ColumnName": "Good", "ColumnType": "string"},
            ],
        })

    out = fetch_table_schema(
        "T", token="tok", transport=_mock_transport(_h),
    )
    assert out == [{"name": "Good", "type": "string"}]


# ---------------------------------------------------------------------------
# fetch_defender_schemas
# ---------------------------------------------------------------------------


def test_fetch_defender_schemas_collects_columns_per_table() -> None:
    def fake_fetch(name, **_kw):
        return [{"name": "TimestampOf" + name, "type": "datetime"}]

    refreshed, skipped = fetch_defender_schemas(
        ["DeviceEvents", "DeviceFileEvents"], fetch_fn=fake_fetch,
    )
    assert [r["name"] for r in refreshed] == ["DeviceEvents", "DeviceFileEvents"]
    assert skipped == []


def test_fetch_defender_schemas_preserves_404_tables_in_skipped_list() -> None:
    def fake_fetch(name, **_kw):
        if name == "DeviceGhost":
            raise DefenderSchemaError(
                f"Graph runHuntingQuery returned 404 for {name!r}; "
                "tenant entitlement gap."
            )
        return [{"name": "Col", "type": "string"}]

    refreshed, skipped = fetch_defender_schemas(
        ["DeviceEvents", "DeviceGhost", "DeviceFileEvents"], fetch_fn=fake_fetch,
    )
    assert [r["name"] for r in refreshed] == ["DeviceEvents", "DeviceFileEvents"]
    assert skipped == ["DeviceGhost"]


def test_fetch_defender_schemas_propagates_non_404_errors() -> None:
    def fake_fetch(name, **_kw):
        raise DefenderSchemaError(
            "Graph runHuntingQuery returned 401; grant ThreatHunting.Read.All"
        )

    with pytest.raises(DefenderSchemaError):
        fetch_defender_schemas(["DeviceEvents"], fetch_fn=fake_fetch)


# ---------------------------------------------------------------------------
# CLI: check-defender-schema
# ---------------------------------------------------------------------------


def _seed_schemas_defender(tmp_path: Path, names: list[str]) -> Path:
    target = tmp_path / "schemas_defender.json"
    payload = {
        "schema_version": 1,
        "database": "SentinelDefender",
        "tables": [
            {"name": n, "columns": [{"name": "Existing", "type": "string"}]}
            for n in names
        ],
    }
    target.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return target


def _seed_strict_config(tmp_path: Path, body: str) -> Path:
    target = tmp_path / "lint_strict.yml"
    target.write_text(body, encoding="utf-8")
    return target


def _patch_credential(monkeypatch) -> None:
    import contentops.utils.auth as auth_mod

    class _Tok:
        token = "stub"

    class _Cred:
        def get_token(self, *a, **kw):
            return _Tok()

    monkeypatch.setattr(auth_mod, "get_credential", lambda: _Cred())


def test_cli_check_defender_schema_respects_mode_off(
    tmp_path: Path, monkeypatch,
) -> None:
    cfg = _seed_strict_config(tmp_path, "mode: off\n")
    monkeypatch.setattr(
        "contentops.lint.strict_config.DEFAULT_CONFIG_PATH", cfg,
    )
    schemas = _seed_schemas_defender(tmp_path, ["DeviceEvents"])

    result = CliRunner().invoke(cli, [
        "upstream", "check-defender-schema",
        "--schemas", str(schemas),
    ])
    assert result.exit_code == 0, result.output
    assert "mode=off" in (result.stderr if hasattr(result, "stderr") else result.output)


def test_cli_check_defender_schema_respects_per_source_disable(
    tmp_path: Path, monkeypatch,
) -> None:
    cfg = _seed_strict_config(
        tmp_path, "mode: report\ndefender:\n  enabled: false\n",
    )
    monkeypatch.setattr(
        "contentops.lint.strict_config.DEFAULT_CONFIG_PATH", cfg,
    )
    schemas = _seed_schemas_defender(tmp_path, ["DeviceEvents"])

    result = CliRunner().invoke(cli, [
        "upstream", "check-defender-schema",
        "--schemas", str(schemas),
    ])
    assert result.exit_code == 0, result.output
    assert "defender.enabled=false" in (
        result.stderr if hasattr(result, "stderr") else result.output
    )


def test_cli_check_defender_schema_errors_when_seed_missing(
    tmp_path: Path, monkeypatch,
) -> None:
    cfg = _seed_strict_config(tmp_path, "mode: report\n")
    monkeypatch.setattr(
        "contentops.lint.strict_config.DEFAULT_CONFIG_PATH", cfg,
    )
    result = CliRunner().invoke(cli, [
        "upstream", "check-defender-schema",
        "--schemas", str(tmp_path / "missing.json"),
    ])
    assert result.exit_code == 1
    assert "not found" in result.output


def test_cli_check_defender_schema_dry_run_lists_added_columns(
    tmp_path: Path, monkeypatch,
) -> None:
    cfg = _seed_strict_config(tmp_path, "mode: report\n")
    monkeypatch.setattr(
        "contentops.lint.strict_config.DEFAULT_CONFIG_PATH", cfg,
    )
    _patch_credential(monkeypatch)

    import contentops.upstream.defender_schema as ds_mod

    def fake_fetch_defender_schemas(seed, **_kw):
        return ([{
            "name": "DeviceEvents",
            "columns": [
                {"name": "Existing", "type": "string"},
                {"name": "NewColumn", "type": "datetime"},
            ],
        }], [])

    monkeypatch.setattr(
        ds_mod, "fetch_defender_schemas", fake_fetch_defender_schemas,
    )

    schemas = _seed_schemas_defender(tmp_path, ["DeviceEvents"])
    result = CliRunner().invoke(cli, [
        "upstream", "check-defender-schema",
        "--schemas", str(schemas),
    ])
    assert result.exit_code == 0, result.output
    assert "Defender XDR schemas" in result.output
    assert "changed" in result.output


def test_cli_check_defender_schema_write_updates_file(
    tmp_path: Path, monkeypatch,
) -> None:
    cfg = _seed_strict_config(tmp_path, "mode: report\n")
    monkeypatch.setattr(
        "contentops.lint.strict_config.DEFAULT_CONFIG_PATH", cfg,
    )
    _patch_credential(monkeypatch)

    import contentops.upstream.defender_schema as ds_mod

    def fake_fetch_defender_schemas(seed, **_kw):
        return ([{
            "name": "DeviceEvents",
            "columns": [{"name": "NewColumn", "type": "datetime"}],
        }], [])

    monkeypatch.setattr(
        ds_mod, "fetch_defender_schemas", fake_fetch_defender_schemas,
    )

    schemas = _seed_schemas_defender(tmp_path, ["DeviceEvents"])
    result = CliRunner().invoke(cli, [
        "upstream", "check-defender-schema",
        "--schemas", str(schemas),
        "--out", str(tmp_path / "wn"),
        "--write",
    ])
    assert result.exit_code == 0, result.output

    raw = json.loads(schemas.read_text(encoding="utf-8"))
    assert raw["tables"][0]["columns"] == [{"name": "NewColumn", "type": "datetime"}]

    md = list((tmp_path / "wn").glob("*-defender-schemas.md"))
    assert len(md) == 1


def test_cli_pre_pr_refresh_skipped_when_mode_off(
    tmp_path: Path, monkeypatch,
) -> None:
    cfg = _seed_strict_config(tmp_path, "mode: off\n")
    monkeypatch.setattr(
        "contentops.lint.strict_config.DEFAULT_CONFIG_PATH", cfg,
    )
    result = CliRunner().invoke(cli, [
        "upstream", "pre-pr-refresh",
        "--sentinel-schemas", str(tmp_path / "s.json"),
        "--defender-schemas", str(tmp_path / "d.json"),
    ])
    assert result.exit_code == 0
    assert "mode=off" in result.output


def test_cli_pre_pr_refresh_skipped_when_refresh_on_pr_false(
    tmp_path: Path, monkeypatch,
) -> None:
    cfg = _seed_strict_config(
        tmp_path, "mode: report\nrefresh_on_pr: false\n",
    )
    monkeypatch.setattr(
        "contentops.lint.strict_config.DEFAULT_CONFIG_PATH", cfg,
    )
    result = CliRunner().invoke(cli, [
        "upstream", "pre-pr-refresh",
        "--sentinel-schemas", str(tmp_path / "s.json"),
        "--defender-schemas", str(tmp_path / "d.json"),
    ])
    assert result.exit_code == 0
    assert "refresh_on_pr=false" in result.output
