# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for the ``contentops config`` CLI group (Phase 2 PR A).

Two subcommands:

* ``config validate`` — load + parse tenant.yml; report engine summary;
  WARN on empty tenant; ``--strict`` exits 1 on the WARN.
* ``config list-workspaces`` — print configured Sentinel workspaces in
  table / JSON / CSV format.
"""

from __future__ import annotations

import json
from pathlib import Path
from textwrap import dedent

import pytest
from click.testing import CliRunner

from contentops.cli import cli


# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------


def _write_yaml(path: Path, body: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(dedent(body), encoding="utf-8")
    return path


def _valid_two_workspace_yaml() -> str:
    return """\
        tenant:
          name: prod-tenant
          tenantId: aad-guid-1
          defender:
            enabled: true
          sentinelWorkspaces:
            - role: prod
              subscriptionId: 11111111-aaaa-bbbb-cccc-222222222222
              resourceGroup: rg-prod
              workspaceName: law-prod
              location: westeurope
            - role: integration
              subscriptionId: 33333333-aaaa-bbbb-cccc-444444444444
              resourceGroup: rg-int
              workspaceName: law-int
              location: westeurope
    """


def _defender_only_yaml() -> str:
    return """\
        tenant:
          name: defender-only
          tenantId: aad-guid-1
          defender:
            enabled: true
          sentinelWorkspaces: []
    """


def _empty_tenant_yaml() -> str:
    return """\
        tenant:
          name: empty
          tenantId: aad-guid-1
          defender:
            enabled: false
          sentinelWorkspaces: []
    """


def _legacy_schema_yaml() -> str:
    """v1 single-workspace shape — must be rejected with the migration hint."""
    return """\
        tenant:
          name: old
          tenantId: aad-guid-1
          sentinel:
            subscriptionId: 1
            resourceGroup: rg
            workspaceName: w
            location: westeurope
    """


def _duplicate_case_workspace_yaml() -> str:
    return """\
        tenant:
          name: t
          tenantId: aad-guid-1
          sentinelWorkspaces:
            - role: prod
              subscriptionId: "sub-1"
              resourceGroup: rg
              workspaceName: law-prod
            - role: integration
              subscriptionId: "sub-2"
              resourceGroup: rg2
              workspaceName: LAW-PROD
    """


# ---------------------------------------------------------------------------
# config validate
# ---------------------------------------------------------------------------


def test_config_validate_passes_on_valid_tenant_yml(tmp_path: Path) -> None:
    cfg = _write_yaml(tmp_path / "tenant.yml", _valid_two_workspace_yaml())
    result = CliRunner().invoke(cli, ["config", "validate", "--path", str(cfg)])
    assert result.exit_code == 0, result.output
    # The summary line names every engine.
    assert "tenant=prod-tenant" in result.output
    assert "sentinel_workspaces=2" in result.output
    assert "defender=enabled" in result.output


def test_config_validate_summary_marks_defender_disabled(tmp_path: Path) -> None:
    cfg = _write_yaml(tmp_path / "tenant.yml", """\
        tenant:
          name: t
          tenantId: aad-guid-1
          defender:
            enabled: false
          sentinelWorkspaces:
            - subscriptionId: s
              resourceGroup: r
              workspaceName: w
    """)
    result = CliRunner().invoke(cli, ["config", "validate", "--path", str(cfg)])
    assert result.exit_code == 0, result.output
    assert "defender=disabled" in result.output


def test_config_validate_summary_marks_defender_absent(tmp_path: Path) -> None:
    cfg = _write_yaml(tmp_path / "tenant.yml", """\
        tenant:
          name: t
          tenantId: aad-guid-1
          sentinelWorkspaces:
            - subscriptionId: s
              resourceGroup: r
              workspaceName: w
    """)
    result = CliRunner().invoke(cli, ["config", "validate", "--path", str(cfg)])
    assert result.exit_code == 0, result.output
    assert "defender=absent" in result.output


def test_config_validate_fails_on_legacy_schema(tmp_path: Path) -> None:
    cfg = _write_yaml(tmp_path / "tenant.yml", _legacy_schema_yaml())
    result = CliRunner().invoke(cli, ["config", "validate", "--path", str(cfg)])
    assert result.exit_code == 1
    assert "legacy single-workspace schema detected" in result.output


def test_config_validate_fails_on_duplicate_workspace_names_case_insensitive(
    tmp_path: Path,
) -> None:
    cfg = _write_yaml(tmp_path / "tenant.yml", _duplicate_case_workspace_yaml())
    result = CliRunner().invoke(cli, ["config", "validate", "--path", str(cfg)])
    assert result.exit_code == 1
    assert "Duplicate workspaceName" in result.output


def test_config_validate_warns_on_empty_tenant_no_strict(tmp_path: Path) -> None:
    """0 workspaces + Defender disabled → exit 0 with WARN line on stderr."""
    cfg = _write_yaml(tmp_path / "tenant.yml", _empty_tenant_yaml())
    result = CliRunner().invoke(cli, ["config", "validate", "--path", str(cfg)])
    assert result.exit_code == 0, result.output
    # Summary still printed.
    assert "tenant=empty" in result.output
    # WARN goes to stderr (mix_stderr=True by default in CliRunner).
    assert "no deployment targets" in result.output


def test_config_validate_strict_exits_1_on_empty_tenant(tmp_path: Path) -> None:
    cfg = _write_yaml(tmp_path / "tenant.yml", _empty_tenant_yaml())
    result = CliRunner().invoke(
        cli, ["config", "validate", "--path", str(cfg), "--strict"],
    )
    assert result.exit_code == 1
    assert "no deployment targets" in result.output


def test_config_validate_missing_file(tmp_path: Path) -> None:
    result = CliRunner().invoke(
        cli, ["config", "validate", "--path", str(tmp_path / "does-not-exist.yml")],
    )
    assert result.exit_code == 1
    assert "tenant config not found" in result.output


def test_config_validate_surfaces_pydantic_validation_error(tmp_path: Path) -> None:
    """Item 2: schema-level field errors (Pydantic ValidationError) must
    exit 1 with the validation message, not silently fall through."""
    cfg = _write_yaml(tmp_path / "tenant.yml", """\
        tenant:
          name: t
          tenantId: aad-guid-1
          sentinelWorkspaces:
            - role: prod
              # subscriptionId missing — Pydantic field-level required check
              resourceGroup: rg
              workspaceName: w
    """)
    result = CliRunner().invoke(cli, ["config", "validate", "--path", str(cfg)])
    assert result.exit_code == 1
    # Pydantic v2 ValidationError stringifies with "validation error" in the
    # message; the exact field name appears too.
    assert "subscriptionId" in result.output


def test_config_validate_strict_fails_when_auth_env_unset(
    tmp_path: Path, monkeypatch,
) -> None:
    """Item 7: --strict against a tenant with deployment targets but no
    AZURE_CLIENT_ID / AZURE_TENANT_ID exits 1, so CI catches the
    misconfiguration before the deploy step burns minutes."""
    cfg = _write_yaml(tmp_path / "tenant.yml", _valid_two_workspace_yaml())
    monkeypatch.delenv("AZURE_CLIENT_ID", raising=False)
    monkeypatch.delenv("AZURE_TENANT_ID", raising=False)
    result = CliRunner().invoke(
        cli, ["config", "validate", "--path", str(cfg), "--strict"],
    )
    assert result.exit_code == 1, result.output
    assert "AZURE_CLIENT_ID" in result.output
    assert "AZURE_TENANT_ID" in result.output


def test_config_validate_strict_passes_when_auth_env_set(
    tmp_path: Path, monkeypatch,
) -> None:
    """Item 7: --strict with a valid tenant + auth env vars present
    exits 0 (the happy CI path)."""
    cfg = _write_yaml(tmp_path / "tenant.yml", _valid_two_workspace_yaml())
    monkeypatch.setenv("AZURE_CLIENT_ID", "test-client-id")
    monkeypatch.setenv("AZURE_TENANT_ID", "test-tenant-id")
    result = CliRunner().invoke(
        cli, ["config", "validate", "--path", str(cfg), "--strict"],
    )
    assert result.exit_code == 0, result.output


def test_config_validate_strict_skips_auth_check_on_empty_tenant(
    tmp_path: Path, monkeypatch,
) -> None:
    """Item 7: --strict on an empty tenant exits 1 due to the WARN, not
    the auth-env check. The two failure modes are reported independently
    so the operator sees the right error first."""
    cfg = _write_yaml(tmp_path / "tenant.yml", _empty_tenant_yaml())
    monkeypatch.delenv("AZURE_CLIENT_ID", raising=False)
    monkeypatch.delenv("AZURE_TENANT_ID", raising=False)
    result = CliRunner().invoke(
        cli, ["config", "validate", "--path", str(cfg), "--strict"],
    )
    assert result.exit_code == 1
    assert "no deployment targets" in result.output
    # Auth-env error should NOT appear — there's nothing to deploy to.
    assert "AZURE_CLIENT_ID" not in result.output


# ---------------------------------------------------------------------------
# config list-workspaces
# ---------------------------------------------------------------------------


def test_config_list_workspaces_table_format(tmp_path: Path) -> None:
    cfg = _write_yaml(tmp_path / "tenant.yml", _valid_two_workspace_yaml())
    result = CliRunner().invoke(
        cli, ["config", "list-workspaces", "--path", str(cfg)],
    )
    assert result.exit_code == 0, result.output
    # Header row.
    assert "name" in result.output
    assert "role" in result.output
    # One row per workspace.
    assert "law-prod" in result.output
    assert "law-int" in result.output
    # Subscription ID is truncated to last 8 chars (privacy / brevity).
    assert "22222222" in result.output
    assert "11111111-aaaa-bbbb-cccc-222222222222" not in result.output


def test_config_list_workspaces_json_format(tmp_path: Path) -> None:
    cfg = _write_yaml(tmp_path / "tenant.yml", _valid_two_workspace_yaml())
    result = CliRunner().invoke(
        cli, ["config", "list-workspaces", "--path", str(cfg), "--format", "json"],
    )
    assert result.exit_code == 0, result.output
    parsed = json.loads(result.output)
    assert isinstance(parsed, list)
    assert len(parsed) == 2
    names = {row["name"] for row in parsed}
    assert names == {"law-prod", "law-int"}
    # Schema is stable; every documented column is present.
    # ``workspace_name`` was removed in the Phase 2 follow-up — it
    # duplicated ``name``, so JSON consumers should read ``name``.
    for row in parsed:
        assert set(row) == {
            "name", "role", "subscription_id_suffix",
            "resource_group", "location",
        }
        assert "workspace_name" not in row


def test_config_list_workspaces_csv_format(tmp_path: Path) -> None:
    cfg = _write_yaml(tmp_path / "tenant.yml", _valid_two_workspace_yaml())
    result = CliRunner().invoke(
        cli, ["config", "list-workspaces", "--path", str(cfg), "--format", "csv"],
    )
    assert result.exit_code == 0, result.output
    lines = result.output.strip().splitlines()
    assert lines[0].startswith("name,role,")
    # Header + 2 data rows = 3 lines.
    assert len(lines) == 3


def test_config_list_workspaces_empty_table(tmp_path: Path) -> None:
    cfg = _write_yaml(tmp_path / "tenant.yml", _defender_only_yaml())
    result = CliRunner().invoke(
        cli, ["config", "list-workspaces", "--path", str(cfg)],
    )
    assert result.exit_code == 0, result.output
    assert "no Sentinel workspaces configured" in result.output
    assert "Defender-only" in result.output


def test_config_list_workspaces_empty_json(tmp_path: Path) -> None:
    """Empty workspace list returns ``[]`` in JSON mode (scriptable)."""
    cfg = _write_yaml(tmp_path / "tenant.yml", _defender_only_yaml())
    result = CliRunner().invoke(
        cli, ["config", "list-workspaces", "--path", str(cfg), "--format", "json"],
    )
    assert result.exit_code == 0, result.output
    assert json.loads(result.output) == []


def test_config_list_workspaces_empty_csv_header_only(tmp_path: Path) -> None:
    cfg = _write_yaml(tmp_path / "tenant.yml", _defender_only_yaml())
    result = CliRunner().invoke(
        cli, ["config", "list-workspaces", "--path", str(cfg), "--format", "csv"],
    )
    assert result.exit_code == 0, result.output
    assert result.output.strip().startswith("name,role,")
    # Only the header line; no data rows.
    assert len(result.output.strip().splitlines()) == 1
