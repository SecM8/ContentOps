# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Smoke test the v2 `plan` Click command end-to-end."""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from contentops.cli import cli


SAMPLE_V2_WATCHLIST = """\
id: smoke-watchlist
version: 0.1.0
asset: sentinel_watchlist
status: production
payload:
  displayName: Smoke Test
  provider: Custom
  source: Local file
  contentType: text/csv
  itemsSearchKey: AssetName
  rawContent: |
    AssetName,Tier
    a,0
"""

def test_apply_dry_run_makes_no_api_calls(tmp_path: Path) -> None:
    (tmp_path / "sentinel_watchlist").mkdir()
    (tmp_path / "sentinel_watchlist" / "wl.yml").write_text(SAMPLE_V2_WATCHLIST)

    runner = CliRunner()
    result = runner.invoke(cli, ["apply", "--path", str(tmp_path), "--dry-run"])
    assert result.exit_code == 0, result.output
    assert "DRY-RUN" in result.output
    assert "smoke-watchlist" in result.output


def test_plan_filter_by_asset(tmp_path: Path) -> None:
    (tmp_path / "sentinel_watchlist").mkdir()
    (tmp_path / "sentinel_watchlist" / "wl.yml").write_text(SAMPLE_V2_WATCHLIST)

    runner = CliRunner()
    result = runner.invoke(
        cli, ["plan", "--path", str(tmp_path), "--asset", "sentinel_watchlist"],
    )
    assert result.exit_code == 0, result.output
    assert "Plan (1 assets):" in result.output
    assert "smoke-watchlist" in result.output
    assert "sentinel-smoke" not in result.output


# ---------------------------------------------------------------------------
# plan --role / --workspace targeting (Phase 2 PR A)
#
# plan_cmd inherited the multi-workspace targeting flags that apply_cmd /
# drift_cmd / prune_cmd / collect_cmd already had. The plumbing reuses
# _resolve_single_workspace_or_exit, so the CLI surface (mutual
# exclusion, ambiguous-target rejection) matches the other commands.
# ---------------------------------------------------------------------------


_MULTI_WORKSPACE_TENANT_YAML = """\
tenant:
  name: prod-tenant
  tenantId: aad-guid-1
  defender:
    enabled: true
  sentinelWorkspaces:
    - role: prod
      subscriptionId: "sub-prod"
      resourceGroup: rg-prod
      workspaceName: law-prod
      location: westeurope
    - role: integration
      subscriptionId: "sub-int"
      resourceGroup: rg-int
      workspaceName: law-int
      location: westeurope
"""


def _plan_with_tenant_yml(
    tmp_path: Path, monkeypatch, *plan_args: str,
) -> object:
    """Run `plan` against a tmp tree + tmp tenant.yml that the loader picks up.

    ``contentops.config.CONFIG_PATH`` is computed at import time relative
    to the package install location, so chdir alone wouldn't redirect
    the loader. Monkeypatch ``CONFIG_PATH`` to the tmp file directly.
    """
    detections = tmp_path / "detections"
    (detections / "sentinel_watchlist").mkdir(parents=True)
    (detections / "sentinel_watchlist" / "wl.yml").write_text(
        SAMPLE_V2_WATCHLIST, encoding="utf-8",
    )
    cfg_path = tmp_path / "tenant.yml"
    cfg_path.write_text(_MULTI_WORKSPACE_TENANT_YAML, encoding="utf-8")
    monkeypatch.setattr("contentops.config.CONFIG_PATH", cfg_path)
    monkeypatch.delenv("PIPELINE_ENV", raising=False)
    # Belt-and-braces: the autouse conftest fixture also pops this, but
    # the explicit ``monkeypatch.delenv`` here protects against any
    # earlier in-process code that set the var inside the test body
    # (and against future test reorderings).
    monkeypatch.delenv("PIPELINE_WORKSPACE_NAME", raising=False)
    return CliRunner().invoke(
        cli, ["plan", "--path", str(detections), *plan_args],
    )


def test_plan_with_role_flag_resolves_workspace(
    tmp_path: Path, monkeypatch,
) -> None:
    """`plan --role integration` against a multi-workspace tenant resolves
    the integration workspace and runs without the `_active_workspace`
    ambiguity error."""
    result = _plan_with_tenant_yml(
        tmp_path, monkeypatch, "--role", "integration",
    )
    assert result.exit_code == 0, result.output
    assert "smoke-watchlist" in result.output


def test_plan_with_workspace_name_flag_resolves_workspace(
    tmp_path: Path, monkeypatch,
) -> None:
    result = _plan_with_tenant_yml(
        tmp_path, monkeypatch, "--workspace", "law-prod",
    )
    assert result.exit_code == 0, result.output
    assert "smoke-watchlist" in result.output


def test_plan_role_and_workspace_mutually_exclusive(
    tmp_path: Path, monkeypatch,
) -> None:
    """Mutex enforced by `_resolve_single_workspace_or_exit` →
    ``select_workspaces`` → ValueError → exit 2."""
    result = _plan_with_tenant_yml(
        tmp_path, monkeypatch, "--role", "prod", "--workspace", "law-int",
    )
    assert result.exit_code == 2
    assert "mutually exclusive" in result.output


def test_plan_fails_fast_on_malformed_tenant_yaml(
    tmp_path: Path, monkeypatch,
) -> None:
    """Regression for CLI-1: plan_cmd used to swallow ValueError/KeyError
    from tenant config parsing together with the legitimate
    FileNotFoundError, silently producing an empty plan. A malformed
    tenant.yml must surface immediately."""
    detections = tmp_path / "detections"
    (detections / "sentinel_watchlist").mkdir(parents=True)
    (detections / "sentinel_watchlist" / "wl.yml").write_text(
        SAMPLE_V2_WATCHLIST, encoding="utf-8",
    )
    # tenant.yml exists (so FileNotFoundError is NOT raised) but is
    # missing the required tenantId field — pydantic raises ValidationError
    # which load_tenant_config wraps into ValueError.
    cfg_path = tmp_path / "tenant.yml"
    cfg_path.write_text(
        "tenant:\n  name: t\n  sentinelWorkspaces: []\n",
        encoding="utf-8",
    )
    monkeypatch.setattr("contentops.config.CONFIG_PATH", cfg_path)
    monkeypatch.delenv("PIPELINE_WORKSPACE_NAME", raising=False)
    result = CliRunner().invoke(
        cli, ["plan", "--path", str(detections)],
    )
    assert result.exit_code == 2, result.output
    assert "tenant config issue" in result.output
