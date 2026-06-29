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


# A Defender custom detection that parses as an envelope but fails
# payload validation: ``severity: Medium`` is capitalised, but the Graph
# API (and our ``DefenderPayload`` model) only accept the lowercase
# literals informational/low/medium/high. This is the exact shape that
# surfaced as a bare ``error-validate`` row in a prod CI plan with no
# stated reason. The regression below asserts the reason is now printed.
SAMPLE_V2_DEFENDER_BAD_SEVERITY = """\
id: smoke-defender-bad-severity
version: 0.1.0
asset: defender_custom_detection
status: production
payload:
  displayName: Smoke Bad Severity
  isEnabled: true
  queryCondition:
    queryText: DeviceProcessEvents | take 1
  schedule:
    period: 1H
  detectionAction:
    alertTemplate:
      title: Smoke Bad Severity
      severity: Medium
      category: SuspiciousActivity
      impactedAssets:
      - '@odata.type': '#microsoft.graph.security.impactedDeviceAsset'
        identifier: deviceName
"""


def test_plan_prints_validation_detail_on_error(tmp_path: Path) -> None:
    """An ``error-validate`` row must surface its reason, not just the status.

    The plan table (``ActionResult.as_row``) shows the status but not the
    detail: its last column is the verify state. Before this fix a
    validation failure printed ``error-validate`` and exited 1 with no
    indication of *why*, which is undiagnosable from a CI log. The plan
    summary now prints each errored asset's detail next to the exit.
    """
    (tmp_path / "defender_custom_detection").mkdir()
    (tmp_path / "defender_custom_detection" / "bad.yml").write_text(
        SAMPLE_V2_DEFENDER_BAD_SEVERITY, encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(
        cli, ["plan", "--path", str(tmp_path), "--skip-deps-check"],
    )

    assert result.exit_code == 1, result.output
    # The row still reports the status...
    assert "error-validate" in result.output
    # ...and the reason is now actionable: the asset id, the offending
    # field, and the validation count all appear.
    assert "Validation errors:" in result.output
    assert "smoke-defender-bad-severity" in result.output
    assert "severity" in result.output
    assert "1 validation error(s)" in result.output


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
