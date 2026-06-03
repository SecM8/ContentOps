# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for symmetric optional-engine gating (Phase 2 PR B).

Both Sentinel and Defender are independently optional in tenant.yml.
Four valid configurations:

* Defender-only            (sentinelWorkspaces: [], defender enabled)
* Sentinel-only            (sentinelWorkspaces non-empty, defender disabled / absent)
* Both                     (default; current main config)
* Empty (degenerate)       (sentinelWorkspaces: [], defender disabled)

The runtime must skip the disabled engine's handler factories and
silently filter envelopes whose engine is disabled. None of the four
configurations should crash.
"""

from __future__ import annotations

from pathlib import Path
from textwrap import dedent

import pytest
from click.testing import CliRunner

from contentops.cli import cli
from contentops.cli.commands._shared import (
    _DEFENDER_ASSET_VALUES,
    _SENTINEL_ASSET_VALUES,
)
from contentops.cli.handler_factories import register_default_handlers
from contentops.core.asset import Asset
from contentops.core.registry import default_registry


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _write_tenant_yml(path: Path, body: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(dedent(body), encoding="utf-8")
    return path


def _both_engines_config(path: Path) -> Path:
    return _write_tenant_yml(path / "tenant.yml", """\
        tenant:
          name: both
          tenantId: aad-1
          defender:
            enabled: true
          sentinelWorkspaces:
            - role: prod
              subscriptionId: sub-prod
              resourceGroup: rg
              workspaceName: law-prod
              location: westeurope
    """)


def _defender_only_config(path: Path) -> Path:
    return _write_tenant_yml(path / "tenant.yml", """\
        tenant:
          name: defender-only
          tenantId: aad-1
          defender:
            enabled: true
          sentinelWorkspaces: []
    """)


def _sentinel_only_config_defender_disabled(path: Path) -> Path:
    return _write_tenant_yml(path / "tenant.yml", """\
        tenant:
          name: sentinel-only-explicit
          tenantId: aad-1
          defender:
            enabled: false
          sentinelWorkspaces:
            - role: prod
              subscriptionId: sub-prod
              resourceGroup: rg
              workspaceName: law-prod
              location: westeurope
    """)


def _sentinel_only_config_defender_absent(path: Path) -> Path:
    return _write_tenant_yml(path / "tenant.yml", """\
        tenant:
          name: sentinel-only-implicit
          tenantId: aad-1
          sentinelWorkspaces:
            - role: prod
              subscriptionId: sub-prod
              resourceGroup: rg
              workspaceName: law-prod
              location: westeurope
    """)


def _empty_tenant_config(path: Path) -> Path:
    return _write_tenant_yml(path / "tenant.yml", """\
        tenant:
          name: empty
          tenantId: aad-1
          defender:
            enabled: false
          sentinelWorkspaces: []
    """)


@pytest.fixture
def _redirect_config(monkeypatch):
    """Returns a function that points contentops.config.CONFIG_PATH at a tmp file.

    Use INSIDE a test that's already created the tmp config file.
    """
    def _setter(cfg_path: Path) -> None:
        monkeypatch.setattr("contentops.config.CONFIG_PATH", cfg_path)
        monkeypatch.delenv("PIPELINE_ENV", raising=False)
    return _setter


# ---------------------------------------------------------------------------
# register_default_handlers — symmetric gating
# ---------------------------------------------------------------------------


def test_register_default_handlers_registers_both_when_both_configured(
    tmp_path: Path, _redirect_config,
) -> None:
    _redirect_config(_both_engines_config(tmp_path))
    register_default_handlers()
    assert default_registry.has(Asset.SENTINEL_ANALYTIC)
    assert default_registry.has(Asset.DEFENDER_CUSTOM_DETECTION)
    assert default_registry.has(Asset.SENTINEL_HUNTING)
    assert default_registry.has(Asset.SENTINEL_WATCHLIST)
    assert default_registry.has(Asset.SENTINEL_PARSER)
    assert default_registry.has(Asset.SENTINEL_DATA_CONNECTOR)


def test_register_default_handlers_skips_defender_when_disabled(
    tmp_path: Path, _redirect_config,
) -> None:
    _redirect_config(_sentinel_only_config_defender_disabled(tmp_path))
    register_default_handlers()
    assert default_registry.has(Asset.SENTINEL_ANALYTIC)
    assert not default_registry.has(Asset.DEFENDER_CUSTOM_DETECTION)


def test_register_default_handlers_skips_defender_when_absent(
    tmp_path: Path, _redirect_config,
) -> None:
    _redirect_config(_sentinel_only_config_defender_absent(tmp_path))
    register_default_handlers()
    assert default_registry.has(Asset.SENTINEL_ANALYTIC)
    assert not default_registry.has(Asset.DEFENDER_CUSTOM_DETECTION)


def test_register_default_handlers_skips_sentinel_when_zero_workspaces(
    tmp_path: Path, _redirect_config,
) -> None:
    _redirect_config(_defender_only_config(tmp_path))
    register_default_handlers()
    assert not default_registry.has(Asset.SENTINEL_ANALYTIC)
    assert not default_registry.has(Asset.SENTINEL_HUNTING)
    assert not default_registry.has(Asset.SENTINEL_WATCHLIST)
    assert not default_registry.has(Asset.SENTINEL_PARSER)
    assert not default_registry.has(Asset.SENTINEL_DATA_CONNECTOR)
    assert default_registry.has(Asset.DEFENDER_CUSTOM_DETECTION)


def test_register_default_handlers_empty_tenant_registers_nothing(
    tmp_path: Path, _redirect_config,
) -> None:
    _redirect_config(_empty_tenant_config(tmp_path))
    register_default_handlers()
    for a in Asset:
        assert not default_registry.has(a), (
            f"empty tenant should register no handlers, got {a.value}"
        )


# ---------------------------------------------------------------------------
# _filter_disabled_engines — envelope filter
# ---------------------------------------------------------------------------


_SAMPLE_ANALYTIC = """\
id: zz-itest-analytic
version: 0.1.0
asset: sentinel_analytic
status: production
payload:
  kind: Scheduled
  displayName: zz
  severity: Low
  query: print 1
  queryFrequency: PT5M
  queryPeriod: PT5M
  triggerOperator: GreaterThan
  triggerThreshold: 0
"""


_SAMPLE_DEFENDER = """\
id: zz-itest-defender
version: 0.1.0
asset: defender_custom_detection
status: production
payload:
  displayName: zz
  isEnabled: true
  queryCondition:
    queryText: DeviceEvents | take 1
"""


def _mixed_detections_tree(root: Path) -> Path:
    detections = root / "detections"
    (detections / "sentinel_analytic").mkdir(parents=True)
    (detections / "sentinel_analytic" / "a.yml").write_text(
        _SAMPLE_ANALYTIC, encoding="utf-8",
    )
    (detections / "defender_custom_detection").mkdir(parents=True)
    (detections / "defender_custom_detection" / "d.yml").write_text(
        _SAMPLE_DEFENDER, encoding="utf-8",
    )
    return detections


def test_plan_against_defender_only_tenant_skips_sentinel_envelopes(
    tmp_path: Path, _redirect_config,
) -> None:
    """Defender-only config: the sentinel envelope is filtered out
    BEFORE handler dispatch (exit code may still be non-zero if the
    surviving Defender envelope's payload fails validation; we only
    assert the filter behaviour)."""
    _redirect_config(_defender_only_config(tmp_path))
    detections = _mixed_detections_tree(tmp_path)
    result = CliRunner().invoke(
        cli, ["plan", "--path", str(detections)],
    )
    assert "no Sentinel workspaces configured" in result.output
    assert "skipping 1 Sentinel envelope" in result.output
    # The sentinel envelope must NOT appear in the plan output (it was
    # filtered before reaching the planner).
    assert "zz-itest-analytic" not in result.output
    # The defender envelope reached the planner (one row in the plan
    # table, status either "planned" or "error-validate").
    assert "zz-itest-defender" in result.output


def test_plan_against_sentinel_only_tenant_skips_defender_envelopes(
    tmp_path: Path, _redirect_config,
) -> None:
    """Symmetric counterpart: Sentinel-only config drops the defender
    envelope. Sentinel envelope reaches the planner."""
    _redirect_config(_sentinel_only_config_defender_disabled(tmp_path))
    detections = _mixed_detections_tree(tmp_path)
    result = CliRunner().invoke(
        cli, ["plan", "--path", str(detections)],
    )
    assert "Defender disabled in tenant.yml" in result.output
    assert "skipping 1 defender_custom_detection envelope" in result.output
    # The defender envelope is filtered before reaching the planner.
    assert "zz-itest-defender" not in result.output
    assert "zz-itest-analytic" in result.output


def test_plan_with_both_engines_emits_no_skip_lines(
    tmp_path: Path, _redirect_config,
) -> None:
    """Baseline: when both engines are configured, the filter is a
    no-op (no skip lines printed)."""
    _redirect_config(_both_engines_config(tmp_path))
    detections = _mixed_detections_tree(tmp_path)
    result = CliRunner().invoke(
        cli, ["plan", "--path", str(detections)],
    )
    # Filter is a no-op → no engine-skip lines in output.
    assert "no Sentinel workspaces configured" not in result.output
    assert "Defender disabled in tenant.yml" not in result.output
    # Both envelopes reach the planner.
    assert "zz-itest-analytic" in result.output
    assert "zz-itest-defender" in result.output


# ---------------------------------------------------------------------------
# _resolve_single_workspace_or_exit — zero-Sentinel branch
# ---------------------------------------------------------------------------


def test_resolve_single_workspace_no_op_when_zero_workspaces(
    tmp_path: Path, _redirect_config, capsys,
) -> None:
    """``--role prod`` against a Defender-only tenant prints an info
    line and returns without setting PIPELINE_WORKSPACE_NAME, so the
    caller can fall through to the Defender-only registration path."""
    import os
    from contentops.cli.commands._shared import (
        _resolve_single_workspace_or_exit,
    )
    _redirect_config(_defender_only_config(tmp_path))
    # Make sure the env var is unset before the call.
    if "PIPELINE_WORKSPACE_NAME" in os.environ:
        del os.environ["PIPELINE_WORKSPACE_NAME"]
    _resolve_single_workspace_or_exit(role="prod", workspace_name=None)
    captured = capsys.readouterr()
    assert "ignored" in captured.out
    assert "no Sentinel workspaces" in captured.out
    # Env var is NOT set — the caller is expected to fall through to
    # Defender-only registration.
    assert "PIPELINE_WORKSPACE_NAME" not in os.environ


# ---------------------------------------------------------------------------
# defender-extensions-probe — early exit when Defender disabled
# ---------------------------------------------------------------------------


def test_defender_extensions_probe_no_op_when_disabled(
    tmp_path: Path, _redirect_config,
) -> None:
    _redirect_config(_sentinel_only_config_defender_disabled(tmp_path))
    result = CliRunner().invoke(cli, ["defender-extensions-probe"])
    assert result.exit_code == 0, result.output
    assert "Defender is disabled" in result.output


def test_defender_extensions_probe_no_op_when_absent(
    tmp_path: Path, _redirect_config,
) -> None:
    _redirect_config(_sentinel_only_config_defender_absent(tmp_path))
    result = CliRunner().invoke(cli, ["defender-extensions-probe"])
    assert result.exit_code == 0, result.output
    assert "Defender is disabled" in result.output


# ---------------------------------------------------------------------------
# Sanity: the engine asset-value sets in _shared mirror the surviving
# Asset enum entries (so a future Asset rename doesn't silently break the
# filter).
# ---------------------------------------------------------------------------


def test_engine_asset_value_sets_mirror_asset_enum() -> None:
    sentinel_values = {a.value for a in Asset if a.value.startswith("sentinel_")}
    defender_values = {a.value for a in Asset if a.value.startswith("defender_")}
    assert _SENTINEL_ASSET_VALUES == sentinel_values
    assert _DEFENDER_ASSET_VALUES == defender_values


def test_engine_asset_value_sets_partition_asset_enum() -> None:
    """Cross-phase review-2 Seam B: the two engine groupings together
    must cover every Asset enum value, with no overlap. Catches a
    future where a new asset is added but doesn't start with
    ``sentinel_`` or ``defender_`` (the implicit prefix contract).
    """
    union = _SENTINEL_ASSET_VALUES | _DEFENDER_ASSET_VALUES
    overlap = _SENTINEL_ASSET_VALUES & _DEFENDER_ASSET_VALUES
    all_values = {a.value for a in Asset}
    assert union == all_values, (
        f"Engine groupings don't cover the Asset enum.\n"
        f"  Missing: {sorted(all_values - union)}\n"
        f"  Extra:   {sorted(union - all_values)}\n"
        f"Asset values must start with 'sentinel_' or 'defender_' "
        f"so the engine-prefix derivation in "
        f"contentops/cli/commands/_shared.py picks them up."
    )
    assert not overlap, (
        f"Engine groupings overlap on: {sorted(overlap)}. "
        f"An Asset can belong to exactly one engine."
    )


# ---------------------------------------------------------------------------
# Cross-phase Seam G: Defender-only tenant + apply env-status gate
# ---------------------------------------------------------------------------


def test_apply_defender_only_tenant_does_not_drop_defender_envelopes(
    tmp_path: Path, _redirect_config,
) -> None:
    """Cross-phase Seam G regression test.

    On a Defender-only tenant (zero Sentinel workspaces, Defender
    enabled) the env-status filter previously compared
    ``gate_key != 'prod'`` literally. The fallback ``gate_key`` was
    the tenant name (e.g. ``defender-only``), so every Defender
    envelope was silently dropped with the misleading
    ``[defender:prod-only]`` label and apply exited 0 deploying
    nothing.

    The fix makes the Defender gate active only when there's a
    Sentinel workspace context to gate against (workspaces is
    non-empty AND the active workspace's role isn't a prod alias).
    On a Defender-only tenant the gate is a no-op, so the Defender
    envelope must reach the planner / handler dispatch.
    """
    _redirect_config(_defender_only_config(tmp_path))
    detections = _mixed_detections_tree(tmp_path)
    # Use --dry-run so we don't try to actually deploy. The check is
    # that the defender envelope is NOT skipped by the env-status
    # filter -- it should reach the handler dispatch (where it may
    # error for unrelated reasons in this synthetic fixture, that's
    # fine; what matters is the lack of [defender:prod-only] line).
    result = CliRunner().invoke(
        cli, ["apply", "--path", str(detections), "--dry-run", "--no-audit"],
    )
    # The Defender envelope must NOT have been filtered with the
    # prod-only label (the bug's signature output).
    assert "[defender:prod-only]" not in result.output, (
        f"Defender envelope incorrectly dropped on Defender-only tenant.\n"
        f"Output:\n{result.output}"
    )
    # The Sentinel envelope IS still skipped (engine-disabled filter
    # runs earlier; that's PR #134 behaviour, unaffected by this fix).
    assert "no Sentinel workspaces configured" in result.output
