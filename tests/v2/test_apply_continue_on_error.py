# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for `contentops apply --continue-on-error`.

Per-rule errors should be visible in the summary but NOT bump the
exit code. Pipeline-level errors (auth, dependency violations,
missing handlers) still exit non-zero — the flag only suppresses
the per-rule rollup at the bottom of apply.

Used by `integration-deploy.yml` so a broken rule doesn't block PR
merges (integration is a smoke test, not a hard gate).
"""

from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner

from contentops.cli import cli
from contentops.core.asset import Asset
from contentops.core.handler import LoadedAsset
from contentops.core.registry import default_registry
from contentops.core.result import ActionResult, PlanAction


class _FailingHandler:
    """Always fails apply with a per-rule error."""
    asset = Asset.SENTINEL_ANALYTIC

    def validate(self, loaded: LoadedAsset) -> None:
        return None

    def plan(self, loaded: LoadedAsset) -> ActionResult:
        return ActionResult(
            asset_id=loaded.envelope.id, asset_kind=self.asset.value,
            action=PlanAction.UPDATE, status="planned",
        )

    def apply(self, loaded: LoadedAsset, *, dry_run: bool = False) -> ActionResult:
        return ActionResult(
            asset_id=loaded.envelope.id, asset_kind=self.asset.value,
            action=PlanAction.UPDATE, status="error-400",
            detail="One of the tables does not exist.",
            verified=False, error="MISMATCH",
        )

    def close(self) -> None:
        return None


def _write_rule(detections: Path, *, rule_id: str = "rule-x") -> None:
    p = detections / "sentinel_analytic"
    p.mkdir(parents=True, exist_ok=True)
    (p / f"{rule_id}.yml").write_text(
        f"""\
id: {rule_id}
version: 0.1.0
asset: sentinel_analytic
status: production
metadata:
  owner: secops@example.com
  runbookUrl: https://runbooks.example.com/x
  severity: low
  tactics: [Execution]
  techniques: [T1059]
  expectedAlertsPerDay: 1
  fpHandling: Triage manually.
payload:
  displayName: x
  severity: Low
  query: |
    SecurityEvent | where TimeGenerated > ago(1h)
""",
        encoding="utf-8",
    )


@pytest.fixture(autouse=True)
def _clean_registry():
    """Restore the registry between tests so handlers don't leak."""
    saved_factories = dict(default_registry._factories)
    saved_instances = dict(default_registry._instances)
    default_registry._factories.clear()
    default_registry._instances.clear()
    yield
    default_registry._factories.clear()
    default_registry._instances.clear()
    default_registry._factories.update(saved_factories)
    default_registry._instances.update(saved_instances)


@pytest.fixture
def _failing_handler():
    default_registry.register(Asset.SENTINEL_ANALYTIC, _FailingHandler)


def test_apply_without_flag_exits_nonzero_on_per_rule_error(
    tmp_path: Path, monkeypatch, _failing_handler,
) -> None:
    monkeypatch.chdir(tmp_path)
    _write_rule(tmp_path / "detections")
    result = CliRunner().invoke(cli, [
        "apply", "--path", "detections", "--no-audit",
        "--skip-deps-check", "--dry-run",
    ])
    # Default behaviour: per-rule failure → exit 1.
    assert result.exit_code == 1, result.output
    assert "1 error(s)" in result.output


def test_apply_with_flag_returns_zero_on_per_rule_error(
    tmp_path: Path, monkeypatch, _failing_handler,
) -> None:
    monkeypatch.chdir(tmp_path)
    _write_rule(tmp_path / "detections")
    result = CliRunner().invoke(cli, [
        "apply", "--path", "detections", "--no-audit",
        "--skip-deps-check", "--dry-run", "--continue-on-error",
    ])
    assert result.exit_code == 0, result.output
    # The failure is still surfaced in the summary — just doesn't
    # bump the exit code.
    assert "per-rule error(s)" in result.output
    assert "exit code suppressed" in result.output
    assert "--continue-on-error" in result.output


def test_apply_with_flag_no_change_when_zero_failures(
    tmp_path: Path, monkeypatch,
) -> None:
    """The flag is a no-op when every rule succeeds."""
    monkeypatch.chdir(tmp_path)
    # Empty detections → nothing to apply → exit 0 either way.
    (tmp_path / "detections").mkdir()
    result = CliRunner().invoke(cli, [
        "apply", "--path", "detections", "--no-audit",
        "--skip-deps-check", "--dry-run", "--continue-on-error",
    ])
    assert result.exit_code == 0, result.output
    # No per-rule errors → no suppression message.
    assert "exit code suppressed" not in result.output


def test_continue_on_error_visible_in_help() -> None:
    result = CliRunner().invoke(cli, ["apply", "--help"])
    assert result.exit_code == 0
    assert "--continue-on-error" in result.output
    assert "integration-deploy" in result.output  # rationale in help
