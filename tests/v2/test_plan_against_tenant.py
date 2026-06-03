# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for `contentops plan --against-tenant` (G17 closeout)."""

from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner

from contentops.cli import cli


def test_plan_against_tenant_flag_exists() -> None:
    """The CLI surfaces the flag in `--help` so operators can discover it."""
    runner = CliRunner()
    result = runner.invoke(cli, ["plan", "--help"])
    assert result.exit_code == 0
    assert "--against-tenant" in result.output
    assert "G17" in result.output


def test_plan_without_flag_does_not_call_detect_drift(monkeypatch, tmp_path: Path) -> None:
    """Default plan must NOT make API calls — fork-PR + offline test
    invariant. We monkeypatch detect_drift to a sentinel so we can
    assert it isn't reached."""
    called = []
    from contentops.core import drift as drift_mod

    def _trap(*a, **kw):
        called.append((a, kw))
        return drift_mod.DriftReport()

    monkeypatch.setattr(drift_mod, "detect_drift", _trap)

    (tmp_path / "detections").mkdir()
    runner = CliRunner()
    # No --against-tenant: detect_drift must not run.
    result = runner.invoke(cli, ["plan", "--path", str(tmp_path / "detections")])
    # plan with no envelopes succeeds with zero-asset output.
    assert "Against-tenant overlay" not in result.output
    assert called == []


def test_plan_against_tenant_renders_overlay(monkeypatch, tmp_path: Path) -> None:
    """When the flag is set, the overlay prints CREATE / UPDATE / NO-CHANGE."""
    from contentops.core import drift as drift_mod
    from contentops.core.asset import Asset
    from contentops.core.drift import DriftEntry, DriftReport

    fake = DriftReport(entries=[
        DriftEntry(asset=Asset.SENTINEL_ANALYTIC, asset_id="a", kind="in-sync"),
        DriftEntry(asset=Asset.SENTINEL_ANALYTIC, asset_id="b", kind="changed"),
        DriftEntry(asset=Asset.SENTINEL_ANALYTIC, asset_id="c", kind="new",
                   envelope={"id": "c"}),
    ])
    monkeypatch.setattr(drift_mod, "detect_drift", lambda *a, **kw: fake)

    (tmp_path / "detections").mkdir()
    runner = CliRunner()
    result = runner.invoke(
        cli, ["plan", "--against-tenant", "--path", str(tmp_path / "detections")],
    )
    assert result.exit_code == 0, result.output
    assert "Against-tenant overlay" in result.output
    assert "UPDATE: 1" in result.output
    assert "NO-CHANGE: 1" in result.output
    assert "ORPHAN-IN-TENANT: 1" in result.output


def test_plan_against_tenant_handles_remote_list_failure(monkeypatch, tmp_path: Path) -> None:
    """If detect_drift raises, the overlay is replaced with a friendly
    banner; the plan above the overlay is still printed."""
    from contentops.core import drift as drift_mod

    def _boom(*a, **kw):
        raise RuntimeError("tenant unreachable")

    monkeypatch.setattr(drift_mod, "detect_drift", _boom)

    (tmp_path / "detections").mkdir()
    runner = CliRunner()
    result = runner.invoke(
        cli, ["plan", "--against-tenant", "--path", str(tmp_path / "detections")],
    )
    assert result.exit_code == 0, result.output
    assert "detect_drift failed" in result.output
    assert "tenant unreachable" in result.output
