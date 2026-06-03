# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for `contentops drift-resolve <id> --strategy ...` (F6)."""

from __future__ import annotations

from pathlib import Path

import pytest

from contentops.core.asset import Asset
from contentops.core.drift import DriftEntry
from contentops.drift_resolve import (
    DriftResolveError,
    NotImplementedStrategy,
    resolve_git,
    resolve_merge,
    resolve_remote,
)


# ---------------------------------------------------------------------------
# resolve_git — pure no-op
# ---------------------------------------------------------------------------


def test_resolve_git_returns_no_change_outcome() -> None:
    out = resolve_git("rule-x")
    assert out.strategy == "git"
    assert out.action == "no-change-needed"
    assert "git is the source of truth" in out.detail
    assert out.path is None


# ---------------------------------------------------------------------------
# resolve_remote — writes the envelope
# ---------------------------------------------------------------------------


def _envelope(rule_id: str = "rule-x") -> dict:
    return {
        "id": rule_id,
        "version": "1.0.0",
        "asset": "sentinel_analytic",
        "status": "production",
        "legacy": True,
        "payload": {"displayName": "X", "query": "T | take 1"},
    }


def test_resolve_remote_writes_envelope_to_existing_local_path(tmp_path: Path) -> None:
    target = tmp_path / "detections" / "sentinel_analytic" / "rule-x.yml"
    target.parent.mkdir(parents=True)
    target.write_text("# old content\n", encoding="utf-8")

    entry = DriftEntry(
        asset=Asset.SENTINEL_ANALYTIC, asset_id="rule-x", kind="changed",
        envelope=_envelope(), local_path=target,
    )
    out = resolve_remote(entry=entry)
    assert out.action == "wrote"
    assert out.path == target
    body = target.read_text(encoding="utf-8")
    assert "rule-x" in body
    assert "# old content" not in body


def test_resolve_remote_dry_run_does_not_write(tmp_path: Path) -> None:
    target = tmp_path / "detections" / "sentinel_analytic" / "rule-x.yml"
    target.parent.mkdir(parents=True)
    target.write_text("# unchanged\n", encoding="utf-8")

    entry = DriftEntry(
        asset=Asset.SENTINEL_ANALYTIC, asset_id="rule-x", kind="changed",
        envelope=_envelope(), local_path=target,
    )
    out = resolve_remote(entry=entry, dry_run=True)
    assert out.action == "would-write"
    assert "# unchanged" in target.read_text(encoding="utf-8")


def test_resolve_remote_new_entry_writes_to_canonical_path(tmp_path: Path) -> None:
    """A 'new' entry has no local_path; writer picks
    detections/<kind>/<id>.yml and creates the dir."""
    import os
    cwd = os.getcwd()
    os.chdir(tmp_path)
    try:
        entry = DriftEntry(
            asset=Asset.SENTINEL_ANALYTIC, asset_id="rule-x", kind="new",
            envelope=_envelope(), local_path=None,
        )
        out = resolve_remote(entry=entry)
        assert out.action == "wrote"
        expected = Path("detections/sentinel_analytic/rule-x.yml")
        assert out.path == expected
        assert expected.is_file()
    finally:
        os.chdir(cwd)


def test_resolve_remote_envelope_required() -> None:
    """An entry without envelope (e.g. an in-sync entry) can't be
    resolved against remote — surface the error clearly."""
    entry = DriftEntry(
        asset=Asset.SENTINEL_ANALYTIC, asset_id="rule-x", kind="in-sync",
        envelope=None, local_path=Path("/x/x.yml"),
    )
    with pytest.raises(DriftResolveError):
        resolve_remote(entry=entry)


# ---------------------------------------------------------------------------
# resolve_merge — explicitly deferred
# ---------------------------------------------------------------------------


def test_resolve_merge_raises_not_implemented() -> None:
    entry = DriftEntry(
        asset=Asset.SENTINEL_ANALYTIC, asset_id="rule-x", kind="changed",
        envelope=_envelope(), local_path=Path("/x/x.yml"),
    )
    with pytest.raises(NotImplementedStrategy):
        resolve_merge(entry=entry)


# ---------------------------------------------------------------------------
# CLI integration — git strategy is the only one that doesn't require a
# live tenant. The remote/merge CLI paths are exercised at the unit-function
# level above.
# ---------------------------------------------------------------------------


def test_cli_drift_resolve_git_strategy(tmp_path: Path) -> None:
    """git strategy needs no remote lookup → safe to exercise via CliRunner."""
    from click.testing import CliRunner
    from contentops.cli import cli

    detections = tmp_path / "detections" / "sentinel_analytic"
    detections.mkdir(parents=True)
    runner = CliRunner()
    result = runner.invoke(cli, [
        "drift-resolve", "rule-x", "--strategy", "git",
        "--path", str(tmp_path / "detections"),
    ])
    assert result.exit_code == 0, result.output
    assert "git is the source of truth" in result.output


def test_cli_drift_resolve_strategy_required(tmp_path: Path) -> None:
    from click.testing import CliRunner
    from contentops.cli import cli

    detections = tmp_path / "detections" / "sentinel_analytic"
    detections.mkdir(parents=True)
    runner = CliRunner()
    result = runner.invoke(cli, [
        "drift-resolve", "rule-x",
        "--path", str(tmp_path / "detections"),
    ])
    # Click rejects missing required option with exit 2.
    assert result.exit_code == 2
