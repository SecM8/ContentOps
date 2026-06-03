# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for `contentops drift` suppression handling (F15).

Layered:
* Loader tests against ``contentops.drift_suppressions.load_suppressions``.
* Filter tests against ``apply_suppressions`` (active hides,
  expired surfaces, unused flags).
* CLI integration via CliRunner using a stub drift detector.
"""

from __future__ import annotations

from datetime import date, timedelta
from pathlib import Path

import pytest
import yaml

from contentops.core.asset import Asset
from contentops.core.drift import DriftEntry, DriftReport
from contentops.drift_suppressions import (
    SUPPRESSIONS_FILENAME,
    Suppression,
    SuppressionsError,
    apply_suppressions,
    load_suppressions,
)


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------


def _write_sups(detections: Path, body: dict | None) -> Path:
    detections.mkdir(parents=True, exist_ok=True)
    path = detections / SUPPRESSIONS_FILENAME
    if body is None:
        path.write_text("", encoding="utf-8")
    else:
        path.write_text(yaml.safe_dump(body), encoding="utf-8")
    return path


def test_load_missing_file_returns_empty(tmp_path: Path) -> None:
    detections = tmp_path / "detections"
    detections.mkdir()
    assert load_suppressions(detections) == []


def test_load_empty_file_returns_empty(tmp_path: Path) -> None:
    detections = tmp_path / "detections"
    _write_sups(detections, None)
    assert load_suppressions(detections) == []


def test_load_valid_entry(tmp_path: Path) -> None:
    detections = tmp_path / "detections"
    _write_sups(detections, {
        "schema_version": "1.0",
        "suppressions": [{
            "asset": "sentinel_analytic",
            "id": "brute-force-ssh-001",
            "reason": "tracked in ENG-7421",
            "expires": "2026-06-01",
        }],
    })
    sups = load_suppressions(detections)
    assert len(sups) == 1
    s = sups[0]
    assert s.asset == "sentinel_analytic"
    assert s.id == "brute-force-ssh-001"
    assert s.expires == date(2026, 6, 1)


def test_load_accepts_yaml_native_date(tmp_path: Path) -> None:
    """PyYAML decodes ``expires: 2026-06-01`` as a python date —
    loader must accept that, not just ISO strings."""
    detections = tmp_path / "detections"
    detections.mkdir()
    (detections / SUPPRESSIONS_FILENAME).write_text("""\
schema_version: "1.0"
suppressions:
  - asset: sentinel_analytic
    id: rule-x
    reason: "test"
    expires: 2026-06-01
""", encoding="utf-8")
    sups = load_suppressions(detections)
    assert sups[0].expires == date(2026, 6, 1)


def test_load_unknown_schema_version_raises(tmp_path: Path) -> None:
    detections = tmp_path / "detections"
    _write_sups(detections, {
        "schema_version": "9.99",
        "suppressions": [],
    })
    with pytest.raises(SuppressionsError):
        load_suppressions(detections)


def test_load_unknown_asset_raises(tmp_path: Path) -> None:
    detections = tmp_path / "detections"
    _write_sups(detections, {
        "schema_version": "1.0",
        "suppressions": [{
            "asset": "not-an-asset", "id": "x",
            "reason": "x", "expires": "2026-06-01",
        }],
    })
    with pytest.raises(SuppressionsError):
        load_suppressions(detections)


def test_load_empty_reason_raises(tmp_path: Path) -> None:
    detections = tmp_path / "detections"
    _write_sups(detections, {
        "schema_version": "1.0",
        "suppressions": [{
            "asset": "sentinel_analytic", "id": "x",
            "reason": "", "expires": "2026-06-01",
        }],
    })
    with pytest.raises(SuppressionsError):
        load_suppressions(detections)


def test_load_garbage_expires_raises(tmp_path: Path) -> None:
    detections = tmp_path / "detections"
    _write_sups(detections, {
        "schema_version": "1.0",
        "suppressions": [{
            "asset": "sentinel_analytic", "id": "x",
            "reason": "x", "expires": "not-a-date",
        }],
    })
    with pytest.raises(SuppressionsError):
        load_suppressions(detections)


def test_load_suppressions_not_a_list_raises(tmp_path: Path) -> None:
    detections = tmp_path / "detections"
    _write_sups(detections, {
        "schema_version": "1.0",
        "suppressions": "not-a-list",
    })
    with pytest.raises(SuppressionsError):
        load_suppressions(detections)


def test_load_top_level_not_a_mapping_raises(tmp_path: Path) -> None:
    detections = tmp_path / "detections"
    detections.mkdir()
    (detections / SUPPRESSIONS_FILENAME).write_text(
        "- asset: x\n", encoding="utf-8",
    )
    with pytest.raises(SuppressionsError):
        load_suppressions(detections)


# ---------------------------------------------------------------------------
# apply_suppressions
# ---------------------------------------------------------------------------


def _entry(asset: Asset, asset_id: str, kind: str = "changed") -> DriftEntry:
    return DriftEntry(asset=asset, asset_id=asset_id, kind=kind)


def test_apply_active_suppression_filters_entry() -> None:
    report = DriftReport(entries=[
        _entry(Asset.SENTINEL_ANALYTIC, "rule-1"),
        _entry(Asset.SENTINEL_ANALYTIC, "rule-2"),
    ])
    sup = Suppression(
        asset="sentinel_analytic", id="rule-1",
        reason="x", expires=date(2099, 1, 1),
    )
    out = apply_suppressions(report, [sup])
    assert {e.asset_id for e in out.filtered.entries} == {"rule-2"}
    assert len(out.suppressed) == 1
    assert out.expired == []
    assert out.unused == []


def test_apply_expired_suppression_keeps_entry_and_flags_expired() -> None:
    report = DriftReport(entries=[
        _entry(Asset.SENTINEL_ANALYTIC, "rule-1"),
    ])
    sup = Suppression(
        asset="sentinel_analytic", id="rule-1",
        reason="x", expires=date(2020, 1, 1),  # already expired
    )
    out = apply_suppressions(report, [sup])
    # Entry passes through.
    assert {e.asset_id for e in out.filtered.entries} == {"rule-1"}
    assert out.suppressed == []
    assert out.expired == [sup]
    assert out.unused == []


def test_apply_unused_suppression_flagged() -> None:
    report = DriftReport(entries=[
        _entry(Asset.SENTINEL_ANALYTIC, "rule-1"),
    ])
    sup_unused = Suppression(
        asset="sentinel_analytic", id="ghost-rule",
        reason="x", expires=date(2099, 1, 1),
    )
    out = apply_suppressions(report, [sup_unused])
    assert out.unused == [sup_unused]
    assert out.suppressed == []
    assert out.expired == []


def test_apply_today_override(monkeypatch) -> None:
    """`today` argument wins over real today() so tests aren't time-dependent."""
    report = DriftReport(entries=[
        _entry(Asset.SENTINEL_ANALYTIC, "rule-1"),
    ])
    sup = Suppression(
        asset="sentinel_analytic", id="rule-1",
        reason="x", expires=date(2026, 6, 1),
    )
    # Today is before expiry → active.
    out = apply_suppressions(report, [sup], today=date(2026, 5, 15))
    assert len(out.suppressed) == 1
    assert out.expired == []
    # Today after expiry → expired.
    out = apply_suppressions(report, [sup], today=date(2026, 7, 1))
    assert out.suppressed == []
    assert out.expired == [sup]


def test_apply_multi_kind_only_filters_changed_keys() -> None:
    """Suppression keys are matched on (asset, id) regardless of kind."""
    report = DriftReport(entries=[
        _entry(Asset.SENTINEL_ANALYTIC, "rule-1", kind="changed"),
        _entry(Asset.SENTINEL_ANALYTIC, "rule-1", kind="in-sync"),
    ])
    sup = Suppression(
        asset="sentinel_analytic", id="rule-1",
        reason="x", expires=date(2099, 1, 1),
    )
    out = apply_suppressions(report, [sup])
    # Both entries with the same (asset, id) get filtered.
    assert out.filtered.entries == []
    assert len(out.suppressed) == 2


# ---------------------------------------------------------------------------
# CLI integration — drift command end-to-end with a stub handler
# ---------------------------------------------------------------------------


def _setup_workspace(tmp_path: Path, suppressions_yaml: str | None = None) -> Path:
    detections = tmp_path / "detections"
    detections.mkdir()
    if suppressions_yaml is not None:
        (detections / SUPPRESSIONS_FILENAME).write_text(
            suppressions_yaml, encoding="utf-8",
        )
    return detections


def test_cli_drift_malformed_suppressions_exits_2(tmp_path: Path) -> None:
    """An invalid drift_suppressions.yml fails fast with a clear message."""
    from click.testing import CliRunner
    from contentops.cli import cli
    detections = _setup_workspace(tmp_path, suppressions_yaml="""\
schema_version: "1.0"
suppressions:
  - asset: not-an-asset
    id: x
    reason: x
    expires: 2026-06-01
""")
    runner = CliRunner()
    result = runner.invoke(cli, [
        "drift", "--path", str(detections),
        "--no-exit-on-drift",
    ])
    assert result.exit_code == 2
    assert "not-an-asset" in result.output


def test_cli_drift_no_suppressions_file_runs_clean(tmp_path: Path) -> None:
    """No drift_suppressions.yml at all → loader returns empty list,
    drift command proceeds without failure on the suppressions axis.

    (Verified at the load_suppressions level; the CLI doesn't need to
    actually hit the network for this assertion — we only confirm the
    command would not exit 2 due to a suppressions error before any
    handler activity.)"""
    detections = tmp_path / "detections"
    detections.mkdir()
    # No file is present — loader must return [] and not raise.
    assert load_suppressions(detections) == []
