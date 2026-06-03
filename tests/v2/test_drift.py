# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for the drift detection engine."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from contentops.core.asset import Asset
from contentops.core.drift import detect_drift, write_drift


class _StubHandler:
    asset = Asset.SENTINEL_ANALYTIC

    def __init__(self, remote_items: list[dict]) -> None:
        self._remote = remote_items
        self.list_calls = 0

    def list_remote(self) -> list[dict]:
        self.list_calls += 1
        return self._remote

    def to_envelope(self, remote: dict) -> dict | None:
        if remote.get("name") == "skip-me":
            return None
        return {
            "id": remote["name"],
            "version": "0.1.0",
            "asset": self.asset.value,
            "status": "production",
            "payload": remote.get("properties", {}),
        }


def _write_local(
    root: Path, asset_id: str, payload: dict, *, version: str = "0.1.0",
) -> Path:
    path = root / "sentinel" / f"{asset_id}.yml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump({
        "id": asset_id, "version": version,
        "asset": Asset.SENTINEL_ANALYTIC.value,
        "status": "production", "legacy": True, "payload": payload,
    }), encoding="utf-8")
    return path


def test_detects_new_remote_asset(tmp_path: Path) -> None:
    handler = _StubHandler([{"name": "rule-a", "properties": {"displayName": "A"}}])
    report = detect_drift([handler], tmp_path)
    assert len(report.new) == 1
    assert report.new[0].asset_id == "rule-a"
    assert report.changed == []


def test_detects_changed_payload(tmp_path: Path) -> None:
    _write_local(tmp_path, "rule-b", {"displayName": "OLD"})
    handler = _StubHandler([{"name": "rule-b", "properties": {"displayName": "NEW"}}])
    report = detect_drift([handler], tmp_path)
    assert len(report.changed) == 1
    assert report.changed[0].asset_id == "rule-b"
    assert report.new == []


def test_in_sync_when_payloads_match(tmp_path: Path) -> None:
    _write_local(tmp_path, "rule-c", {"displayName": "C"})
    handler = _StubHandler([{"name": "rule-c", "properties": {"displayName": "C"}}])
    report = detect_drift([handler], tmp_path)
    assert report.changed == []
    assert report.new == []
    assert len(report.in_sync) == 1
    assert not report.has_drift()


def test_handler_can_skip_remote_items(tmp_path: Path) -> None:
    handler = _StubHandler([
        {"name": "skip-me", "properties": {}},
        {"name": "keep", "properties": {"displayName": "K"}},
    ])
    report = detect_drift([handler], tmp_path)
    assert {e.asset_id for e in report.new} == {"keep"}


def test_normalization_treats_key_order_as_equal(tmp_path: Path) -> None:
    _write_local(tmp_path, "rule-x", {"a": 1, "b": {"x": 1, "y": 2}})
    handler = _StubHandler([
        {"name": "rule-x", "properties": {"b": {"y": 2, "x": 1}, "a": 1}},
    ])
    report = detect_drift([handler], tmp_path)
    assert len(report.in_sync) == 1


def test_write_drift_overwrites_local_for_changed(tmp_path: Path) -> None:
    local = _write_local(tmp_path, "rule-d", {"displayName": "OLD"})
    handler = _StubHandler([{"name": "rule-d", "properties": {"displayName": "NEW"}}])
    report = detect_drift([handler], tmp_path)
    written = write_drift(report, tmp_path)
    assert written == [local]
    on_disk = yaml.safe_load(local.read_text())
    assert on_disk["payload"]["displayName"] == "NEW"


def test_write_drift_preserves_local_version_no_downgrade(tmp_path: Path) -> None:
    """Regression: a drift import must never downgrade an operator's
    committed version.

    ``version`` is repo-side only — the remote has no concept of it, so
    ``to_envelope`` stamps the synthetic ``0.1.0`` collect baseline.
    Writing that baseline over a bumped ``0.1.1`` is the bug that reset
    7 production Defender detections (PR #291). The on-disk value must
    survive a drift-write even though the rule's payload genuinely
    changed.
    """
    local = _write_local(
        tmp_path, "rule-v", {"displayName": "OLD"}, version="0.1.1",
    )
    handler = _StubHandler([{"name": "rule-v", "properties": {"displayName": "NEW"}}])
    report = detect_drift([handler], tmp_path)
    assert len(report.changed) == 1  # payload differs -> real drift
    write_drift(report, tmp_path)
    on_disk = yaml.safe_load(local.read_text())
    assert on_disk["payload"]["displayName"] == "NEW"  # payload still imported
    assert on_disk["version"] == "0.1.1"  # ...but version not downgraded


def test_write_drift_preserves_local_version_over_remote(tmp_path: Path) -> None:
    """version is operator-managed: a drift re-import never overwrites the
    on-disk value, even if the handler emits a different (higher) one. The
    remote has no authoritative version to import, so local always wins.
    """
    class _VersionedHandler(_StubHandler):
        def to_envelope(self, remote: dict) -> dict | None:
            env = super().to_envelope(remote)
            if env is not None:
                env["version"] = "2.0.0"  # synthetic baseline, not authoritative
            return env

    local = _write_local(
        tmp_path, "rule-w", {"displayName": "OLD"}, version="1.5.0",
    )
    handler = _VersionedHandler([{"name": "rule-w", "properties": {"displayName": "NEW"}}])
    report = detect_drift([handler], tmp_path)
    write_drift(report, tmp_path)
    on_disk = yaml.safe_load(local.read_text())
    assert on_disk["payload"]["displayName"] == "NEW"  # content imported
    assert on_disk["version"] == "1.5.0"  # ...version untouched


def test_write_drift_creates_new_file_under_asset_dir(tmp_path: Path) -> None:
    handler = _StubHandler([{"name": "rule-e", "properties": {"displayName": "E"}}])
    report = detect_drift([handler], tmp_path)
    written = write_drift(report, tmp_path)
    assert len(written) == 1
    assert written[0].name == "rule-e.yml"
    assert "sentinel_analytic" in str(written[0])


def test_detect_drift_continues_on_handler_list_error(tmp_path: Path, caplog) -> None:
    class _BoomHandler:
        asset = Asset.SENTINEL_ANALYTIC
        def list_remote(self): raise RuntimeError("api down")
        def to_envelope(self, r): return r

    good = _StubHandler([{"name": "rule-f", "properties": {}}])
    report = detect_drift([_BoomHandler(), good], tmp_path)
    # Bad handler logged AND surfaced as an error entry; good handler still ran.
    assert len(report.new) == 1
    assert len(report.errors) == 1
    assert report.errors[0].asset is Asset.SENTINEL_ANALYTIC
    assert "api down" in (report.errors[0].error or "")
    assert report.has_errors()


def test_detect_drift_surfaces_list_remote_failure(tmp_path: Path) -> None:
    """Regression for C-3: list_remote failures used to silently log
    and continue, producing a report that said "no changes" while the
    asset kind was never actually checked. Now an error entry surfaces
    so the CLI exit code + JSON report reflect the missed check.
    """
    class _BoomHandler:
        asset = Asset.SENTINEL_ANALYTIC
        def list_remote(self): raise RuntimeError("ARM 503")
        def to_envelope(self, r): return r

    report = detect_drift([_BoomHandler()], tmp_path)
    assert report.has_errors()
    assert not report.has_drift()  # new/changed empty — the failure isn't drift
    assert report.errors[0].asset_id == "*"


def test_detect_drift_logs_unloadable_yaml(tmp_path: Path, caplog) -> None:
    """Regression for C-2: a malformed YAML file used to silently drop
    out of the local index, making the matching remote rule look NEW.
    """
    import logging
    bad = tmp_path / "sentinel_analytic" / "broken.yml"
    bad.parent.mkdir(parents=True, exist_ok=True)
    bad.write_text("id: rule-broken\nversion: 0.1.0\nasset: sentinel_analytic\n"
                   "status: production\npayload: [: invalid", encoding="utf-8")
    handler = _StubHandler([])
    with caplog.at_level(logging.WARNING, logger="contentops.core.drift"):
        detect_drift([handler], tmp_path)
    assert any("broken.yml" in rec.message for rec in caplog.records)
