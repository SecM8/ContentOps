# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for the deployment-status renderer.

Builds a synthetic mini-repo under tmp_path with detection YAMLs +
state.json + audit JSONL, then renders and asserts row classification.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from contentops.state import AssetStateEntry, EnvState
from contentops.status.deployments import render_deployments


def _fixed_now() -> datetime:
    return datetime(2026, 5, 20, 12, 34, 56, tzinfo=timezone.utc)


def _write_detection(root: Path, kind: str, asset_id: str) -> Path:
    """Write a minimal valid envelope YAML for ``asset_id`` under ``root/kind/``."""
    target = root / kind / f"{asset_id}.yml"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        f"id: {asset_id}\nversion: 1.0.0\nasset: {kind}\n"
        "status: production\npayload: {}\n",
        encoding="utf-8",
    )
    return target


def _write_audit(audit_dir: Path, records: list[dict]) -> None:
    audit_dir.mkdir(parents=True, exist_ok=True)
    target = audit_dir / "2026-05-20.jsonl"
    target.write_text(
        "\n".join(json.dumps(r) for r in records) + "\n",
        encoding="utf-8",
    )


def _state_with(env: str, managed: dict[str, dict[str, AssetStateEntry]]) -> EnvState:
    return EnvState(
        env=env,
        last_apply_sha="deadbeef" + "0" * 32,
        last_apply_at="2026-05-20T10:00:00.000000Z",
        managed_assets=managed,
    )


def test_renders_title_and_generated_at(tmp_path: Path) -> None:
    md = render_deployments(
        detections_root=tmp_path / "detections",
        state=EnvState(),
        audit_dir=tmp_path / "audit",
        generated_at=_fixed_now(),
    )
    assert md.startswith("# Deployment status\n")
    assert "Last refreshed 2026-05-20 12:34 UTC" in md


def test_in_sync_row_appears_when_git_and_state_both_have_asset(tmp_path: Path) -> None:
    detections = tmp_path / "detections"
    _write_detection(detections, "sentinel_analytic", "brute-force-ssh-001")
    state = _state_with(
        "prod",
        {
            "sentinel_analytic": {
                "brute-force-ssh-001": AssetStateEntry(
                    remote_id="r-1",
                    last_applied_at="2026-05-20T10:00:00.000000Z",
                    last_applied_sha="abc12345" + "0" * 32,
                    status="success",
                ),
            },
        },
    )
    md = render_deployments(
        detections_root=detections,
        state=state,
        audit_dir=tmp_path / "audit",  # missing on purpose
        generated_at=_fixed_now(),
    )
    assert "`brute-force-ssh-001`" in md
    assert "✅ in-sync" in md
    assert "1 in-sync" in md
    assert "`abc12345`" in md  # short sha


def test_unmanaged_row_when_git_has_asset_not_in_state(tmp_path: Path) -> None:
    detections = tmp_path / "detections"
    _write_detection(detections, "sentinel_analytic", "unmanaged-rule")
    md = render_deployments(
        detections_root=detections,
        state=EnvState(),
        audit_dir=tmp_path / "audit",
        generated_at=_fixed_now(),
    )
    assert "`unmanaged-rule`" in md
    assert "⚪ unmanaged" in md
    assert "1 unmanaged" in md


def test_orphan_row_when_state_has_asset_not_in_git(tmp_path: Path) -> None:
    state = _state_with(
        "prod",
        {
            "sentinel_analytic": {
                "ghost-rule": AssetStateEntry(
                    remote_id="r-9",
                    last_applied_at="2026-05-19T08:00:00.000000Z",
                    last_applied_sha="bbbbbbbb" + "0" * 32,
                    status="success",
                ),
            },
        },
    )
    md = render_deployments(
        detections_root=tmp_path / "detections",  # missing
        state=state,
        audit_dir=tmp_path / "audit",
        generated_at=_fixed_now(),
    )
    assert "`ghost-rule`" in md
    assert "⚠️ orphan" in md
    assert "1 orphan" in md


def test_failed_when_state_or_audit_says_failed(tmp_path: Path) -> None:
    detections = tmp_path / "detections"
    _write_detection(detections, "sentinel_analytic", "flapping-rule")
    state = _state_with(
        "prod",
        {
            "sentinel_analytic": {
                "flapping-rule": AssetStateEntry(
                    remote_id="r-2",
                    last_applied_at="2026-05-20T09:00:00.000000Z",
                    last_applied_sha="ccccccc" + "0" * 33,
                    status="failed",
                ),
            },
        },
    )
    md = render_deployments(
        detections_root=detections,
        state=state,
        audit_dir=tmp_path / "audit",
        generated_at=_fixed_now(),
    )
    assert "`flapping-rule`" in md
    assert "❌ failed" in md
    assert "1 failed" in md


def test_audit_failure_promotes_in_sync_to_failed(tmp_path: Path) -> None:
    """State says success but the latest audit record is failed → classify as failed."""
    detections = tmp_path / "detections"
    _write_detection(detections, "sentinel_analytic", "regressed-rule")
    state = _state_with(
        "prod",
        {
            "sentinel_analytic": {
                "regressed-rule": AssetStateEntry(
                    remote_id="r-3",
                    last_applied_at="2026-05-20T08:00:00.000000Z",
                    last_applied_sha="dddddddd" + "0" * 32,
                    status="success",
                ),
            },
        },
    )
    _write_audit(
        tmp_path / "audit",
        [
            {
                "timestamp": "2026-05-20T11:00:00.000000Z",
                "asset": "sentinel_analytic",
                "id": "regressed-rule",
                "action": "update",
                "status": "failed",
                "sha": "deadbeef",
                "actor": "ci",
            }
        ],
    )
    md = render_deployments(
        detections_root=detections,
        state=state,
        audit_dir=tmp_path / "audit",
        generated_at=_fixed_now(),
    )
    assert "❌ failed" in md
    assert "update (failed)" in md  # last audit cell


def test_empty_everything_renders_placeholder(tmp_path: Path) -> None:
    md = render_deployments(
        detections_root=tmp_path / "detections",  # missing
        state=EnvState(),
        audit_dir=tmp_path / "audit",  # missing
        generated_at=_fixed_now(),
    )
    assert "_No detections discovered" in md


def test_per_kind_sections_with_counts(tmp_path: Path) -> None:
    detections = tmp_path / "detections"
    _write_detection(detections, "sentinel_analytic", "rule-a")
    _write_detection(detections, "sentinel_analytic", "rule-b")
    _write_detection(detections, "sentinel_hunting", "hunt-1")
    md = render_deployments(
        detections_root=detections,
        state=EnvState(),
        audit_dir=tmp_path / "audit",
        generated_at=_fixed_now(),
    )
    assert "## `sentinel_analytic` (2 assets)" in md
    assert "## `sentinel_hunting` (1 assets)" in md


def test_per_kind_subtotal_row_renders(tmp_path: Path) -> None:
    """A summary line of in-sync/failed/unmanaged/orphan appears above each table."""
    detections = tmp_path / "detections"
    _write_detection(detections, "sentinel_analytic", "rule-in-sync")
    _write_detection(detections, "sentinel_analytic", "rule-unmanaged")
    state = _state_with(
        "prod",
        {
            "sentinel_analytic": {
                "rule-in-sync": AssetStateEntry(
                    remote_id="r-1",
                    last_applied_at="2026-05-20T10:00:00.000000Z",
                    last_applied_sha="abc12345" + "0" * 32,
                    status="success",
                ),
                # In state but not in git -> orphan
                "rule-orphan": AssetStateEntry(
                    remote_id="r-9",
                    last_applied_at="2026-05-19T08:00:00.000000Z",
                    last_applied_sha="bbbbbbbb" + "0" * 32,
                    status="success",
                ),
            },
        },
    )
    md = render_deployments(
        detections_root=detections,
        state=state,
        audit_dir=tmp_path / "audit",
        generated_at=_fixed_now(),
    )
    # The per-kind subtotal line includes all four classes for this kind.
    assert (
        "✅ 1 in-sync · ❌ 0 failed · ⚪ 1 unmanaged · ⚠️ 1 orphan"
    ) in md


def test_failures_only_filters_in_sync_and_unmanaged(tmp_path: Path) -> None:
    """In failures-only mode, only failed + orphan rows survive."""
    detections = tmp_path / "detections"
    _write_detection(detections, "sentinel_analytic", "rule-clean")
    _write_detection(detections, "sentinel_analytic", "rule-untracked")  # unmanaged
    _write_detection(detections, "sentinel_analytic", "rule-broken")
    state = _state_with(
        "prod",
        {
            "sentinel_analytic": {
                "rule-clean": AssetStateEntry(
                    remote_id="r-1",
                    last_applied_at="2026-05-20T10:00:00.000000Z",
                    last_applied_sha="abc12345" + "0" * 32,
                    status="success",
                ),
                "rule-broken": AssetStateEntry(
                    remote_id="r-2",
                    last_applied_at="2026-05-20T10:00:00.000000Z",
                    last_applied_sha="abc12345" + "0" * 32,
                    status="failed",
                ),
                "rule-ghost": AssetStateEntry(  # orphan
                    remote_id="r-3",
                    last_applied_at="2026-05-19T08:00:00.000000Z",
                    last_applied_sha="bbbbbbbb" + "0" * 32,
                    status="success",
                ),
            },
        },
    )
    md = render_deployments(
        detections_root=detections,
        state=state,
        audit_dir=tmp_path / "audit",
        generated_at=_fixed_now(),
        failures_only=True,
    )
    # Filter banner present
    assert "Filtered to `failed` + `orphan`" in md
    # Failed + orphan survive
    assert "`rule-broken`" in md
    assert "`rule-ghost`" in md
    # In-sync + unmanaged are filtered out
    assert "`rule-clean`" not in md
    assert "`rule-untracked`" not in md


def test_failures_only_keeps_totals_intact(tmp_path: Path) -> None:
    """The global Totals line reflects the full counts even in filtered view."""
    detections = tmp_path / "detections"
    _write_detection(detections, "sentinel_analytic", "rule-clean")
    _write_detection(detections, "sentinel_analytic", "rule-broken")
    state = _state_with(
        "prod",
        {
            "sentinel_analytic": {
                "rule-clean": AssetStateEntry(
                    remote_id="r-1",
                    last_applied_at="2026-05-20T10:00:00.000000Z",
                    last_applied_sha="abc12345" + "0" * 32,
                    status="success",
                ),
                "rule-broken": AssetStateEntry(
                    remote_id="r-2",
                    last_applied_at="2026-05-20T10:00:00.000000Z",
                    last_applied_sha="abc12345" + "0" * 32,
                    status="failed",
                ),
            },
        },
    )
    md = render_deployments(
        detections_root=detections,
        state=state,
        audit_dir=tmp_path / "audit",
        generated_at=_fixed_now(),
        failures_only=True,
    )
    # Totals reflect both the in-sync rule and the failed one.
    assert "1 in-sync" in md
    assert "1 failed" in md


def test_failures_only_skips_kinds_with_no_actionable_rows(tmp_path: Path) -> None:
    """A kind whose subtotal is zero failed + zero orphan is dropped entirely."""
    detections = tmp_path / "detections"
    _write_detection(detections, "sentinel_analytic", "rule-clean")
    _write_detection(detections, "sentinel_hunting", "hunt-broken")
    state = _state_with(
        "prod",
        {
            "sentinel_analytic": {
                "rule-clean": AssetStateEntry(
                    remote_id="r-1",
                    last_applied_at="2026-05-20T10:00:00.000000Z",
                    last_applied_sha="abc12345" + "0" * 32,
                    status="success",
                ),
            },
            "sentinel_hunting": {
                "hunt-broken": AssetStateEntry(
                    remote_id="r-2",
                    last_applied_at="2026-05-20T10:00:00.000000Z",
                    last_applied_sha="abc12345" + "0" * 32,
                    status="failed",
                ),
            },
        },
    )
    md = render_deployments(
        detections_root=detections,
        state=state,
        audit_dir=tmp_path / "audit",
        generated_at=_fixed_now(),
        failures_only=True,
    )
    # The all-in-sync analytic kind is dropped; the failing hunting kind remains.
    assert "## `sentinel_analytic`" not in md
    assert "## `sentinel_hunting`" in md


def test_refresh_banner_links_to_workflow(tmp_path: Path) -> None:
    md = render_deployments(
        detections_root=tmp_path / "detections",
        state=EnvState(),
        audit_dir=tmp_path / "audit",
        generated_at=_fixed_now(),
    )
    assert "Last refreshed 2026-05-20 12:34 UTC" in md
    assert ".github/workflows/status-refresh.yml" in md
