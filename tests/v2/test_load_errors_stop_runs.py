# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""A detection file that fails to load must stop a run that writes, not
vanish from it.

It was only echoed to stderr and left out: apply reported "No assets to
apply" and exited 0 (the change never deployed), and prune counted that
file's live rule as an orphan and deleted it.
"""

from __future__ import annotations

from pathlib import Path

import yaml
from click.testing import CliRunner

from contentops.cli import cli
from contentops.core.asset import Asset
from contentops.core.drift import detect_drift
from contentops.core.registry import default_registry

_GOOD = {
    "id": "hunt-good", "version": "1.0.0", "asset": "sentinel_hunting", "status": "production",
    "payload": {"displayName": "Hunt good", "query": "SecurityEvent | take 1"},
}


def _tree(tmp_path: Path) -> Path:
    folder = tmp_path / "detections" / "sentinel_hunting"
    folder.mkdir(parents=True)
    (folder / "hunt-good.yml").write_text(yaml.safe_dump(_GOOD), encoding="utf-8")
    (folder / "hunt-broken.yml").write_text("id: hunt-broken\nversion: [1.0\n", encoding="utf-8")
    return tmp_path / "detections"


def _invoke(args: list[str]):
    default_registry.reset_all()
    try:
        return CliRunner().invoke(cli, args)
    finally:
        default_registry.reset_all()


def test_plan_stops_when_a_file_fails_to_load(tmp_path: Path) -> None:
    result = _invoke(["plan", "--path", str(_tree(tmp_path)), "--skip-deps-check"])
    assert result.exit_code == 1, result.output
    assert "hunt-broken.yml" in result.output
    assert "failed to load" in result.output


def test_apply_stops_before_any_write_when_a_file_fails_to_load(tmp_path: Path) -> None:
    result = _invoke(["apply", "--path", str(_tree(tmp_path)), "--dry-run", "--skip-deps-check"])
    assert result.exit_code == 1, result.output
    assert "hunt-broken.yml" in result.output
    assert "Apply summary" not in result.output


def test_prune_refuses_when_a_file_fails_to_load(tmp_path: Path) -> None:
    """Its live rule would count as an orphan and be deleted."""
    result = _invoke(["prune", "--path", str(_tree(tmp_path))])
    assert result.exit_code == 2, result.output
    assert "hunt-broken.yml" in result.output
    assert "orphan" in result.output


def test_drift_reports_a_file_that_fails_to_load(tmp_path: Path) -> None:
    class Handler:
        asset = Asset.SENTINEL_HUNTING

        def list_remote(self):
            return []

        def to_envelope(self, remote):
            return None

    report = detect_drift([Handler()], _tree(tmp_path))
    errors = report.errors
    assert len(errors) == 1
    assert errors[0].asset is Asset.SENTINEL_HUNTING
    assert "hunt-broken.yml" in (errors[0].error or "")
