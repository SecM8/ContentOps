# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for `pipeline restore <archive>` (F10)."""

from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path

import pytest
from click.testing import CliRunner

from contentops.cli import cli
from contentops.restore import RestoreError, restore_from_archive


# ---------------------------------------------------------------------------
# Archive helpers
# ---------------------------------------------------------------------------


def _make_archive(
    target: Path, files: dict[str, bytes],
) -> Path:
    """Build a .tar.gz at ``target`` containing ``files`` (path -> content)."""
    target.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(target, mode="w:gz") as tar:
        for name, body in files.items():
            data = io.BytesIO(body)
            info = tarfile.TarInfo(name=name)
            info.size = len(body)
            tar.addfile(info, data)
    return target


_RULE_YAML = b"""\
id: rule-x
version: 1.0.0
asset: sentinel_analytic
status: production
payload:
  displayName: X
"""


# ---------------------------------------------------------------------------
# restore_from_archive — happy paths and refusals
# ---------------------------------------------------------------------------


def test_restore_writes_yaml_files(tmp_path: Path) -> None:
    archive = _make_archive(tmp_path / "snap.tar.gz", {
        "detections/sentinel_analytic/rule-x.yml": _RULE_YAML,
        "detections/sentinel_analytic/rule-y.yml": _RULE_YAML.replace(
            b"rule-x", b"rule-y",
        ),
    })
    target = tmp_path / "out"
    report = restore_from_archive(archive, target=target)
    assert len(report.written) == 2
    assert (target / "detections/sentinel_analytic/rule-x.yml").exists()
    assert (target / "detections/sentinel_analytic/rule-y.yml").exists()


def test_restore_refuses_non_empty_target_without_force(tmp_path: Path) -> None:
    archive = _make_archive(tmp_path / "snap.tar.gz", {
        "detections/sentinel_analytic/rule-x.yml": _RULE_YAML,
    })
    target = tmp_path / "out"
    target.mkdir()
    (target / "existing.txt").write_text("don't clobber me", encoding="utf-8")
    with pytest.raises(RestoreError):
        restore_from_archive(archive, target=target)


def test_restore_force_overlays_archive_into_non_empty_target(tmp_path: Path) -> None:
    archive = _make_archive(tmp_path / "snap.tar.gz", {
        "detections/sentinel_analytic/rule-x.yml": _RULE_YAML,
    })
    target = tmp_path / "out"
    target.mkdir()
    (target / "existing.txt").write_text("preserved", encoding="utf-8")
    report = restore_from_archive(archive, target=target, force=True)
    # Existing non-conflicting file is preserved.
    assert (target / "existing.txt").read_text(encoding="utf-8") == "preserved"
    assert len(report.written) == 1


def test_restore_picks_up_manifest(tmp_path: Path) -> None:
    archive = _make_archive(tmp_path / "snap.tar.gz", {
        "MANIFEST.json": json.dumps({"asset_count": 7}).encode("utf-8"),
        "detections/sentinel_analytic/rule-x.yml": _RULE_YAML,
    })
    target = tmp_path / "out"
    report = restore_from_archive(archive, target=target)
    assert report.manifest_present is True
    assert report.manifest_assets == 7


def test_restore_skips_non_yaml_entries(tmp_path: Path) -> None:
    """Auxiliary files (logs, stray binaries) in the archive are NOT written."""
    archive = _make_archive(tmp_path / "snap.tar.gz", {
        "detections/sentinel_analytic/rule-x.yml": _RULE_YAML,
        "logs/collect.log": b"some garbage",
    })
    target = tmp_path / "out"
    report = restore_from_archive(archive, target=target)
    assert "logs/collect.log" in report.skipped
    assert not (target / "logs").exists()


def test_restore_refuses_path_traversal(tmp_path: Path) -> None:
    """A malicious archive trying to write to ../etc/passwd is rejected."""
    archive_path = tmp_path / "evil.tar.gz"
    with tarfile.open(archive_path, mode="w:gz") as tar:
        body = b"x"
        info = tarfile.TarInfo(name="../escaped.yml")
        info.size = len(body)
        tar.addfile(info, io.BytesIO(body))

    target = tmp_path / "out"
    with pytest.raises(RestoreError):
        restore_from_archive(archive_path, target=target)


def test_restore_missing_archive_raises(tmp_path: Path) -> None:
    with pytest.raises(RestoreError):
        restore_from_archive(tmp_path / "nope.tar.gz", target=tmp_path / "out")


def test_restore_unrecognised_extension_raises(tmp_path: Path) -> None:
    bad = tmp_path / "snap.zip"
    bad.write_bytes(b"PK")
    with pytest.raises(RestoreError):
        restore_from_archive(bad, target=tmp_path / "out")


# ---------------------------------------------------------------------------
# CLI integration
# ---------------------------------------------------------------------------


def test_cli_restore_happy_path(tmp_path: Path) -> None:
    archive = _make_archive(tmp_path / "snap.tar.gz", {
        "detections/sentinel_analytic/rule-x.yml": _RULE_YAML,
    })
    target = tmp_path / "out"
    runner = CliRunner()
    result = runner.invoke(cli, [
        "restore", str(archive), "--out", str(target),
    ])
    assert result.exit_code == 0, result.output
    assert "Restored 1 file(s)" in result.output


def test_cli_restore_refuses_non_empty_without_force(tmp_path: Path) -> None:
    archive = _make_archive(tmp_path / "snap.tar.gz", {
        "detections/sentinel_analytic/rule-x.yml": _RULE_YAML,
    })
    target = tmp_path / "out"
    target.mkdir()
    (target / "existing.txt").write_text("x", encoding="utf-8")
    runner = CliRunner()
    result = runner.invoke(cli, [
        "restore", str(archive), "--out", str(target),
    ])
    assert result.exit_code == 1
    assert "not empty" in result.output


def test_cli_restore_force_overlays(tmp_path: Path) -> None:
    archive = _make_archive(tmp_path / "snap.tar.gz", {
        "detections/sentinel_analytic/rule-x.yml": _RULE_YAML,
    })
    target = tmp_path / "out"
    target.mkdir()
    (target / "existing.txt").write_text("x", encoding="utf-8")
    runner = CliRunner()
    result = runner.invoke(cli, [
        "restore", str(archive), "--out", str(target), "--force",
    ])
    assert result.exit_code == 0, result.output
