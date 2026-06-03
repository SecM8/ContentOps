# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""CLI integration tests for `contentops upstream` (G3 + G4).

Mocks `SentinelArmProvider.from_env` so no Azure auth or network is
needed. Asserts dry-run + --write paths, idempotency, and that the
WHATSNEW file is only written when the diff is non-empty.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

from click.testing import CliRunner

from contentops.cli import cli


def _make_provider(raw_entries: list[dict]) -> MagicMock:
    provider = MagicMock()
    provider.list_resource.return_value = list(raw_entries)
    provider.close = MagicMock()
    return provider


def _arm_entry(name: str, version: str = "1.0.0") -> dict:
    return {
        "name": name,
        "kind": "Scheduled",
        "properties": {
            "displayName": name.title(),
            "version": version,
            "source": {"kind": "Solution"},
        },
    }


def _patch_from_env(monkeypatch, raw_entries: list[dict]) -> None:
    """Replace SentinelArmProvider.from_env with a stub returning raw_entries."""
    import contentops.providers.sentinel_arm as arm_mod
    provider = _make_provider(raw_entries)
    monkeypatch.setattr(
        arm_mod.SentinelArmProvider, "from_env",
        classmethod(lambda cls: provider),
    )


def test_check_marketplace_dry_run_lists_added(
    tmp_path: Path, monkeypatch,
) -> None:
    _patch_from_env(monkeypatch, [_arm_entry("pkg-a"), _arm_entry("pkg-b")])
    manifest = tmp_path / "m.json"

    result = CliRunner().invoke(cli, [
        "upstream", "check-marketplace",
        "--manifest", str(manifest),
        "--out", str(tmp_path / "whatsnew"),
    ])
    assert result.exit_code == 0, result.output
    assert "Content Packages" in result.output
    assert "added (2)" in result.output
    assert "pkg-a" in result.output
    # Dry-run: manifest must not exist.
    assert not manifest.exists()
    # Dry-run: no whatsnew file.
    assert not (tmp_path / "whatsnew").exists() or not list(
        (tmp_path / "whatsnew").glob("*.md")
    )


def test_check_marketplace_write_creates_manifest_and_whatsnew(
    tmp_path: Path, monkeypatch,
) -> None:
    _patch_from_env(monkeypatch, [_arm_entry("pkg-a"), _arm_entry("pkg-b")])
    manifest = tmp_path / "m.json"
    whatsnew_dir = tmp_path / "whatsnew"

    result = CliRunner().invoke(cli, [
        "upstream", "check-marketplace", "--write",
        "--manifest", str(manifest),
        "--out", str(whatsnew_dir),
    ])
    assert result.exit_code == 0, result.output
    assert manifest.exists()
    assert whatsnew_dir.exists()
    md_files = list(whatsnew_dir.glob("*.md"))
    assert len(md_files) == 1
    body = md_files[0].read_text(encoding="utf-8")
    assert "## Content Packages" in body
    assert "### Added (2)" in body


def test_check_marketplace_no_diff_writes_nothing(
    tmp_path: Path, monkeypatch,
) -> None:
    """Second invocation against an unchanged upstream is fully idempotent."""
    entries = [_arm_entry("pkg-a"), _arm_entry("pkg-b")]
    _patch_from_env(monkeypatch, entries)
    manifest = tmp_path / "m.json"
    whatsnew_dir = tmp_path / "whatsnew"

    # First run writes the manifest and one whatsnew file.
    CliRunner().invoke(cli, [
        "upstream", "check-marketplace", "--write",
        "--manifest", str(manifest), "--out", str(whatsnew_dir),
    ])
    first_manifest = manifest.read_bytes()
    first_files = sorted(p.name for p in whatsnew_dir.glob("*.md"))

    # Second run with the SAME upstream entries -> no new whatsnew, manifest unchanged.
    _patch_from_env(monkeypatch, entries)
    result = CliRunner().invoke(cli, [
        "upstream", "check-marketplace", "--write",
        "--manifest", str(manifest), "--out", str(whatsnew_dir),
    ])
    assert result.exit_code == 0, result.output
    assert manifest.read_bytes() == first_manifest
    assert sorted(p.name for p in whatsnew_dir.glob("*.md")) == first_files
    assert "no changes; manifest unchanged" in result.output


def test_check_templates_dry_run(tmp_path: Path, monkeypatch) -> None:
    _patch_from_env(monkeypatch, [
        _arm_entry("tpl-a"), _arm_entry("tpl-b", version="2.0.0"),
    ])
    result = CliRunner().invoke(cli, [
        "upstream", "check-templates",
        "--manifest", str(tmp_path / "t.json"),
        "--out", str(tmp_path / "whatsnew"),
    ])
    assert result.exit_code == 0, result.output
    assert "Alert Rule Templates" in result.output
    assert "added (2)" in result.output


def test_check_marketplace_version_bump_is_changed(
    tmp_path: Path, monkeypatch,
) -> None:
    manifest = tmp_path / "m.json"
    whatsnew_dir = tmp_path / "whatsnew"

    # Seed: write v1 baseline.
    _patch_from_env(monkeypatch, [_arm_entry("pkg-a", "1.0.0")])
    CliRunner().invoke(cli, [
        "upstream", "check-marketplace", "--write",
        "--manifest", str(manifest), "--out", str(whatsnew_dir),
    ])

    # Now upstream bumps to v2 -> changed entry.
    _patch_from_env(monkeypatch, [_arm_entry("pkg-a", "2.0.0")])
    result = CliRunner().invoke(cli, [
        "upstream", "check-marketplace",
        "--manifest", str(manifest), "--out", str(whatsnew_dir),
    ])
    assert result.exit_code == 0, result.output
    assert "changed (1)" in result.output
    assert "1.0.0 -> 2.0.0" in result.output
