# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for `contentops clean` and `contentops collect --clear`.

Both share the same `_clean_local_detections` helper. The CLI
surface stays thin so we exercise the helper directly + the
click command's preview / confirm flow via CliRunner.
"""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from contentops.cli import cli
from contentops.cli.commands import _clean_local_detections
from contentops.core.asset import Asset


def _seed_corpus(tmp_path: Path) -> Path:
    """Create a representative detections/ layout for cleaning."""
    root = tmp_path / "detections"
    # v2 kind dirs that should be cleaned by default.
    (root / "sentinel_analytic").mkdir(parents=True)
    (root / "sentinel_analytic" / "a.yml").write_text("id: a\n", encoding="utf-8")
    (root / "sentinel_analytic" / "b.yml").write_text("id: b\n", encoding="utf-8")

    (root / "defender_custom_detection").mkdir()
    (root / "defender_custom_detection" / "c.yml").write_text("id: c\n", encoding="utf-8")

    (root / "sentinel_watchlist").mkdir()
    (root / "sentinel_watchlist" / "d.yml").write_text("id: d\n", encoding="utf-8")

    # Preserved dirs.
    (root / "templates").mkdir()
    (root / "templates" / "tmpl.yml").write_text("id: tmpl\n", encoding="utf-8")
    (root / "samples").mkdir()
    (root / "samples" / "sample.yml").write_text("id: s\n", encoding="utf-8")

    # Unrelated directory that the cleaner shouldn't touch.
    (root / "unknown_dir").mkdir()
    (root / "unknown_dir" / "x.yml").write_text("id: x\n", encoding="utf-8")

    return root


# ---------------------------------------------------------------------------
# Helper: _clean_local_detections
# ---------------------------------------------------------------------------


def test_helper_removes_all_v2_kind_dirs_by_default(tmp_path) -> None:
    root = _seed_corpus(tmp_path)

    deleted, dirs_removed = _clean_local_detections(root, asset_kinds=None)

    # 4 YAMLs across the cleanable v2 dirs (a, b, c, d).
    assert deleted == 4
    assert set(dirs_removed) == {
        "sentinel_analytic",
        "defender_custom_detection",
        "sentinel_watchlist",
    }

    # Preserved.
    assert (root / "templates" / "tmpl.yml").exists()
    assert (root / "samples" / "sample.yml").exists()
    # Unknown dirs left alone.
    assert (root / "unknown_dir" / "x.yml").exists()


def test_helper_respects_asset_filter(tmp_path) -> None:
    """An --asset filter restricts the helper to one kind."""
    root = _seed_corpus(tmp_path)

    deleted, dirs_removed = _clean_local_detections(
        root,
        asset_kinds={Asset.SENTINEL_ANALYTIC},
    )

    assert deleted == 2
    assert set(dirs_removed) == {"sentinel_analytic"}
    # Other v2 dirs untouched.
    assert (root / "defender_custom_detection" / "c.yml").exists()
    assert (root / "sentinel_watchlist" / "d.yml").exists()


# ---------------------------------------------------------------------------
# CLI: contentops clean
# ---------------------------------------------------------------------------


def test_cli_clean_requires_confirmation(tmp_path) -> None:
    """Without --yes, the command prompts and aborts on no."""
    root = _seed_corpus(tmp_path)

    result = CliRunner().invoke(
        cli, ["clean", "--path", str(root)], input="n\n",
    )
    # Click's abort sets exit code 1 by default.
    assert result.exit_code != 0
    # Files preserved.
    assert (root / "sentinel_analytic" / "a.yml").exists()


def test_cli_clean_with_yes_runs_destructive_path(tmp_path) -> None:
    root = _seed_corpus(tmp_path)

    result = CliRunner().invoke(
        cli, ["clean", "--path", str(root), "--yes"],
    )
    assert result.exit_code == 0, result.output
    assert not (root / "sentinel_analytic").exists()
    assert "Deleted 4 YAML file(s)" in result.output
    # Preserved.
    assert (root / "templates" / "tmpl.yml").exists()


def test_cli_clean_asset_filter(tmp_path) -> None:
    root = _seed_corpus(tmp_path)

    result = CliRunner().invoke(cli, [
        "clean", "--path", str(root), "--yes",
        "--asset", "sentinel_analytic",
    ])
    assert result.exit_code == 0, result.output
    assert not (root / "sentinel_analytic").exists()
    # Other kinds untouched.
    assert (root / "defender_custom_detection" / "c.yml").exists()
    assert (root / "sentinel_watchlist" / "d.yml").exists()
