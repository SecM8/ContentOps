# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for contentops/lint/strict_config.py."""

from __future__ import annotations

from pathlib import Path

from contentops.lint.strict_config import (
    DEFAULT_CONFIG,
    LintStrictConfig,
    load_lint_strict_config,
)


def test_load_returns_defaults_when_missing(tmp_path: Path) -> None:
    cfg, info = load_lint_strict_config(tmp_path / "missing.yml")
    assert cfg == DEFAULT_CONFIG
    assert cfg.mode == "report"
    assert cfg.sentinel_enabled is True
    assert cfg.defender_enabled is True
    assert cfg.refresh_on_pr is True
    assert info is not None
    assert "not found" in info


def test_load_returns_defaults_on_malformed_yaml(tmp_path: Path) -> None:
    p = tmp_path / "broken.yml"
    p.write_text("not: valid: yaml: [", encoding="utf-8")
    cfg, info = load_lint_strict_config(p)
    assert cfg == DEFAULT_CONFIG
    assert info is not None
    assert "failed to parse" in info


def test_load_returns_defaults_on_non_mapping_top_level(tmp_path: Path) -> None:
    p = tmp_path / "list.yml"
    p.write_text("- not a mapping\n", encoding="utf-8")
    cfg, info = load_lint_strict_config(p)
    assert cfg == DEFAULT_CONFIG
    assert info is not None
    assert "not a mapping" in info


def test_mode_off_loaded(tmp_path: Path) -> None:
    p = tmp_path / "lint_strict.yml"
    p.write_text("mode: off\n", encoding="utf-8")
    cfg, info = load_lint_strict_config(p)
    assert cfg.mode == "off"
    assert info is None


def test_mode_block_loaded(tmp_path: Path) -> None:
    p = tmp_path / "lint_strict.yml"
    p.write_text("mode: block\n", encoding="utf-8")
    cfg, info = load_lint_strict_config(p)
    assert cfg.mode == "block"


def test_invalid_mode_falls_back_to_report_with_info(tmp_path: Path) -> None:
    p = tmp_path / "lint_strict.yml"
    p.write_text("mode: full-strict\n", encoding="utf-8")
    cfg, info = load_lint_strict_config(p)
    assert cfg.mode == "report"
    assert info is not None
    assert "invalid mode" in info
    assert "full-strict" in info


def test_per_source_disable(tmp_path: Path) -> None:
    p = tmp_path / "lint_strict.yml"
    p.write_text(
        "mode: block\n"
        "sentinel:\n  enabled: false\n"
        "defender:\n  enabled: true\n",
        encoding="utf-8",
    )
    cfg, _ = load_lint_strict_config(p)
    assert cfg.mode == "block"
    assert cfg.sentinel_enabled is False
    assert cfg.defender_enabled is True


def test_refresh_on_pr_default_true_when_key_absent(tmp_path: Path) -> None:
    p = tmp_path / "lint_strict.yml"
    p.write_text("mode: report\n", encoding="utf-8")
    cfg, _ = load_lint_strict_config(p)
    assert cfg.refresh_on_pr is True


def test_refresh_on_pr_can_be_disabled(tmp_path: Path) -> None:
    p = tmp_path / "lint_strict.yml"
    p.write_text("refresh_on_pr: false\n", encoding="utf-8")
    cfg, _ = load_lint_strict_config(p)
    assert cfg.refresh_on_pr is False


def test_dataclass_frozen() -> None:
    """LintStrictConfig is frozen; tests rely on it being hashable / immutable."""
    cfg = LintStrictConfig(mode="block")
    # AssertionError if not frozen — frozen dataclasses raise FrozenInstanceError
    import dataclasses as _dc
    try:
        cfg.mode = "off"  # type: ignore[misc]
    except _dc.FrozenInstanceError:
        return
    raise AssertionError("expected FrozenInstanceError")


# ---------------------------------------------------------------------------
# schema_exclude_tables (keep operator scratch/test tables out of the schema)
# ---------------------------------------------------------------------------


def test_schema_exclude_tables_defaults_empty(tmp_path: Path) -> None:
    p = tmp_path / "c.yml"
    p.write_text("mode: report\n", encoding="utf-8")
    cfg, _ = load_lint_strict_config(p)
    assert cfg.schema_exclude_tables == ()


def test_schema_exclude_tables_parsed_as_tuple(tmp_path: Path) -> None:
    p = tmp_path / "c.yml"
    p.write_text(
        "mode: report\n"
        "schema_exclude_tables:\n"
        "  - 'Test*'\n"
        "  - 'SuspiciousUA*'\n"
        "  - '  '\n",                # blank entry dropped
        encoding="utf-8",
    )
    cfg, _ = load_lint_strict_config(p)
    assert cfg.schema_exclude_tables == ("Test*", "SuspiciousUA*")


def test_schema_exclude_tables_non_list_is_ignored(tmp_path: Path) -> None:
    p = tmp_path / "c.yml"
    p.write_text("schema_exclude_tables: nope\n", encoding="utf-8")
    cfg, info = load_lint_strict_config(p)
    assert cfg.schema_exclude_tables == ()
    assert info is not None and "schema_exclude_tables" in info
