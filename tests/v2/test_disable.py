# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for the `contentops disable` emergency command."""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from contentops.cli import cli


SAMPLE = """\
id: {rid}
version: 0.1.0
asset: sentinel_watchlist
status: production
payload:
  displayName: Sample
  provider: Custom
  source: Local file
  contentType: text/csv
  itemsSearchKey: AssetName
  rawContent: |
    AssetName,Tier
    a,0
"""


def _write(tmp_path: Path, name: str, rid: str, status: str = "production") -> Path:
    (tmp_path / "sentinel_watchlist").mkdir(exist_ok=True)
    p = tmp_path / "sentinel_watchlist" / name
    text = SAMPLE.format(rid=rid).replace("status: production", f"status: {status}")
    p.write_text(text)
    return p


def test_disable_finds_and_mutates_yaml(tmp_path: Path) -> None:
    p = _write(tmp_path, "rule.yml", "noisy-rule")
    runner = CliRunner()
    result = runner.invoke(cli, ["disable", "noisy-rule", "--path", str(tmp_path)])
    assert result.exit_code == 0, result.output
    text = p.read_text()
    assert "status: deprecated" in text
    assert "status: production" not in text
    assert "disabled noisy-rule" in result.output


def test_disable_rule_not_found_exits_1(tmp_path: Path) -> None:
    _write(tmp_path, "rule.yml", "real-rule")
    runner = CliRunner()
    result = runner.invoke(cli, ["disable", "missing-rule", "--path", str(tmp_path)])
    assert result.exit_code == 1
    assert "no rule with id" in result.output


def test_disable_already_deprecated_warns_and_exits_0(tmp_path: Path) -> None:
    p = _write(tmp_path, "rule.yml", "old-rule", status="deprecated")
    before = p.read_text()
    runner = CliRunner()
    result = runner.invoke(cli, ["disable", "old-rule", "--path", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert "already deprecated" in result.output
    assert p.read_text() == before


def test_disable_appends_reason_when_given(tmp_path: Path) -> None:
    p = _write(tmp_path, "rule.yml", "noisy-rule")
    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["disable", "noisy-rule", "--reason", "FP storm 3am", "--path", str(tmp_path)],
    )
    assert result.exit_code == 0, result.output
    text = p.read_text()
    assert "status: deprecated" in text
    assert 'disableReason: "FP storm 3am"' in text


def test_disable_refuses_when_multiple_matches(tmp_path: Path) -> None:
    _write(tmp_path, "a.yml", "dup-rule")
    _write(tmp_path, "b.yml", "dup-rule")
    runner = CliRunner()
    result = runner.invoke(cli, ["disable", "dup-rule", "--path", str(tmp_path)])
    assert result.exit_code == 1
    assert "matches 2 files" in result.output
