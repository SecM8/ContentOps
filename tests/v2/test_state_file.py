# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for the per-env state file.

Covers load/save round-trips, the apply-merge helper, and the
classify_remote contract that drift / prune use to distinguish
"managed orphan" from "unmanaged remote".
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest
from click.testing import CliRunner

from contentops.cli import cli
from contentops.state import (
    AssetStateEntry,
    EnvState,
    classify_remote,
    load_state,
    merge_apply_results,
    save_state,
    state_path,
)


def test_state_path_default(tmp_path: Path) -> None:
    p = state_path(env=None, root=tmp_path)
    assert p == tmp_path / "state" / "state.json"


def test_state_path_with_env(tmp_path: Path) -> None:
    p = state_path(env="prod", root=tmp_path)
    assert p == tmp_path / "state" / "prod" / "state.json"


def test_load_state_absent_file_returns_empty(tmp_path: Path) -> None:
    s = load_state(env="prod", root=tmp_path)
    assert s.env == "prod"
    assert s.last_apply_sha == ""
    assert s.asset_count() == 0


def test_save_then_load_roundtrip(tmp_path: Path) -> None:
    s = EnvState(env="prod", last_apply_sha="abc123")
    s.remember(
        "sentinel_analytic", "rule-1",
        remote_id="rule-1", sha="abc123", status="success",
    )
    save_state(s, root=tmp_path)
    loaded = load_state(env="prod", root=tmp_path)
    assert loaded.last_apply_sha == "abc123"
    assert loaded.is_managed("sentinel_analytic", "rule-1")


def test_load_state_corrupt_returns_empty(tmp_path: Path) -> None:
    p = state_path(env="prod", root=tmp_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("not-valid-json", encoding="utf-8")
    s = load_state(env="prod", root=tmp_path)
    # Corrupt state must never crash the pipeline.
    assert s.env == "prod"
    assert s.asset_count() == 0


def _write_raw_state(tmp_path: Path, text: str) -> Path:
    p = state_path(env="prod", root=tmp_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


@pytest.mark.parametrize(
    "text",
    [
        "not-valid-json",
        "[]",
        '{"managed_assets": []}',
        '{"managed_assets": {"sentinel_analytic": ["rule-1"]}}',
        '{"managed_assets": {"sentinel_analytic": {"rule-1": "success"}}}',
    ],
    ids=["invalid-json", "top-level-list", "assets-list", "entries-list", "entry-string"],
)
def test_unreadable_state_is_reported_and_treated_as_empty(
    tmp_path: Path, caplog: pytest.LogCaptureFixture, text: str,
) -> None:
    """Invalid JSON used to become an empty state without a word, and valid
    JSON of the wrong shape crashed instead. Both now load as empty and
    say which file and how to rebuild it."""
    _write_raw_state(tmp_path, text)
    with caplog.at_level(logging.WARNING, logger="contentops.state"):
        s = load_state(env="prod", root=tmp_path)
    assert s.env == "prod"
    assert s.asset_count() == 0
    assert "state.json" in caplog.text
    assert "state adopt" in caplog.text


def test_state_entry_with_an_unknown_field_still_loads(tmp_path: Path) -> None:
    """A newer tool may add a field; an older one reads the known ones
    (it used to stop with a TypeError)."""
    _write_raw_state(
        tmp_path,
        '{"managed_assets": {"sentinel_analytic": {"rule-1": '
        '{"remote_id": "r1", "status": "success", "added_later": 1}}}}',
    )
    s = load_state(env="prod", root=tmp_path)
    assert s.is_managed("sentinel_analytic", "rule-1")
    assert s.managed_assets["sentinel_analytic"]["rule-1"].remote_id == "r1"


def test_saving_over_an_unreadable_state_keeps_a_copy(tmp_path: Path) -> None:
    """Saving used to replace an unreadable file with only the current
    batch, so the inventory it held was gone for good."""
    p = _write_raw_state(tmp_path, "not-valid-json")
    s = load_state(env="prod", root=tmp_path)
    s.remember("sentinel_analytic", "rule-1", status="success")
    save_state(s, root=tmp_path)
    copies = list(p.parent.glob("state.json.corrupt-*"))
    assert len(copies) == 1
    assert copies[0].read_text(encoding="utf-8") == "not-valid-json"
    assert load_state(env="prod", root=tmp_path).is_managed("sentinel_analytic", "rule-1")


def test_saving_over_a_readable_state_keeps_no_copy(tmp_path: Path) -> None:
    s = EnvState(env="prod")
    save_state(s, root=tmp_path)
    save_state(s, root=tmp_path)
    assert not list(state_path(env="prod", root=tmp_path).parent.glob("*corrupt*"))


def test_save_does_not_share_a_temporary_file_with_another_writer(tmp_path: Path) -> None:
    """Every save wrote ``state.tmp`` and renamed it, so two writers could
    swap each other's half-written files."""
    p = state_path(env="prod", root=tmp_path)
    p.parent.mkdir(parents=True)
    other = p.with_suffix(".tmp")
    other.write_text("another writer", encoding="utf-8")
    save_state(EnvState(env="prod"), root=tmp_path)
    assert other.read_text(encoding="utf-8") == "another writer"
    assert sorted(x.name for x in p.parent.iterdir()) == ["state.json", "state.tmp"]


def test_remember_and_forget() -> None:
    s = EnvState(env="prod")
    s.remember("sentinel_analytic", "rule-1", status="success")
    assert s.is_managed("sentinel_analytic", "rule-1")
    s.forget("sentinel_analytic", "rule-1")
    assert not s.is_managed("sentinel_analytic", "rule-1")
    # Empty bucket cleaned up.
    assert "sentinel_analytic" not in s.managed_assets


def test_merge_apply_results_skips_skipped() -> None:
    s = EnvState(env="prod")
    merge_apply_results(s, [
        ("sentinel_analytic", "kept", "kept", "success"),
        ("sentinel_analytic", "lost", "lost", "skipped"),
        ("sentinel_analytic", "broken", "broken", "failed"),
    ], sha="def456")
    assert s.last_apply_sha == "def456"
    assert s.is_managed("sentinel_analytic", "kept")
    assert not s.is_managed("sentinel_analytic", "lost")
    # Failed entries ARE recorded so the next retry-failed knows about them.
    assert s.is_managed("sentinel_analytic", "broken")
    assert s.managed_assets["sentinel_analytic"]["broken"].status == "failed"


def test_classify_remote_four_cases() -> None:
    s = EnvState(env="prod")
    s.remember("sentinel_analytic", "managed-rule")

    # in-sync: local + state
    assert classify_remote(s, "sentinel_analytic", "managed-rule", in_local=True) == "in-sync"
    # new-local: local but not in state (first apply)
    assert classify_remote(s, "sentinel_analytic", "fresh-rule", in_local=True) == "new-local"
    # orphan: state has it but local doesn't (delete candidate)
    assert classify_remote(s, "sentinel_analytic", "managed-rule", in_local=False) == "orphan"
    # unmanaged: neither
    assert classify_remote(s, "sentinel_analytic", "third-party", in_local=False) == "unmanaged"


# ---------------------------------------------------------------------------
# CLI: contentops state show / forget
# ---------------------------------------------------------------------------


def test_state_show_empty(tmp_path: Path) -> None:
    """Run from a tmp cwd so the state file lookup goes against a clean dir."""
    runner = CliRunner()
    result = runner.invoke(
        cli, ["state", "show", "--env", "absent"],
        catch_exceptions=False,
    )
    assert result.exit_code == 0
    # Either the empty-state header prints, or a JSON-rendered snapshot.
    assert "absent" in result.output or "asset_count" in result.output


def test_state_forget_via_cli(tmp_path: Path) -> None:
    """Round-trip: create a state file, forget an entry via CLI, reload."""
    runner = CliRunner()
    with runner.isolated_filesystem(temp_dir=tmp_path) as fs:
        s = EnvState(env="t")
        s.remember("sentinel_analytic", "to-forget")
        s.remember("sentinel_analytic", "to-keep")
        save_state(s, root=Path(fs))

        result = runner.invoke(
            cli,
            ["state", "forget", "to-forget",
             "--asset", "sentinel_analytic", "--env", "t"],
            catch_exceptions=False,
        )
        assert result.exit_code == 0, result.output

        reloaded = load_state(env="t", root=Path(fs))
        assert not reloaded.is_managed("sentinel_analytic", "to-forget")
        assert reloaded.is_managed("sentinel_analytic", "to-keep")
