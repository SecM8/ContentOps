# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for the kql_strict wrapper-finding allowlist.

Covers loader behaviour (missing / malformed / partially-invalid)
and the suppression check. Wired-into-run_strict integration is
covered by tests/v2/test_lint_strict_dotnet.py-style fixtures when
the wrapper is present; here we exercise the pure-Python pieces.
"""

from __future__ import annotations

from pathlib import Path

from contentops.lint.kql import LintFinding
from contentops.lint.strict_allowlist import (
    ALLOWED_RULES,
    AllowlistEntry,
    load_allowlist,
    should_suppress,
)


def _write(path: Path, body: str) -> Path:
    path.write_text(body, encoding="utf-8")
    return path


def test_load_returns_empty_when_file_missing(tmp_path: Path) -> None:
    entries, notes = load_allowlist(tmp_path / "does-not-exist.yml")
    assert entries == ()
    assert notes == []


def test_load_returns_empty_when_allowlist_key_absent(tmp_path: Path) -> None:
    cfg = _write(tmp_path / "a.yml", "schema_version: 1\n")
    entries, notes = load_allowlist(cfg)
    assert entries == ()
    assert notes == []


def test_load_parses_valid_entries(tmp_path: Path) -> None:
    cfg = _write(tmp_path / "a.yml", (
        "allowlist:\n"
        "  - rule: KS142\n"
        "    pattern: '\\bSHA1\\d+\\b'\n"
        "    reason: KQL join-suffix convention\n"
        "  - rule: KS211\n"
        "    pattern: '\\bFileProfile\\b'\n"
        "    reason: Defender-specific invoke function\n"
    ))
    entries, notes = load_allowlist(cfg)
    assert notes == []
    assert len(entries) == 2
    assert entries[0].rule_id == "KS142"
    assert entries[1].rule_id == "KS211"
    assert "join-suffix" in entries[0].reason


def test_load_rejects_entry_without_reason(tmp_path: Path) -> None:
    cfg = _write(tmp_path / "a.yml", (
        "allowlist:\n"
        "  - rule: KS142\n"
        "    pattern: 'X'\n"
    ))
    entries, notes = load_allowlist(cfg)
    assert entries == ()
    assert any("reason" in n for n in notes)


def test_load_rejects_disallowed_rule_id(tmp_path: Path) -> None:
    """Heuristic rules (KQL001-007) and policy rules (KQL101) cannot
    be allowlisted -- the loader skips them and emits an info note
    naming the allowed set."""
    cfg = _write(tmp_path / "a.yml", (
        "allowlist:\n"
        "  - rule: KQL101\n"
        "    pattern: 'take'\n"
        "    reason: ignore the policy rule entirely\n"
    ))
    entries, notes = load_allowlist(cfg)
    assert entries == ()
    assert any("not allowlistable" in n for n in notes)
    # All allowed rules named in the note so an operator can fix the file.
    assert any("KS142" in n for n in notes)


def test_load_rejects_invalid_regex(tmp_path: Path) -> None:
    cfg = _write(tmp_path / "a.yml", (
        "allowlist:\n"
        "  - rule: KS142\n"
        "    pattern: '['\n"
        "    reason: unterminated character class\n"
    ))
    entries, notes = load_allowlist(cfg)
    assert entries == ()
    assert any("not a valid regex" in n for n in notes)


def test_load_falls_back_to_empty_on_malformed_yaml(tmp_path: Path) -> None:
    cfg = _write(tmp_path / "a.yml", "::: not yaml :::\n  - x: [")
    entries, notes = load_allowlist(cfg)
    assert entries == ()
    assert any("failed to parse" in n for n in notes)


def test_load_skips_bad_entries_keeps_good_ones(tmp_path: Path) -> None:
    """Partial validity: a single bad entry doesn't tank the rest of
    the file. Operators get a note per skip plus the good entries."""
    cfg = _write(tmp_path / "a.yml", (
        "allowlist:\n"
        "  - rule: KS142\n"
        "    pattern: '\\bSHA\\d+\\b'\n"
        "    reason: join suffix\n"
        "  - rule: KQL004\n"            # disallowed
        "    pattern: 'project'\n"
        "    reason: nope\n"
        "  - rule: KS211\n"
        "    pattern: '\\bFileProfile\\b'\n"
        "    reason: invoke\n"
    ))
    entries, notes = load_allowlist(cfg)
    assert len(entries) == 2
    assert {e.rule_id for e in entries} == {"KS142", "KS211"}
    assert len(notes) == 1
    assert "KQL004" in notes[0]


def test_should_suppress_matches_rule_id_and_pattern() -> None:
    allow = (
        AllowlistEntry(
            rule_id="KS142",
            pattern=__import__("re").compile(r"\bSHA1\d+\b"),
            reason="join suffix",
        ),
    )
    f = LintFinding("KS142", "warning", "The name 'SHA11' does not refer to any known column", line=5)
    assert should_suppress(f, allow) is True


def test_should_suppress_rejects_different_rule_id() -> None:
    allow = (
        AllowlistEntry(
            rule_id="KS142",
            pattern=__import__("re").compile(r".*"),
            reason="match anything",
        ),
    )
    f = LintFinding("KS204", "warning", "any message", line=1)
    assert should_suppress(f, allow) is False


def test_should_suppress_rejects_when_pattern_misses() -> None:
    allow = (
        AllowlistEntry(
            rule_id="KS142",
            pattern=__import__("re").compile(r"\bSHA1\d+\b"),
            reason="join suffix",
        ),
    )
    f = LintFinding("KS142", "warning", "The name 'TypoColumn' is unknown", line=2)
    assert should_suppress(f, allow) is False


def test_empty_allowlist_suppresses_nothing() -> None:
    f = LintFinding("KS142", "warning", "anything", line=1)
    assert should_suppress(f, ()) is False


def test_allowed_rules_constant_includes_documented_ids() -> None:
    """Pin the public contract: only KS142 + KS211 are allowlistable.
    Adding rules to the constant is a deliberate operator decision;
    this test exists so a casual edit (e.g. "while I'm here let me
    also add KS204") fails CI and forces conversation."""
    assert ALLOWED_RULES == frozenset({"KS142", "KS211"})


def test_example_config_loads_cleanly() -> None:
    """The shipped `config/kql_lint_allowlist.yml.example` must parse
    without notes when loaded as-is. Catches example-file drift."""
    repo_root = Path(__file__).resolve().parents[2]
    example = repo_root / "config" / "kql_lint_allowlist.yml.example"
    assert example.exists(), example
    entries, notes = load_allowlist(example)
    assert notes == [], notes
    assert len(entries) > 0
    # Every entry must have a non-trivial reason (the example doc
    # contract -- skip-with-reason is a hard requirement).
    assert all(len(e.reason) > 10 for e in entries)
