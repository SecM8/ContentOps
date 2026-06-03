# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Regression test for C-1 — envelope metadata fallback logging.

When envelope metadata fails strict parsing (e.g. a typo in
``tactics`` or an invalid ``severity`` value), parse_envelope falls
back to loose acceptance preserving only ``arm_name``. The fallback
used to swallow the exception with a bare ``except Exception:`` and
no log line, so the silent field-drop was invisible to operators.
"""

from __future__ import annotations

import logging

from contentops.core.envelope import parse_envelope


def test_metadata_fallback_logs_warning_with_id(caplog) -> None:
    # Partial metadata: not strict-complete (missing required fields)
    # AND not pure-loose (has extra keys beyond arm_name). Lands in
    # the else branch where the strict-then-loose fallback runs.
    raw = {
        "id": "rule-typo",
        "version": "0.1.0",
        "asset": "sentinel_analytic",
        "status": "production",
        "metadata": {
            "arm_name": "1234",
            # Invalid severity value — RuleMetadata's Literal validator
            # raises on the strict path; the loose fallback then drops
            # everything except arm_name.
            "severity": "not-a-valid-severity",
        },
        "payload": {},
    }
    with caplog.at_level(logging.WARNING, logger="contentops.core.envelope"):
        envelope, _ = parse_envelope(raw)
    # Loose-fallback path preserves arm_name…
    assert envelope.arm_name == "1234"
    # …but the warning carries the rule id + the validation message.
    assert any(
        "rule-typo" in rec.message and "loose parse" in rec.message
        for rec in caplog.records
    )


def test_strict_metadata_does_not_log_fallback(caplog) -> None:
    """Sanity check: a well-formed envelope should not emit the fallback log."""
    raw = {
        "id": "rule-good",
        "version": "0.1.0",
        "asset": "sentinel_analytic",
        "status": "production",
        "metadata": {
            "arm_name": "1234",
            "owner": "me@example.com",
            "runbookUrl": "https://runbooks.example.com/x",
            "severity": "medium",
            "tactics": ["Execution"],
            "techniques": ["T1059"],
            "expectedAlertsPerDay": 1,
            "fpHandling": "n/a",
        },
        "payload": {},
    }
    with caplog.at_level(logging.WARNING, logger="contentops.core.envelope"):
        parse_envelope(raw)
    assert not any(
        "loose parse" in rec.message for rec in caplog.records
    )


def test_loose_parse_tally_records_and_dedupes_ids() -> None:
    """The CLI replaces the per-rule WARNING flood with one summary line
    built from this tally; it must dedupe by rule id (the operator repo
    carries duplicate-id collected rules)."""
    from contentops.core.envelope import (
        loose_parse_fallback_ids,
        reset_loose_parse_fallbacks,
    )

    reset_loose_parse_fallbacks()
    raw = {
        "id": "rule-tally",
        "version": "0.1.0",
        "asset": "sentinel_analytic",
        "status": "production",
        "metadata": {"arm_name": "1", "severity": "not-valid"},
        "payload": {},
    }
    parse_envelope(raw)
    parse_envelope(raw)  # same id twice -> counted once
    assert loose_parse_fallback_ids() == frozenset({"rule-tally"})
    reset_loose_parse_fallbacks()
    assert loose_parse_fallback_ids() == frozenset()


def test_emit_loose_parse_summary_one_line(capsys) -> None:
    """``_emit_loose_parse_summary`` prints one note (to stderr) when
    anything fell back, and nothing when the tally is empty."""
    from contentops.cli.commands import _emit_loose_parse_summary
    from contentops.core.envelope import (
        _record_loose_parse_fallback,
        reset_loose_parse_fallbacks,
    )

    reset_loose_parse_fallbacks()
    _emit_loose_parse_summary(0)
    captured = capsys.readouterr()
    assert captured.err == ""  # no-op when nothing fell back
    assert captured.out == ""

    _record_loose_parse_fallback("r1")
    _record_loose_parse_fallback("r2")
    _emit_loose_parse_summary(0)
    captured = capsys.readouterr()
    assert captured.out == ""  # summary never touches stdout
    assert "2 detection(s)" in captured.err
    assert "contentops lint" in captured.err
    assert "-v" in captured.err  # default-verbosity hint
    reset_loose_parse_fallbacks()


def test_loose_parse_note_shown_for_doctor_suppressed_for_lint(
    tmp_path, monkeypatch,
) -> None:
    """The note says "run contentops lint", so it's circular on `lint`
    itself — suppress it there, keep it on other detection-loading
    commands like `doctor`. (Adopters hit this on their own filled repo
    once they `collect` + `lint`, so it's not operator-repo-specific.)"""
    from click.testing import CliRunner

    from contentops.cli import cli

    det = tmp_path / "detections" / "sentinel_analytic"
    det.mkdir(parents=True)
    # Partial metadata (keys beyond arm_name, not strict-complete) lands
    # in the else-branch loose-parse fallback.
    (det / "partial.yml").write_text(
        "id: partial-rule\n"
        "version: 0.1.0\n"
        "asset: sentinel_analytic\n"
        "status: experimental\n"
        "metadata:\n"
        "  arm_name: '1'\n"
        "  severity: not-a-valid-severity\n"
        "payload:\n"
        "  query: 'SecurityEvent | take 1'\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()

    # lint: the per-rule findings already print; the note is suppressed.
    res_lint = runner.invoke(cli, ["lint", "--path", str(tmp_path / "detections")])
    assert "incomplete authoring metadata" not in res_lint.stderr

    # doctor: the one-line note is shown (on stderr).
    res_doc = runner.invoke(cli, ["doctor"])
    assert "incomplete authoring metadata" in res_doc.stderr
