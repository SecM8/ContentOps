# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for `contentops lint --strict` (F1).

Strict mode runs two layers:

* Python policy rules (``contentops.lint.strict_rules``) — always.
  KQL101 (`| take` / `| limit` forbidden) is the first shipped
  rule; see ``test_lint_strict_take_limit.py`` for rule-level
  coverage.
* Optional Kusto.Language wrapper — layered on if installed.

These tests cover the wrapper integration + CLI plumbing.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from contentops.lint.kql import LintFinding
from contentops.lint.strict import (
    ADVISORY_MESSAGE,
    is_available,
    run_strict,
)


# ---------------------------------------------------------------------------
# is_available — reflects environment
# ---------------------------------------------------------------------------


def test_is_available_false_when_wrapper_missing(tmp_path: Path) -> None:
    """In a fresh repo with no wrapper present, is_available is False."""
    assert is_available(repo_root=tmp_path) is False


def test_is_available_false_when_only_wrapper_present(
    tmp_path: Path, monkeypatch,
) -> None:
    """Wrapper without dotnet → still not available."""
    (tmp_path / "tools").mkdir()
    (tmp_path / "tools" / "kql_strict.dll").write_text("stub", encoding="utf-8")
    monkeypatch.setattr(
        "contentops.lint.strict._resolve_dotnet", lambda: None,
    )
    assert is_available(repo_root=tmp_path) is False


def test_is_available_true_when_both_present(
    tmp_path: Path, monkeypatch,
) -> None:
    (tmp_path / "tools").mkdir()
    (tmp_path / "tools" / "kql_strict.dll").write_text("stub", encoding="utf-8")
    monkeypatch.setattr(
        "contentops.lint.strict._resolve_dotnet", lambda: "/usr/bin/dotnet",
    )
    assert is_available(repo_root=tmp_path) is True


# ---------------------------------------------------------------------------
# run_strict — stub mode
# ---------------------------------------------------------------------------


def test_run_strict_runs_python_rules_when_wrapper_unavailable(
    tmp_path: Path,
) -> None:
    """Without the dotnet wrapper, the Python rule pack still runs.

    The advisory is printed by the CLI as a banner — `run_strict`
    itself returns only real findings (no advisory finding).
    """
    findings = run_strict(
        tmp_path / "rule.yml", "T | take 1",
        repo_root=tmp_path,
    )
    assert [f.rule_id for f in findings] == ["KQL101"]
    assert findings[0].severity == "error"


def test_run_strict_returns_no_findings_for_clean_query(tmp_path: Path) -> None:
    """Clean query, no wrapper installed → no findings at all."""
    findings = run_strict(
        tmp_path / "rule.yml",
        "T | where TimeGenerated > ago(1h) | project a, b",
        repo_root=tmp_path,
    )
    assert findings == []


def test_advisory_message_still_exported(tmp_path: Path) -> None:
    """The CLI banner still relies on ADVISORY_MESSAGE."""
    assert "Kusto.Language" in ADVISORY_MESSAGE


# ---------------------------------------------------------------------------
# run_strict — wrapper-present mode (mocked subprocess.run)
# ---------------------------------------------------------------------------


def test_run_strict_parses_wrapper_diagnostics(
    tmp_path: Path, monkeypatch,
) -> None:
    """When wrapper + dotnet are present, parse one diagnostic per line."""
    (tmp_path / "tools").mkdir()
    (tmp_path / "tools" / "kql_strict.dll").write_text("stub", encoding="utf-8")
    monkeypatch.setattr(
        "contentops.lint.strict._resolve_dotnet", lambda: "/usr/bin/dotnet",
    )

    class _FakeResult:
        returncode = 0
        stdout = "KQL100\terror\t3\tundefined column 'foo'\nKQL101\twarning\t10\tobsolete operator\n"
        stderr = ""

    monkeypatch.setattr(
        "contentops.lint.strict.subprocess.run",
        lambda *a, **kw: _FakeResult(),
    )
    findings = run_strict(
        tmp_path / "rule.yml", "T | where foo == 1",
        repo_root=tmp_path,
    )
    assert len(findings) == 2
    assert findings[0].rule_id == "KQL100"
    assert findings[0].severity == "error"
    assert findings[0].line == 3
    assert findings[1].severity == "warning"


def test_run_strict_handles_wrapper_crash(
    tmp_path: Path, monkeypatch,
) -> None:
    (tmp_path / "tools").mkdir()
    (tmp_path / "tools" / "kql_strict.dll").write_text("stub", encoding="utf-8")
    monkeypatch.setattr(
        "contentops.lint.strict._resolve_dotnet", lambda: "/usr/bin/dotnet",
    )

    class _Crash:
        returncode = 1
        stdout = ""
        stderr = "wrapper boom"

    monkeypatch.setattr(
        "contentops.lint.strict.subprocess.run",
        lambda *a, **kw: _Crash(),
    )
    findings = run_strict(
        tmp_path / "rule.yml", "T",
        repo_root=tmp_path,
    )
    assert len(findings) == 1
    assert findings[0].rule_id == "KQL000"
    assert findings[0].severity == "warning"
    assert "boom" in findings[0].message


def test_run_strict_handles_invocation_failure(
    tmp_path: Path, monkeypatch,
) -> None:
    (tmp_path / "tools").mkdir()
    (tmp_path / "tools" / "kql_strict.dll").write_text("stub", encoding="utf-8")
    monkeypatch.setattr(
        "contentops.lint.strict._resolve_dotnet", lambda: "/usr/bin/dotnet",
    )
    def _boom(*a, **kw):
        raise OSError("could not exec")
    monkeypatch.setattr("contentops.lint.strict.subprocess.run", _boom)
    findings = run_strict(
        tmp_path / "rule.yml", "T",
        repo_root=tmp_path,
    )
    assert len(findings) == 1
    assert findings[0].severity == "warning"


def test_run_strict_skips_malformed_wrapper_output(
    tmp_path: Path, monkeypatch,
) -> None:
    (tmp_path / "tools").mkdir()
    (tmp_path / "tools" / "kql_strict.dll").write_text("stub", encoding="utf-8")
    monkeypatch.setattr(
        "contentops.lint.strict._resolve_dotnet", lambda: "/usr/bin/dotnet",
    )

    class _Mixed:
        returncode = 0
        stdout = "KQL100\terror\t3\tgood line\nnot-a-tab-separated-line\n"
        stderr = ""

    monkeypatch.setattr(
        "contentops.lint.strict.subprocess.run",
        lambda *a, **kw: _Mixed(),
    )
    findings = run_strict(
        tmp_path / "rule.yml", "T",
        repo_root=tmp_path,
    )
    # Only the well-formed diagnostic survives.
    assert [f.rule_id for f in findings] == ["KQL100"]


# ---------------------------------------------------------------------------
# run_strict — allowlist integration
# ---------------------------------------------------------------------------


def _wrapper_stub(tmp_path: Path, monkeypatch, stdout: str) -> None:
    """Mock the .NET wrapper to return ``stdout`` and pretend dotnet is
    on PATH. Used by every allowlist-integration test below."""
    (tmp_path / "tools").mkdir(exist_ok=True)
    (tmp_path / "tools" / "kql_strict.dll").write_text(
        "stub", encoding="utf-8",
    )
    monkeypatch.setattr(
        "contentops.lint.strict._resolve_dotnet", lambda: "/usr/bin/dotnet",
    )

    class _Result:
        returncode = 0

        def __init__(self, body: str) -> None:
            self.stdout = body
            self.stderr = ""

    monkeypatch.setattr(
        "contentops.lint.strict.subprocess.run",
        lambda *a, **kw: _Result(stdout),
    )


def test_run_strict_suppresses_allowlisted_wrapper_finding(
    tmp_path: Path, monkeypatch,
) -> None:
    """A KS142 finding matching an allowlist entry is filtered out of
    `run_strict`'s return value. Other findings flow through.

    The most important suppression path: without this assertion,
    operators have no CI-stable proof that their allowlist actually
    suppresses anything end-to-end. `should_suppress` is unit-tested
    in isolation; this test pins the wiring."""
    _wrapper_stub(
        tmp_path, monkeypatch,
        # Two diagnostics: a KS142 on SHA11 (allowlisted -> dropped)
        # and a KS204 on a real typo (NOT allowlistable -> kept).
        "KS142\twarning\t5\tThe name 'SHA11' does not refer to any known column\n"
        "KS204\twarning\t9\tThe name 'TypoTable' does not refer to any known table\n",
    )

    # Stub the allowlist loader so the test doesn't depend on a
    # config/kql_lint_allowlist.yml on the operator's filesystem.
    import re as _re
    from contentops.lint import strict_allowlist
    allow = (
        strict_allowlist.AllowlistEntry(
            rule_id="KS142",
            pattern=_re.compile(r"\bSHA\d+\b"),
            reason="KQL join-suffix convention",
        ),
    )
    monkeypatch.setattr(
        "contentops.lint.strict_allowlist.load_allowlist",
        lambda path=None: (allow, []),
    )

    findings = run_strict(
        tmp_path / "rule.yml", "T | join (T) on SHA1",
        repo_root=tmp_path,
    )
    rule_ids = [f.rule_id for f in findings]
    assert "KS142" not in rule_ids, (
        f"KS142 should have been suppressed by the allowlist. "
        f"Got: {rule_ids}"
    )
    assert "KS204" in rule_ids, (
        f"KS204 is NOT allowlistable and must flow through. "
        f"Got: {rule_ids}"
    )


def test_run_strict_surfaces_allowlist_parse_notes(
    tmp_path: Path, monkeypatch,
) -> None:
    """When `load_allowlist` returns notes about skipped/malformed
    entries, `run_strict` emits one KQL000 warning per note so the
    operator sees feedback in lint output. Without this surfacing, a
    typo'd rule ID or missing `reason` field silently loses the
    suppression and findings the operator thought were allowlisted
    appear in CI with no explanation."""
    _wrapper_stub(
        tmp_path, monkeypatch,
        "KS142\twarning\t5\tcolumn 'X' unknown\n",
    )

    # Two parse notes -- simulates two malformed entries skipped at
    # load time. The loader still returns whatever DID parse (here:
    # an empty tuple).
    notes = [
        "allowlist[0] rule 'KQL142' is not allowlistable; skipping.",
        "allowlist[2] missing 'reason' field; skipping.",
    ]
    monkeypatch.setattr(
        "contentops.lint.strict_allowlist.load_allowlist",
        lambda path=None: ((), notes),
    )

    findings = run_strict(
        tmp_path / "rule.yml", "T | take 1",
        repo_root=tmp_path,
    )
    note_findings = [
        f for f in findings
        if f.rule_id == "KQL000" and "kql_lint_allowlist" in f.message
    ]
    assert len(note_findings) == 2, (
        f"Expected 2 KQL000 warnings (one per skipped allowlist entry). "
        f"Got: {[(f.rule_id, f.message) for f in findings]}"
    )
    assert all(f.severity == "warning" for f in note_findings)
    assert any("not allowlistable" in f.message for f in note_findings)
    assert any("missing 'reason' field" in f.message for f in note_findings)
    # The actual wrapper finding still surfaces alongside the notes.
    assert any(f.rule_id == "KS142" for f in findings)


# ---------------------------------------------------------------------------
# CLI integration
# ---------------------------------------------------------------------------


def test_cli_lint_strict_prints_advisory(tmp_path: Path) -> None:
    """`contentops lint --strict` on a real workspace prints the advisory
    when the wrapper isn't installed."""
    from click.testing import CliRunner
    from contentops.cli import cli

    detections = tmp_path / "detections" / "sentinel_analytic"
    detections.mkdir(parents=True)
    # status: test (not production) — the test is about the wrapper
    # advisory, not about the L4 META-error escalation on production
    # rules.
    (detections / "rule.yml").write_text("""\
id: rule-x
version: 1.0.0
asset: sentinel_analytic
status: test
payload:
  displayName: x
  query: |
    SecurityEvent
    | where TimeGenerated > ago(1h)
""", encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(cli, [
        "lint", "--strict",
        "--path", str(tmp_path / "detections"),
    ])
    assert result.exit_code == 0, result.output
    assert "Kusto.Language" in result.output or "[strict]" in result.output
