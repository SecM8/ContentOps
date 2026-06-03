# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""KQL101 — `| take` / `| limit` forbidden in production detections."""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from contentops.cli import cli
from contentops.lint.strict_rules import no_take_or_limit, run_python_rules


def _ids(query: str) -> list[str]:
    return [f.rule_id for f in run_python_rules(query)]


def test_kql101_flags_take() -> None:
    findings = list(no_take_or_limit("T | take 100"))
    assert len(findings) == 1
    assert findings[0].rule_id == "KQL101"
    assert findings[0].severity == "error"
    assert "take" in findings[0].message


def test_kql101_flags_limit() -> None:
    findings = list(no_take_or_limit("T | limit 50"))
    assert len(findings) == 1
    assert findings[0].rule_id == "KQL101"
    assert "limit" in findings[0].message


def test_kql101_flags_take_without_arg() -> None:
    """`| take` without a numeric arg is still a take — flag it."""
    assert _ids("T | take") == ["KQL101"]


def test_kql101_is_case_insensitive() -> None:
    assert _ids("T | TAKE 100") == ["KQL101"]
    assert _ids("T | Limit 1") == ["KQL101"]


def test_kql101_ignores_take_in_line_comments() -> None:
    """`// | take 5` inside a comment must not trigger."""
    query = """\
T
// | take 5
| where x == 1
"""
    assert _ids(query) == []


def test_kql101_ignores_take_inside_string_literal() -> None:
    """A string literal that happens to contain `| take` is not a take."""
    query = 'T | where Comment == "| take 5"'
    assert _ids(query) == []


def test_kql101_ignores_lookalike_identifiers() -> None:
    """Word-boundary anchor — `takeover`, `limited` must not match."""
    assert _ids("T | where User == 'takeover'") == []
    assert _ids("T | extend limited_view = 1") == []


def test_kql101_passes_clean_top_n() -> None:
    """`top N by` is the recommended replacement and must not trigger."""
    query = "T | top 10 by Count desc"
    assert _ids(query) == []


def test_kql101_reports_correct_line_number() -> None:
    query = "T\n| where x == 1\n| take 50\n"
    findings = list(no_take_or_limit(query))
    assert len(findings) == 1
    assert findings[0].line == 3


def test_kql101_flags_multiple_occurrences() -> None:
    """Two violations in the same query → two findings."""
    query = "T\n| take 5\n| project a\n| limit 1\n"
    findings = list(no_take_or_limit(query))
    assert [f.rule_id for f in findings] == ["KQL101", "KQL101"]
    assert [f.line for f in findings] == [2, 4]


# ---------------------------------------------------------------------------
# CLI integration — `contentops lint --strict` flags KQL101 + exits non-zero
# ---------------------------------------------------------------------------


def _write_rule(detections: Path, query: str, *, rule_id: str = "rule-x") -> None:
    """Write a non-legacy v2 sentinel_analytic envelope so KQL rules run."""
    detections.mkdir(parents=True, exist_ok=True)
    (detections / f"{rule_id}.yml").write_text(
        f"""\
id: {rule_id}
version: 0.1.0
asset: sentinel_analytic
status: test
metadata:
  owner: secops@example.com
  runbookUrl: https://runbooks.example.com/x
  severity: low
  tactics: [Execution]
  techniques: [T1059]
  expectedAlertsPerDay: 1
  fpHandling: Triage manually.
payload:
  displayName: Strict-mode test rule
  severity: Low
  query: |
{_indent(query, 4)}
""",
        encoding="utf-8",
    )


def _indent(text: str, n: int) -> str:
    pad = " " * n
    return "\n".join(pad + line for line in text.splitlines())


def test_cli_lint_strict_flags_take_and_exits_nonzero(tmp_path: Path) -> None:
    detections = tmp_path / "detections" / "sentinel_analytic"
    _write_rule(
        detections,
        "SecurityEvent\n| where TimeGenerated > ago(1h)\n| take 1",
    )

    result = CliRunner().invoke(cli, [
        "lint", "--strict",
        "--path", str(tmp_path / "detections"),
    ])
    assert result.exit_code == 1, result.output
    assert "KQL101" in result.output
    assert "take" in result.output


def test_cli_lint_strict_clean_rule_passes(tmp_path: Path) -> None:
    detections = tmp_path / "detections" / "sentinel_analytic"
    _write_rule(
        detections,
        "SecurityEvent\n| where TimeGenerated > ago(1h)\n| project Foo",
    )

    result = CliRunner().invoke(cli, [
        "lint", "--strict",
        "--path", str(tmp_path / "detections"),
    ])
    assert result.exit_code == 0, result.output
    assert "KQL101" not in result.output
