# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for the M3 KQL linter and `contentops lint` CLI command."""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from contentops.cli import cli
from contentops.lint.kql import LintFinding, lint_kql


GOOD_QUERY = """\
SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID == 4625
| project TimeGenerated, Account, Computer
| take 100
"""


def _ids(findings: list[LintFinding]) -> set[str]:
    return {f.rule_id for f in findings}


def test_finding_shape_and_line_numbers() -> None:
    findings = lint_kql("T\n| where x == (1\n")
    assert findings, "expected at least one finding"
    f = findings[0]
    assert f.rule_id.startswith("KQL")
    assert f.severity in {"error", "warning", "info"}
    assert isinstance(f.message, str)
    assert f.line is None or isinstance(f.line, int)


def test_happy_path_canonical_good_query_triggers_nothing() -> None:
    findings = lint_kql(GOOD_QUERY, kind="sentinel_analytic")
    assert findings == [], f"expected no findings, got {findings!r}"


def test_verbatim_string_with_trailing_backslash_does_not_unterminate() -> None:
    """Kusto verbatim string ``@"...\\"`` was tripping the unterminated-
    string rule because the regex treated the trailing ``\\"`` as an
    escape sequence (regular-string semantics) instead of treating
    ``\\`` as literal and ``"`` as the closing quote (verbatim-string
    semantics).

    Real example from a Defender custom detection:
        let MonitoredFolder = @"\\AppData\\Local\\Microsoft\\OneDrive\\";
    """
    query = (
        "let MonitoredFolder = @\"\\AppData\\Local\\Microsoft\\OneDrive\\\";\n"
        "DeviceImageLoadEvents | where FolderPath contains MonitoredFolder"
    )
    findings = lint_kql(query, kind="defender_custom_detection")
    assert "KQL002" not in _ids(findings), findings
    assert "KQL001" not in _ids(findings), findings


def test_verbatim_string_with_braces_does_not_unbalance_brackets() -> None:
    """A Kusto verbatim string containing literal ``{`` / ``}`` must
    not contribute to the bracket-balance count."""
    query = 'let pat = @"{not a real brace pair";\nT | take 1'
    findings = lint_kql(query, kind="sentinel_analytic")
    assert "KQL001" not in _ids(findings), findings


def test_verbatim_string_doubled_quote_escape() -> None:
    """``""`` inside ``@"..."`` is the Kusto verbatim escape for a
    literal quote — the second quote does NOT close the string."""
    query = 'let q = @"He said ""hi""";\nT | take 1'
    findings = lint_kql(query, kind="sentinel_analytic")
    assert "KQL002" not in _ids(findings), findings


# KQL001 — balanced brackets ------------------------------------------------

def test_kql001_unbalanced_parens_flagged() -> None:
    bad = "T | where (x > 1\n"
    assert "KQL001" in _ids(lint_kql(bad))


def test_kql001_balanced_parens_clean() -> None:
    good = "T | where (x > 1) and [a] == {b}\n| take 1"
    assert "KQL001" not in _ids(lint_kql(good))


# KQL002 — unterminated string --------------------------------------------

def test_kql002_unbalanced_double_quotes_flagged_as_unterminated() -> None:
    bad = 'T | where x == "a" and y == "b'
    assert "KQL002" in _ids(lint_kql(bad))


def test_kql002_balanced_double_quotes_clean() -> None:
    good = 'T | where x == "a" and y == "b"\n| take 1'
    assert "KQL002" not in _ids(lint_kql(good))


def test_kql002_unterminated_string_flagged() -> None:
    bad = 'T | where x == "abc'
    assert "KQL002" in _ids(lint_kql(bad))


def test_kql002_terminated_string_clean() -> None:
    good = 'T | where x == "abc"\n| take 1'
    assert "KQL002" not in _ids(lint_kql(good))


# KQL003 — empty query -----------------------------------------------------

def test_kql003_empty_query_flagged() -> None:
    assert "KQL003" in _ids(lint_kql("   \n // a comment\n  "))


def test_kql003_non_empty_clean() -> None:
    assert "KQL003" not in _ids(lint_kql("T | take 1"))


# KQL004 — `project *` -----------------------------------------------------

def test_kql004_project_star_flagged() -> None:
    assert "KQL004" in _ids(lint_kql("T\n| project *\n| take 1"))


def test_kql004_explicit_project_clean() -> None:
    assert "KQL004" not in _ids(lint_kql("T | project a, b"))


# KQL005 — bare `| take` ---------------------------------------------------

def test_kql005_bare_take_flagged() -> None:
    assert "KQL005" in _ids(lint_kql("T | take"))


def test_kql005_take_with_number_clean() -> None:
    assert "KQL005" not in _ids(lint_kql("T | take 100"))


# KQL006 — bag_unpack ------------------------------------------------------

def test_kql006_bag_unpack_flagged() -> None:
    assert "KQL006" in _ids(lint_kql("T | evaluate bag_unpack(props)"))


def test_kql006_no_bag_unpack_clean() -> None:
    assert "KQL006" not in _ids(lint_kql("T | extend a = props.a"))


# KQL007 — union * ---------------------------------------------------------

def test_kql007_union_star_flagged() -> None:
    assert "KQL007" in _ids(lint_kql("union * | where x == 1"))


def test_kql007_union_kind_star_flagged() -> None:
    assert "KQL007" in _ids(lint_kql("union kind=inner * | take 1"))


def test_kql007_explicit_union_clean() -> None:
    assert "KQL007" not in _ids(lint_kql("union T1, T2 | take 1"))


# CLI integration ----------------------------------------------------------

GOOD_V2_HUNTING = """\
id: lint-good-hunting
version: 0.1.0
asset: sentinel_hunting
status: production
metadata:
  owner: secops@example.com
  runbookUrl: https://runbooks.example.com/good
  severity: low
  tactics: [Discovery]
  techniques: [T1059]
  expectedAlertsPerDay: 1
  fpHandling: Triage manually.
payload:
  displayName: Good Hunting
  query: |
    SecurityEvent
    | where TimeGenerated > ago(1h)
    | take 50
"""

BAD_V2_ANALYTIC = """\
id: lint-bad-analytic
version: 0.1.0
asset: sentinel_analytic
status: production
metadata:
  owner: secops@example.com
  runbookUrl: https://runbooks.example.com/bad
  severity: low
  tactics: [Discovery]
  techniques: [T1059]
  expectedAlertsPerDay: 1
  fpHandling: Triage manually.
payload:
  displayName: Bad Analytic
  severity: Low
  query: |
    SecurityEvent
    | where TimeGenerated > ago(1h)
    | where (Account == "x"
    | take 10
"""

V2_WATCHLIST = """\
id: lint-watchlist
version: 0.1.0
asset: sentinel_watchlist
status: test
payload:
  displayName: WL
  provider: Custom
  source: Local file
  contentType: text/csv
  itemsSearchKey: AssetName
  rawContent: |
    AssetName,Tier
    a,0
"""


def test_lint_cmd_picks_up_sentinel_analytic_and_hunting_queries(tmp_path: Path) -> None:
    (tmp_path / "sentinel").mkdir()
    (tmp_path / "sentinel_hunting").mkdir()
    (tmp_path / "sentinel" / "bad.yml").write_text(BAD_V2_ANALYTIC)
    (tmp_path / "sentinel_hunting" / "good.yml").write_text(GOOD_V2_HUNTING)

    runner = CliRunner()
    result = runner.invoke(cli, ["lint", "--path", str(tmp_path)])
    assert result.exit_code == 1, result.output
    assert "bad.yml" in result.output
    assert "KQL001" in result.output


def test_lint_cmd_skips_kql_checks_for_assets_without_kql_field(
    tmp_path: Path,
) -> None:
    """Watchlists have no KQL field, so KQL/cost/snippet rules don't
    run on them. Metadata-level rules (e.g. META001 for
    lastValidatedAt freshness) still apply to every envelope kind —
    the assertion is that no KQL-rule findings appear, not that the
    file is fully unscanned."""
    (tmp_path / "sentinel_watchlist").mkdir()
    (tmp_path / "sentinel_watchlist" / "wl.yml").write_text(V2_WATCHLIST)

    runner = CliRunner()
    result = runner.invoke(cli, ["lint", "--path", str(tmp_path)])
    # META001 is a warning, not an error — lint still exits 0.
    assert result.exit_code == 0, result.output
    # No KQL-rule finding appears (those rules don't run on watchlists).
    assert "KQL00" not in result.output
    assert "KQL10" not in result.output
    assert "KQL01" not in result.output
