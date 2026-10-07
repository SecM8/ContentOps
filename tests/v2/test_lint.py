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


# ENVELOPE001 --------------------------------------------------------------


def _lint(path: Path, *args: str):
    return CliRunner().invoke(cli, ["lint", "--path", str(path), *args])


def _findings_by_file(output: str) -> dict[str, list[str]]:
    by_file: dict[str, list[str]] = {}
    current = ""
    for line in output.splitlines():
        if line.startswith("  ") and current:
            by_file[current].append(line.strip())
        elif line.endswith(".yml"):
            current = Path(line).name
            by_file[current] = []
    return by_file


def test_envelope001_reports_files_that_do_not_load(tmp_path: Path) -> None:
    """plan / apply echo "load error" and skip a file that doesn't load;
    lint used to skip it silently, so it passed CI and never deployed."""
    d = tmp_path / "detections"
    d.mkdir()
    (d / "yaml.yml").write_text("id: x\nasset: [sentinel_analytic\n")
    (d / "empty.yml").write_text("")
    (d / "missing.yml").write_text(GOOD_V2_HUNTING.replace("status: production\n", ""))
    (d / "bad-id.yml").write_text(GOOD_V2_HUNTING.replace("lint-good-hunting", "Not_Valid"))
    (d / "bad-meta.yml").write_text(
        GOOD_V2_HUNTING.replace("severity: low", "severity: catastrophic"),
    )
    (d / "good.yml").write_text(GOOD_V2_HUNTING)

    result = _lint(d)
    assert result.exit_code == 1, result.output
    found = _findings_by_file(result.output)
    for name, expected in {
        "yaml.yml": "Envelope does not load (YAML does not parse: expected ',' or ']'",
        "empty.yml": "Envelope does not load (envelope is empty or not a YAML mapping)",
        "missing.yml": "Envelope does not load (missing required key 'status')",
        "bad-id.yml": "Envelope does not load (id: String should match pattern",
        "bad-meta.yml": "Envelope does not load (metadata.severity: Input should be",
    }.items():
        [finding] = found[name]
        assert finding.startswith("ENVELOPE001 error"), finding
        assert expected in finding, finding
        assert finding.endswith("plan and apply skip this file."), finding
    assert "line 3" in found["yaml.yml"][0]
    assert not any(f.startswith("ENVELOPE001") for f in found.get("good.yml", []))
    assert "6 files scanned" in result.output


def test_envelope001_asset_filter_skips_only_other_kinds(tmp_path: Path) -> None:
    """``lint --asset X`` leaves a broken file of another kind to that
    kind's run, but still reports one whose kind can't be read."""
    d = tmp_path / "detections"
    d.mkdir()
    (d / "hunting.yml").write_text(GOOD_V2_HUNTING.replace("status: production\n", ""))
    (d / "unreadable.yml").write_text("asset: [sentinel_analytic\n")
    (d / "no-kind.yml").write_text("id: x\n")

    analytic = _findings_by_file(_lint(d, "--asset", "sentinel_analytic").output)
    assert set(analytic) == {"unreadable.yml", "no-kind.yml"}
    hunting = _lint(d, "--asset", "sentinel_hunting")
    assert hunting.exit_code == 1
    assert set(_findings_by_file(hunting.output)) == {
        "hunting.yml", "unreadable.yml", "no-kind.yml",
    }


def test_envelope001_with_strict_mode(tmp_path: Path) -> None:
    """--strict re-loads each linted file for the wrapper; a file that
    doesn't load keeps its ENVELOPE001 and nothing crashes."""
    d = tmp_path / "detections"
    d.mkdir()
    (d / "empty.yml").write_text("")
    result = _lint(d, "--strict")
    assert result.exit_code == 1, result.output
    assert "ENVELOPE001" in result.output
