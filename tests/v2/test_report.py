# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for the SOC-grade detection inventory report
(``contentops.report``).

Three layers:

* Pure-function tests for the assembler — git log + audit JSONL +
  envelope join.
* Renderer tests — HTML escape safety, markdown table shape,
  badge schema conformance.
* CLI integration — ``contentops report`` writes the three output
  files.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner

from contentops.cli import cli
from contentops.report import (
    ReportRow,
    ReportSummary,
    assemble_report,
    render_badge,
    render_html,
    render_markdown,
)
from contentops.report.assemble import (
    _audit_deploy_dates,
    _git_last_pr_for_path,
    _git_merge_date,
    _github_origin_repo,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _envelope_yaml(
    rule_id: str = "rule-a",
    status: str = "production",
    severity: str = "medium",
    title: str = "Example",
    last_validated: str | None = "2026-05-01",
    tactics: tuple[str, ...] = ("Execution",),
    techniques: tuple[str, ...] = ("T1059",),
) -> str:
    meta_extra = ""
    if last_validated:
        meta_extra = f'  lastValidatedAt: "{last_validated}"\n'
    return (
        f"id: {rule_id}\n"
        f"version: 1.0.0\n"
        f"asset: sentinel_analytic\n"
        f"status: {status}\n"
        f"metadata:\n"
        f"  owner: secops@example.com\n"
        f"  runbookUrl: https://runbooks.example.com/{rule_id}\n"
        f"  severity: {severity}\n"
        f"  tactics: {list(tactics)}\n"
        f"  techniques: {list(techniques)}\n"
        f"  expectedAlertsPerDay: 1\n"
        f"  fpHandling: triage\n"
        f"{meta_extra}"
        f"payload:\n"
        f"  displayName: {title}\n"
        f"  query: SecurityEvent | take 1\n"
    )


@pytest.fixture
def repo_tree(tmp_path: Path) -> Path:
    """Build a synthetic detections tree + audit dir under tmp_path."""
    detections = tmp_path / "detections" / "sentinel_analytic"
    detections.mkdir(parents=True)
    (detections / "rule-a.yml").write_text(
        _envelope_yaml(rule_id="rule-a", title="Rule A"),
        encoding="utf-8",
    )
    (detections / "rule-b.yml").write_text(
        _envelope_yaml(rule_id="rule-b", title="Rule B", status="experimental"),
        encoding="utf-8",
    )
    audit = tmp_path / "audit"
    audit.mkdir()
    # rule-a has two deployment records; only the latest success counts.
    audit.joinpath("2026-04-01.jsonl").write_text(
        json.dumps({
            "timestamp": "2026-04-01T10:00:00.000Z",
            "asset": "sentinel_analytic", "id": "rule-a",
            "action": "update", "status": "success",
            "sha": "abc", "actor": "ci", "workflow_run": None,
            "message": "deployed", "metadata_owner": None,
        }) + "\n",
        encoding="utf-8",
    )
    audit.joinpath("2026-05-15.jsonl").write_text(
        json.dumps({
            "timestamp": "2026-05-15T14:00:00.000Z",
            "asset": "sentinel_analytic", "id": "rule-a",
            "action": "update", "status": "success",
            "sha": "def", "actor": "ci", "workflow_run": None,
            "message": "deployed", "metadata_owner": None,
        }) + "\n"
        # Failed record for rule-b is NOT picked up (status != success).
        + json.dumps({
            "timestamp": "2026-05-15T15:00:00.000Z",
            "asset": "sentinel_analytic", "id": "rule-b",
            "action": "update", "status": "failed",
            "sha": "def", "actor": "ci", "workflow_run": None,
            "message": "ARM 500", "metadata_owner": None,
        }) + "\n",
        encoding="utf-8",
    )
    return tmp_path


# ---------------------------------------------------------------------------
# _audit_deploy_dates
# ---------------------------------------------------------------------------


def test_audit_deploy_dates_picks_latest_success(repo_tree: Path) -> None:
    deploy = _audit_deploy_dates(repo_tree / "audit")
    # rule-a has two success records; the later one wins
    assert deploy["rule-a"] == "2026-05-15T14:00:00.000Z"
    # rule-b's only record is status=failed -> not included
    assert "rule-b" not in deploy


def test_audit_deploy_dates_handles_missing_dir(tmp_path: Path) -> None:
    """No audit directory -> empty dict, not an exception."""
    assert _audit_deploy_dates(tmp_path / "nonexistent") == {}


def test_audit_deploy_dates_skips_malformed_lines(tmp_path: Path) -> None:
    """Garbage / empty / non-JSON lines are skipped silently — the
    goal is best-effort latest-deploy view, not chain integrity (that
    is audit-verify's job)."""
    audit = tmp_path / "audit"
    audit.mkdir()
    audit.joinpath("2026-05-01.jsonl").write_text(
        "this is not json\n"
        "\n"
        '{"missing_id_field": true, "status": "success", "timestamp": "2026-05-01T10:00:00Z"}\n'
        '{"id": "rule-ok", "status": "success", "timestamp": "2026-05-01T10:00:00Z"}\n',
        encoding="utf-8",
    )
    deploy = _audit_deploy_dates(audit)
    assert deploy == {"rule-ok": "2026-05-01T10:00:00Z"}


# ---------------------------------------------------------------------------
# _git_merge_date
# ---------------------------------------------------------------------------


def test_git_merge_date_returns_iso_for_tracked_file(tmp_path: Path) -> None:
    """Initialize a tiny git repo, commit a file, verify the merge date
    helper returns the commit's ISO-8601 timestamp."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "file.txt").write_text("hello\n", encoding="utf-8")

    env = {
        **os.environ,
        "GIT_AUTHOR_NAME": "test",
        "GIT_AUTHOR_EMAIL": "test@example.com",
        "GIT_COMMITTER_NAME": "test",
        "GIT_COMMITTER_EMAIL": "test@example.com",
    }
    subprocess.run(["git", "init", "-q"], cwd=repo, env=env, check=True)
    subprocess.run(["git", "add", "file.txt"], cwd=repo, env=env, check=True)
    subprocess.run(
        ["git", "commit", "-q", "-m", "initial"],
        cwd=repo, env=env, check=True,
    )

    iso = _git_merge_date(repo, "file.txt")
    assert iso is not None
    # ISO-8601 like 2026-05-23T12:34:56+02:00 — relaxed shape check
    assert iso.startswith("20") and "T" in iso


def test_git_merge_date_untracked_returns_none(tmp_path: Path) -> None:
    """A file not in the repo yields None (operator just authored it
    locally and hasn't committed)."""
    repo = tmp_path / "repo"
    repo.mkdir()
    env = {**os.environ,
           "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@e.com",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@e.com"}
    subprocess.run(["git", "init", "-q"], cwd=repo, env=env, check=True)
    # No commits yet -> "log" returns nothing -> None
    assert _git_merge_date(repo, "no-such.txt") is None


# ---------------------------------------------------------------------------
# _git_last_pr_for_path
# ---------------------------------------------------------------------------


def _init_repo_with_commit(tmp_path: Path, subject: str) -> Path:
    """Helper: create a git repo and commit a file with the given subject."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "rule-a.yml").write_text("id: rule-a\n", encoding="utf-8")
    env = {**os.environ,
           "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@e.com",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@e.com"}
    subprocess.run(["git", "init", "-q"], cwd=repo, env=env, check=True)
    subprocess.run(["git", "add", "rule-a.yml"], cwd=repo, env=env, check=True)
    subprocess.run(
        ["git", "commit", "-q", "-m", subject],
        cwd=repo, env=env, check=True,
    )
    return repo


def test_git_last_pr_extracts_squash_merge_pr_number(tmp_path: Path) -> None:
    """The standard squash-merge subject `feat(...): summary (#NNN)`
    yields PR# = NNN + a fully-qualified GitHub URL."""
    repo = _init_repo_with_commit(
        tmp_path, "feat(report): add CFO polish (#257)",
    )
    pr_num, pr_url = _git_last_pr_for_path(
        repo, "rule-a.yml", origin_repo="KustoKing/SIEMContent",
    )
    assert pr_num == 257
    assert pr_url == "https://github.com/KustoKing/SIEMContent/pull/257"


def test_git_last_pr_returns_none_when_no_pr_ref(tmp_path: Path) -> None:
    """Subjects without a trailing (#NNN) — local commits, manual
    `git commit -m "fix typo"` — yield None. The column renders as
    blank, distinguishing 'no PR' from 'PR unknown'."""
    repo = _init_repo_with_commit(tmp_path, "fix typo")
    pr_num, pr_url = _git_last_pr_for_path(
        repo, "rule-a.yml", origin_repo="KustoKing/SIEMContent",
    )
    assert pr_num is None
    assert pr_url is None


def test_git_last_pr_without_origin_repo_returns_number_no_url(tmp_path: Path) -> None:
    """When the origin remote isn't a github.com URL (forked / mirrored
    elsewhere), we still surface the PR# but skip the link."""
    repo = _init_repo_with_commit(
        tmp_path, "chore: bump deps (#42)",
    )
    pr_num, pr_url = _git_last_pr_for_path(
        repo, "rule-a.yml", origin_repo=None,
    )
    assert pr_num == 42
    assert pr_url is None


def test_github_origin_repo_parses_https_url(tmp_path: Path) -> None:
    """`git remote get-url origin` typically returns
    https://github.com/owner/repo.git — parser must extract owner/repo."""
    repo = _init_repo_with_commit(tmp_path, "initial")
    env = {**os.environ,
           "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@e.com",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@e.com"}
    subprocess.run(
        ["git", "remote", "add", "origin",
         "https://github.com/KustoKing/SIEMContent.git"],
        cwd=repo, env=env, check=True,
    )
    assert _github_origin_repo(repo) == "KustoKing/SIEMContent"


def test_github_origin_repo_parses_ssh_url(tmp_path: Path) -> None:
    """SSH origin URL: git@github.com:owner/repo.git — same parse."""
    repo = _init_repo_with_commit(tmp_path, "initial")
    env = {**os.environ,
           "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@e.com",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@e.com"}
    subprocess.run(
        ["git", "remote", "add", "origin",
         "git@github.com:KustoKing/SIEMContent.git"],
        cwd=repo, env=env, check=True,
    )
    assert _github_origin_repo(repo) == "KustoKing/SIEMContent"


def test_github_origin_repo_returns_none_for_non_github(tmp_path: Path) -> None:
    repo = _init_repo_with_commit(tmp_path, "initial")
    env = {**os.environ,
           "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@e.com",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@e.com"}
    subprocess.run(
        ["git", "remote", "add", "origin",
         "https://gitlab.example.com/team/repo.git"],
        cwd=repo, env=env, check=True,
    )
    assert _github_origin_repo(repo) is None


# ---------------------------------------------------------------------------
# assemble_report — top-level join
# ---------------------------------------------------------------------------


def test_assemble_report_joins_envelope_and_audit(repo_tree: Path) -> None:
    rows, summary = assemble_report(
        repo_tree / "detections",
        repo_root=repo_tree,
        audit_dir=repo_tree / "audit",
    )
    by_id = {r.rule_id: r for r in rows}

    assert "rule-a" in by_id
    assert by_id["rule-a"].title == "Rule A"
    assert by_id["rule-a"].status == "production"
    assert by_id["rule-a"].severity == "medium"
    assert by_id["rule-a"].tactics == ("Execution",)
    assert by_id["rule-a"].techniques == ("T1059",)
    # Last successful deploy from the audit fixture
    assert by_id["rule-a"].deployment_date == "2026-05-15T14:00:00.000Z"
    assert by_id["rule-a"].last_review_date == "2026-05-01"
    # File isn't in any git repo here -> merge_date is None (graceful)
    assert by_id["rule-a"].merge_date is None

    # rule-b had only a failed record -> no deployment_date
    assert by_id["rule-b"].deployment_date is None
    assert by_id["rule-b"].status == "experimental"


def test_assemble_report_summary_counts_status(repo_tree: Path) -> None:
    rows, summary = assemble_report(
        repo_tree / "detections",
        repo_root=repo_tree,
        audit_dir=repo_tree / "audit",
    )
    assert summary.total == 2
    assert summary.production == 1
    assert summary.experimental == 1
    assert summary.deprecated == 0
    # coverage_pct is whatever the coverage_summary helper returns
    # against the synthetic envelopes; just assert it's an int in range.
    assert 0 <= summary.coverage_pct <= 100


def test_assemble_report_handles_empty_detections_dir(tmp_path: Path) -> None:
    empty = tmp_path / "detections"
    empty.mkdir()
    rows, summary = assemble_report(
        empty, repo_root=tmp_path, audit_dir=tmp_path / "audit",
    )
    assert rows == []
    assert summary.total == 0


# ---------------------------------------------------------------------------
# Renderers
# ---------------------------------------------------------------------------


def _sample_row(**over) -> ReportRow:
    base = dict(
        rule_id="rule-a", asset_kind="sentinel_analytic",
        path="detections/sentinel_analytic/rule-a.yml",
        title="Example rule", status="production", severity="high",
        tactics=("Execution",), techniques=("T1059",),
        merge_date="2026-05-01T10:00:00Z",
        deployment_date="2026-05-15T14:00:00.000Z",
        last_review_date="2026-05-01",
    )
    base.update(over)
    return ReportRow(**base)


def _sample_summary(**over) -> ReportSummary:
    base = dict(
        total=1, production=1, experimental=0, deprecated=0,
        coverage_pct=50, coverage_covered=37, coverage_total=75,
        generated_at="2026-05-23T16:00:00Z",
    )
    base.update(over)
    return ReportSummary(**base)


def test_render_html_includes_rule_data(repo_tree: Path) -> None:
    rows = [_sample_row(title="Failed Logins", rule_id="failed-logins")]
    html = render_html(rows, _sample_summary())
    assert "<title>ContentOps — Detection Inventory</title>" in html
    assert "Failed Logins" in html
    assert "failed-logins" in html
    # Status pill class is applied
    assert "status-production" in html
    # Sortable JS is embedded
    assert "addEventListener('click'" in html
    # No external resource references
    assert "https://" not in html.split("<body>")[0] or "https://" not in html.split("<body>")[0].split("ContentOps")[0]


def test_render_html_escapes_special_chars() -> None:
    """displayName values historically contain &, <, >, '. The renderer
    must escape them or the HTML breaks."""
    rows = [_sample_row(title="<script>alert('x')</script> & co.")]
    html = render_html(rows, _sample_summary())
    assert "<script>alert" not in html  # would be literal if not escaped
    assert "&lt;script&gt;" in html
    assert "&amp; co." in html


def test_render_markdown_includes_summary_and_table() -> None:
    rows = [_sample_row(title="Failed Logins")]
    md = render_markdown(rows, _sample_summary())
    assert "# Detection inventory" in md
    assert "| Total detections | **1** |" in md
    assert "| Failed Logins" in md
    assert "| 2026-05-15 |" in md  # truncated to YYYY-MM-DD


def test_render_markdown_escapes_pipe_chars() -> None:
    """Pipes in displayName must be escaped or the markdown table
    column count breaks for that row."""
    rows = [_sample_row(title="Has | pipe")]
    md = render_markdown(rows, _sample_summary())
    assert "Has \\| pipe" in md


def test_render_html_emits_exec_summary_block() -> None:
    """The CFO-facing one-paragraph TL;DR sits at the top of the
    report. Required content: total active detections, MITRE
    coverage %, owner-accountability %, review-freshness %."""
    rows = [_sample_row(owner="blue@example.com", last_review_date="2026-05-20")]
    html = render_html(rows, _sample_summary(production=1, total=1))
    assert 'class="exec-summary"' in html
    assert "Executive summary" in html
    assert "1</strong> active detections" in html
    assert "MITRE ATT&amp;CK" in html


def test_render_html_emits_pr_link_when_url_set() -> None:
    """Rows with last_pr_url get a clickable `#NNN` link; rows
    without get a plain `#NNN`; rows without either get `—`."""
    rows = [
        _sample_row(last_pr_number=257, last_pr_url="https://github.com/KK/Repo/pull/257"),
        _sample_row(rule_id="rule-b", title="B", last_pr_number=42, last_pr_url=None),
        _sample_row(rule_id="rule-c", title="C"),  # no PR
    ]
    html = render_html(rows, _sample_summary())
    assert 'href="https://github.com/KK/Repo/pull/257"' in html
    assert ">#257</a>" in html
    assert ">#42</span>" in html  # PR# without link


def test_render_html_renders_runbook_inline_when_set() -> None:
    """When metadata.runbookUrl is set, the title cell carries an
    inline `runbook` link. Without it, just the title + rule_id."""
    rows = [_sample_row(runbook_url="https://wiki/runbook")]
    html = render_html(rows, _sample_summary())
    assert 'href="https://wiki/runbook"' in html
    assert ">runbook</a>" in html


def test_render_html_owner_shows_local_part_with_full_on_hover() -> None:
    """blue@acme.com -> 'blue' in the cell, 'blue@acme.com' as title."""
    rows = [_sample_row(owner="blue@acme.com")]
    html = render_html(rows, _sample_summary())
    assert '>blue</span>' in html
    assert 'title="blue@acme.com"' in html


def test_render_html_includes_severity_chart() -> None:
    """The inline SVG severity chart sits below the summary cards.
    Four bars (high / medium / low / informational); counts driven
    by the row data."""
    rows = [
        _sample_row(severity="high"),
        _sample_row(rule_id="b", severity="high"),
        _sample_row(rule_id="c", severity="medium"),
        _sample_row(rule_id="d", severity="low"),
    ]
    html = render_html(rows, _sample_summary(total=4))
    # SVG present
    assert 'class="sev-chart"' in html
    # All four severity labels render
    assert ">high<" in html
    assert ">medium<" in html
    assert ">low<" in html
    assert ">informational<" in html


def test_render_html_severity_chart_suppressed_when_empty() -> None:
    """No rows -> no chart block. The CSS class lives in the stylesheet
    block (always emitted), but the <svg> element + chart container
    must not appear."""
    html = render_html([], _sample_summary(total=0))
    # The CSS rule for .sev-chart stays in the <style> block.
    # The chart-block container should not appear.
    assert '<div class="chart-block">' not in html
    assert "<svg" not in html


def test_render_html_delta_phrase_when_delta_passed() -> None:
    """When a ReportDelta is passed to render_html, the exec summary
    gains a 'Since <date>' tail phrase with growth signals."""
    from contentops.report.snapshot import ReportDelta
    delta = ReportDelta(
        previous_date="2026-05-16",
        total_delta=3, production_delta=2,
        experimental_delta=1, deprecated_delta=0,
        coverage_techniques_delta=5,
        coverage_sub_techniques_delta=2,
    )
    rows = [_sample_row()]
    html = render_html(rows, _sample_summary(), delta=delta)
    assert "Since 2026-05-16" in html
    assert "+3 rules" in html
    assert "+5 techniques covered" in html
    assert "+2 sub-techniques covered" in html


def test_render_markdown_includes_owner_and_pr_columns() -> None:
    rows = [_sample_row(
        owner="blue@example.com",
        last_pr_number=257,
        last_pr_url="https://github.com/KK/Repo/pull/257",
    )]
    md = render_markdown(rows, _sample_summary())
    assert "| Owner |" in md       # header
    assert "| Last PR |" in md
    assert "blue |" in md         # cell content
    assert "[#257](https://github.com/KK/Repo/pull/257)" in md


def test_render_badge_conforms_to_shields_endpoint_schema() -> None:
    payload = json.loads(render_badge(_sample_summary(
        total=148, coverage_pct=39,
    )))
    assert payload["schemaVersion"] == 1
    assert payload["label"] == "detections"
    assert "148" in payload["message"]
    assert "39% MITRE" in payload["message"]
    assert payload["color"] in {
        "red", "orange", "yellow", "yellowgreen", "brightgreen",
    }


# ---------------------------------------------------------------------------
# Alert summary cards (render_html with live enrichment data)
# ---------------------------------------------------------------------------


def test_render_html_alert_summary_cards_when_enriched() -> None:
    rows = [
        _sample_row(alerts_30d=50, true_positives_30d=35, false_positives_30d=15),
        _sample_row(rule_id="rule-b", title="Rule B", alerts_30d=20, true_positives_30d=18, false_positives_30d=2),
    ]
    html = render_html(rows, _sample_summary())
    assert "Alerts (30d)" in html
    assert "70" in html
    assert "TP rate" in html
    assert "Detections firing" in html
    assert "2" in html


def test_render_html_tp_rate_color_thresholds() -> None:
    high_tp = [_sample_row(alerts_30d=100, true_positives_30d=80, false_positives_30d=20)]
    html = render_html(high_tp, _sample_summary())
    assert "green" in html

    mid_tp = [_sample_row(alerts_30d=100, true_positives_30d=50, false_positives_30d=50)]
    html = render_html(mid_tp, _sample_summary())
    assert "amber" in html

    low_tp = [_sample_row(alerts_30d=100, true_positives_30d=10, false_positives_30d=90)]
    html = render_html(low_tp, _sample_summary())
    assert "red" in html


def test_render_html_alert_cards_absent_without_enrichment() -> None:
    rows = [_sample_row()]
    html = render_html(rows, _sample_summary())
    assert "Alerts (30d)" not in html
    assert "TP rate" not in html
    assert "Detections firing" not in html


# ---------------------------------------------------------------------------
# CLI integration
# ---------------------------------------------------------------------------


def test_cli_report_writes_all_three_outputs(tmp_path: Path) -> None:
    """`contentops report` writes html / md / badge.json into the
    configured output paths. Synthetic detections tree so no live
    repo data leaks into the test."""
    detections = tmp_path / "detections" / "sentinel_analytic"
    detections.mkdir(parents=True)
    (detections / "rule-x.yml").write_text(
        _envelope_yaml(rule_id="rule-x", title="X"),
        encoding="utf-8",
    )

    out_html = tmp_path / "out" / "report.html"
    out_md = tmp_path / "out" / "report.md"
    out_badge = tmp_path / "out" / "badge.json"
    # Redirect --out-json too: its default is the repo's reports/latest.json,
    # so omitting it makes this test write into the working tree (and a
    # dated reports/<date>.json snapshot). Keep every output under tmp_path
    # so the test stays hermetic.
    out_json = tmp_path / "out" / "report.json"
    audit = tmp_path / "audit"
    audit.mkdir()

    runner = CliRunner()
    result = runner.invoke(cli, [
        "report",
        "--path", str(tmp_path / "detections"),
        "--audit-dir", str(audit),
        "--out-html", str(out_html),
        "--out-md", str(out_md),
        "--out-badge", str(out_badge),
        "--out-json", str(out_json),
    ])
    assert result.exit_code == 0, result.output

    assert out_html.exists()
    assert out_md.exists()
    assert out_badge.exists()
    assert out_json.exists()
    payload = json.loads(out_badge.read_text(encoding="utf-8"))
    assert payload["schemaVersion"] == 1
    assert "1" in payload["message"]  # 1 detection
