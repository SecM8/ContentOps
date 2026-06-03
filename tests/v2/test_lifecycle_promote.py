# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for `contentops lifecycle promote` (F8)."""

from __future__ import annotations

from datetime import date, timedelta
from pathlib import Path

import pytest
from click.testing import CliRunner

from contentops.cli import cli
from contentops.lifecycle import (
    DEFAULT_LIFECYCLE_CONFIG_PATH,
    LifecycleConfig,
    LifecycleError,
    PromotionReport,
    check_gates,
    gate_currently_experimental,
    gate_fp_rate_threshold,
    gate_live_test_pass,
    gate_recent_validation,
    load_lifecycle_config,
    promote,
)
from contentops.workspace_kql import QueryResult, WorkspaceKqlError


# ---------------------------------------------------------------------------
# Fixtures — synthetic envelopes
# ---------------------------------------------------------------------------


def _envelope(
    rule_id: str = "rule-x",
    status: str = "experimental",
    last_validated: str | None = None,
) -> str:
    metadata_block = ""
    if last_validated is not None:
        metadata_block = (
            f"  lastValidatedAt: {last_validated}\n"
        )
    return f"""\
id: {rule_id}
version: 1.0.0
asset: sentinel_analytic
status: {status}
metadata:
  owner: secops@example.com
  runbookUrl: https://runbooks.example.com/{rule_id}
  severity: medium
  tactics: [Execution]
  techniques: [T1059]
  expectedAlertsPerDay: 1
  fpHandling: triage
{metadata_block}payload:
  displayName: X
  query: SecurityEvent | take 1
"""


def _write(tmp_path: Path, body: str) -> Path:
    detections = tmp_path / "detections" / "sentinel_analytic"
    detections.mkdir(parents=True)
    target = detections / "rule-x.yml"
    target.write_text(body, encoding="utf-8")
    return tmp_path / "detections"


# ---------------------------------------------------------------------------
# gate_currently_experimental
# ---------------------------------------------------------------------------


def test_gate_status_passes_for_experimental() -> None:
    g = gate_currently_experimental({"status": "experimental"})
    assert g.passed is True


def test_gate_status_fails_for_production() -> None:
    g = gate_currently_experimental({"status": "production"})
    assert g.passed is False
    assert "production" in g.detail


def test_gate_status_fails_for_missing() -> None:
    assert gate_currently_experimental({}).passed is False


# ---------------------------------------------------------------------------
# gate_recent_validation
# ---------------------------------------------------------------------------


def test_gate_recent_validation_passes_within_window() -> None:
    today = date(2026, 5, 7)
    envelope = {
        "metadata": {"lastValidatedAt": "2026-04-20"},  # 17 days ago
    }
    g = gate_recent_validation(envelope, max_age_days=30, today=today)
    assert g.passed is True


def test_gate_recent_validation_fails_when_stale() -> None:
    today = date(2026, 5, 7)
    envelope = {
        "metadata": {"lastValidatedAt": "2024-01-01"},  # ~500 days ago
    }
    g = gate_recent_validation(envelope, max_age_days=30, today=today)
    assert g.passed is False


def test_gate_recent_validation_fails_when_missing() -> None:
    g = gate_recent_validation({"metadata": {}}, max_age_days=30)
    assert g.passed is False
    assert "missing" in g.detail.lower() or "unparseable" in g.detail.lower()


def test_gate_recent_validation_fails_on_garbage() -> None:
    g = gate_recent_validation(
        {"metadata": {"lastValidatedAt": "yesterday"}},
        max_age_days=30,
    )
    assert g.passed is False


# ---------------------------------------------------------------------------
# check_gates — composite
# ---------------------------------------------------------------------------


def test_check_gates_returns_four_results() -> None:
    results = check_gates({"status": "experimental"})
    names = [g.name for g in results]
    assert names == [
        "status_is_experimental",
        "recent_validation",
        "live_test_pass",
        "fp_rate_threshold",
    ]


def test_check_gates_both_workspace_gates_deferred_without_workspace() -> None:
    """Without a workspace, BOTH workspace-backed gates stay deferred —
    the caller opted out of the live queries (offline / dry-run path)."""
    results = check_gates({"status": "experimental"})
    by_name = {g.name: g for g in results}
    assert by_name["live_test_pass"].deferred is True
    assert by_name["fp_rate_threshold"].deferred is True


def test_check_gates_fp_rate_evaluates_when_workspace_id_provided() -> None:
    """With workspace_id + token + mocked query_fn, fp_rate is no longer
    deferred — it produces a real pass/fail outcome."""
    def fake_query(*args, **kwargs):
        return QueryResult(
            rows=[
                {"rule_name": "X", "alerts_30d": 5, "incidents_30d": 4, "closed_fp_30d": 1},
            ],
            column_names=["rule_name", "alerts_30d", "incidents_30d", "closed_fp_30d"],
        )

    envelope = {"status": "experimental", "payload": {"displayName": "X"}}
    results = check_gates(
        envelope,
        workspace_id="ws-id", token="t",
        fp_rate_threshold=0.5,
        fp_rate_query_fn=fake_query,
    )
    by_name = {g.name: g for g in results}
    fp_gate = by_name["fp_rate_threshold"]
    assert fp_gate.deferred is False
    assert fp_gate.passed is True


# ---------------------------------------------------------------------------
# gate_live_test_pass — the F2 live path (executes the rule's KQL)
# ---------------------------------------------------------------------------


def _kql_envelope(query: str = "SecurityEvent | take 1") -> dict:
    return {
        "status": "experimental",
        "asset": "sentinel_analytic",
        "payload": {"displayName": "X", "query": query},
    }


def test_gate_live_test_pass_deferred_without_workspace() -> None:
    g = gate_live_test_pass(_kql_envelope(), workspace_id=None, token=None)
    assert g.deferred is True
    assert g.passed is True


def test_gate_live_test_pass_passes_when_query_executes() -> None:
    """A successful server-side execution proves the rule runs against the
    live schema — the gate passes and reports the row count."""
    def fake_query(*a, **kw):
        return QueryResult(rows=[{"Count": 42}], column_names=["Count"])

    g = gate_live_test_pass(
        _kql_envelope(), workspace_id="ws", token="t", query_fn=fake_query,
    )
    assert g.deferred is False
    assert g.passed is True
    assert "42" in g.detail


def test_gate_live_test_pass_fail_closed_on_query_error() -> None:
    """A SemanticError / 403 / outage means the rule can't run — fail-closed."""
    def raise_kql(*a, **kw):
        raise WorkspaceKqlError("SemanticError: 'FooColumn' could not be resolved")

    g = gate_live_test_pass(
        _kql_envelope(), workspace_id="ws", token="t", query_fn=raise_kql,
    )
    assert g.passed is False
    assert "failed" in g.detail.lower()


def test_gate_live_test_pass_passes_when_no_kql_body() -> None:
    """A kind with no KQL (watchlist) has nothing to live-test — pass, no query."""
    called = {"n": 0}

    def should_not_run(*a, **kw):
        called["n"] += 1
        raise AssertionError("query must not run for a no-KQL asset")

    envelope = {"status": "experimental", "asset": "sentinel_watchlist", "payload": {}}
    g = gate_live_test_pass(
        envelope, workspace_id="ws", token="t", query_fn=should_not_run,
    )
    assert g.passed is True
    assert called["n"] == 0


def test_check_gates_wires_live_test_query_fn() -> None:
    """check_gates threads live_test_query_fn into the gate so it runs live
    when a workspace is supplied."""
    def fake_query(*a, **kw):
        return QueryResult(rows=[{"Count": 3}], column_names=["Count"])

    results = check_gates(
        _kql_envelope(),
        workspace_id="ws", token="t",
        fp_rate_query_fn=fake_query,
        live_test_query_fn=fake_query,
    )
    by_name = {g.name: g for g in results}
    assert by_name["live_test_pass"].deferred is False
    assert by_name["live_test_pass"].passed is True


# ---------------------------------------------------------------------------
# gate_fp_rate_threshold — direct unit tests
# ---------------------------------------------------------------------------


def _fp_envelope(display_name: str = "X") -> dict:
    return {"status": "experimental", "payload": {"displayName": display_name}}


def test_gate_fp_rate_under_threshold_passes() -> None:
    def fake_query(*a, **kw):
        return QueryResult(
            rows=[{"rule_name": "X", "alerts_30d": 100, "incidents_30d": 10, "closed_fp_30d": 2}],
            column_names=["rule_name", "alerts_30d", "incidents_30d", "closed_fp_30d"],
        )

    g = gate_fp_rate_threshold(
        _fp_envelope(), workspace_id="w", token="t",
        threshold=0.5, query_fn=fake_query,
    )
    assert g.passed is True
    assert "fp_rate=0.200" in g.detail


def test_gate_fp_rate_over_threshold_fails() -> None:
    def fake_query(*a, **kw):
        return QueryResult(
            rows=[{"rule_name": "X", "alerts_30d": 100, "incidents_30d": 10, "closed_fp_30d": 8}],
            column_names=["rule_name", "alerts_30d", "incidents_30d", "closed_fp_30d"],
        )

    g = gate_fp_rate_threshold(
        _fp_envelope(), workspace_id="w", token="t",
        threshold=0.5, query_fn=fake_query,
    )
    assert g.passed is False
    assert "fp_rate=0.800" in g.detail


def test_gate_fp_rate_no_incidents_passes() -> None:
    """incidents_30d == 0 -> FP-rate undefined; pass with skip detail."""
    def fake_query(*a, **kw):
        return QueryResult(
            rows=[{"rule_name": "X", "alerts_30d": 100, "incidents_30d": 0, "closed_fp_30d": 0}],
            column_names=["rule_name", "alerts_30d", "incidents_30d", "closed_fp_30d"],
        )

    g = gate_fp_rate_threshold(
        _fp_envelope(), workspace_id="w", token="t",
        threshold=0.5, query_fn=fake_query,
    )
    assert g.passed is True
    assert "no incidents" in g.detail


def test_gate_fp_rate_rule_not_in_telemetry_passes() -> None:
    """displayName not in response -> rule hasn't fired; pass with detail."""
    def fake_query(*a, **kw):
        return QueryResult(rows=[], column_names=["rule_name", "incidents_30d", "closed_fp_30d"])

    g = gate_fp_rate_threshold(
        _fp_envelope("Brand New Rule"),
        workspace_id="w", token="t",
        threshold=0.5, query_fn=fake_query,
    )
    assert g.passed is True
    assert "not in workspace telemetry window" in g.detail


def test_gate_fp_rate_workspace_failure_is_fail_closed() -> None:
    """Auth / network errors -> passed=False (operator must --force)."""
    def raise_kql(*a, **kw):
        raise WorkspaceKqlError("LA Query returned 500: server error")

    g = gate_fp_rate_threshold(
        _fp_envelope(), workspace_id="w", token="t",
        threshold=0.5, query_fn=raise_kql,
    )
    assert g.passed is False
    assert "workspace query failed" in g.detail


def test_gate_fp_rate_without_workspace_is_deferred() -> None:
    g = gate_fp_rate_threshold(
        _fp_envelope(), workspace_id=None, token=None, threshold=0.5,
    )
    assert g.deferred is True
    assert g.passed is True


# ---------------------------------------------------------------------------
# load_lifecycle_config
# ---------------------------------------------------------------------------


def test_load_lifecycle_config_returns_defaults_when_missing(tmp_path: Path) -> None:
    cfg, info = load_lifecycle_config(tmp_path / "missing.yml")
    assert cfg.fp_rate_threshold == 0.5
    assert info is not None
    assert "not found" in info


def test_load_lifecycle_config_reads_threshold(tmp_path: Path) -> None:
    cfg_path = tmp_path / "lifecycle.yml"
    cfg_path.write_text("fp_rate_threshold: 0.25\n", encoding="utf-8")
    cfg, info = load_lifecycle_config(cfg_path)
    assert cfg.fp_rate_threshold == 0.25
    assert info is None


def test_load_lifecycle_config_garbage_falls_back_to_defaults(tmp_path: Path) -> None:
    cfg_path = tmp_path / "lifecycle.yml"
    cfg_path.write_text("fp_rate_threshold: not-a-number\n", encoding="utf-8")
    cfg, info = load_lifecycle_config(cfg_path)
    assert cfg.fp_rate_threshold == 0.5
    assert info is not None


# ---------------------------------------------------------------------------
# promote — orchestration
# ---------------------------------------------------------------------------


def test_promote_writes_when_all_gates_pass(tmp_path: Path) -> None:
    today = date(2026, 5, 7)
    detections = _write(tmp_path, _envelope(
        status="experimental", last_validated="2026-04-20",
    ))
    report = promote(
        "rule-x", detections_root=detections, today=today,
    )
    assert report.all_passed() is True
    assert report.promoted is True
    target = detections / "sentinel_analytic" / "rule-x.yml"
    text = target.read_text(encoding="utf-8")
    assert "status: production" in text
    # Phase 2.2a — every successful promotion stamps the envelope with
    # lifecycle.promotedAt + promotedBy. scripts/detect_production_promotions.py
    # later asserts this stamp is present and within the 30-day window.
    assert "lifecycle:" in text
    assert "promotedAt: 2026-05-07" in text
    assert "promotedBy:" in text


def test_promote_re_promotion_updates_existing_stamp(
    tmp_path: Path, monkeypatch,
) -> None:
    """Idempotency: re-running promote on an already-promoted rule
    updates the existing lifecycle.promotedAt rather than appending a
    duplicate block. (Edge case for the force path or a re-run.)"""
    monkeypatch.setenv("GITHUB_ACTOR", "test-actor-2")
    today1 = date(2026, 1, 10)
    detections = _write(tmp_path, _envelope(
        status="experimental", last_validated="2026-01-05",
    ))
    promote("rule-x", detections_root=detections, today=today1)
    target = detections / "sentinel_analytic" / "rule-x.yml"
    assert "promotedAt: 2026-01-10" in target.read_text(encoding="utf-8")

    # Manually flip back to experimental to simulate a re-promote round.
    text = target.read_text(encoding="utf-8")
    target.write_text(text.replace("status: production", "status: experimental"))

    today2 = date(2026, 5, 10)
    monkeypatch.setenv("GITHUB_ACTOR", "test-actor-2")
    # Bump lastValidatedAt so the freshness gate still passes.
    new_text = target.read_text(encoding="utf-8")
    new_text = new_text.replace("lastValidatedAt: 2026-01-05", "lastValidatedAt: 2026-05-05")
    target.write_text(new_text)
    promote("rule-x", detections_root=detections, today=today2)

    final = target.read_text(encoding="utf-8")
    # Only ONE lifecycle: block — the existing one was updated, not
    # duplicated.
    assert final.count("lifecycle:") == 1
    assert "promotedAt: 2026-05-10" in final
    assert "promotedAt: 2026-01-10" not in final


def test_promote_resolves_actor_from_github_actor_env(
    tmp_path: Path, monkeypatch,
) -> None:
    """The lifecycle.promotedBy stamp resolves from GITHUB_ACTOR when
    set (CI path); falls back to git user.email locally."""
    monkeypatch.setenv("GITHUB_ACTOR", "github-test-actor")
    today = date(2026, 5, 7)
    detections = _write(tmp_path, _envelope(
        status="experimental", last_validated="2026-04-20",
    ))
    promote("rule-x", detections_root=detections, today=today)
    target = detections / "sentinel_analytic" / "rule-x.yml"
    assert "promotedBy: github-test-actor" in target.read_text(encoding="utf-8")


def test_promote_refuses_when_gate_fails(tmp_path: Path) -> None:
    today = date(2026, 5, 7)
    detections = _write(tmp_path, _envelope(
        status="experimental",
        last_validated="2024-01-01",  # stale
    ))
    report = promote(
        "rule-x", detections_root=detections, today=today,
    )
    assert report.all_passed() is False
    assert report.promoted is False
    target = detections / "sentinel_analytic" / "rule-x.yml"
    assert "status: experimental" in target.read_text(encoding="utf-8")


def test_promote_force_overrides_gate_failure(tmp_path: Path) -> None:
    today = date(2026, 5, 7)
    detections = _write(tmp_path, _envelope(
        status="experimental",
        last_validated="2024-01-01",  # stale
    ))
    report = promote(
        "rule-x", detections_root=detections, today=today, force=True,
    )
    assert report.all_passed() is False  # gates still fail
    assert report.promoted is True       # but force wrote anyway


def test_promote_unknown_rule_raises(tmp_path: Path) -> None:
    detections = tmp_path / "detections"
    detections.mkdir()
    with pytest.raises(LifecycleError):
        promote("ghost", detections_root=detections)


def test_promote_already_production_fails_status_gate(tmp_path: Path) -> None:
    detections = _write(tmp_path, _envelope(
        status="production", last_validated="2026-05-01",
    ))
    report = promote(
        "rule-x", detections_root=detections, today=date(2026, 5, 7),
    )
    # Status gate fails; promotion is a no-op.
    assert report.promoted is False
    assert report.gates[0].passed is False


# ---------------------------------------------------------------------------
# CLI integration
# ---------------------------------------------------------------------------


def test_cli_lifecycle_promote_happy_path(tmp_path: Path) -> None:
    today = date.today()
    last_validated = today.isoformat()
    detections = _write(tmp_path, _envelope(
        status="experimental", last_validated=last_validated,
    ))
    runner = CliRunner()
    result = runner.invoke(cli, [
        "lifecycle", "promote", "rule-x",
        "--path", str(detections),
    ])
    assert result.exit_code == 0, result.output
    assert "PROMOTED" in result.output
    assert "[pass] status_is_experimental" in result.output
    assert "[skip] live_test_pass" in result.output


def test_cli_lifecycle_promote_refuses_stale(tmp_path: Path) -> None:
    detections = _write(tmp_path, _envelope(
        status="experimental", last_validated="2024-01-01",
    ))
    runner = CliRunner()
    result = runner.invoke(cli, [
        "lifecycle", "promote", "rule-x",
        "--path", str(detections),
    ])
    assert result.exit_code == 1
    assert "REFUSED" in result.output
    assert "[FAIL] recent_validation" in result.output


def test_cli_lifecycle_promote_dry_run_does_not_write(tmp_path: Path) -> None:
    today = date.today()
    detections = _write(tmp_path, _envelope(
        status="experimental", last_validated=today.isoformat(),
    ))
    runner = CliRunner()
    result = runner.invoke(cli, [
        "lifecycle", "promote", "rule-x",
        "--path", str(detections), "--dry-run",
    ])
    assert result.exit_code == 0
    assert "[dry-run]" in result.output
    target = detections / "sentinel_analytic" / "rule-x.yml"
    assert "status: experimental" in target.read_text(encoding="utf-8")


def test_cli_lifecycle_promote_unknown_rule_exits_1(tmp_path: Path) -> None:
    detections = tmp_path / "detections"
    detections.mkdir()
    runner = CliRunner()
    result = runner.invoke(cli, [
        "lifecycle", "promote", "ghost",
        "--path", str(detections),
    ])
    assert result.exit_code == 1
    assert "no rule" in result.output


def test_cli_lifecycle_promote_no_workspace_query_keeps_fp_gate_deferred(
    tmp_path: Path,
) -> None:
    """--no-workspace-query opts out even when --workspace-id is set."""
    today = date.today()
    detections = _write(tmp_path, _envelope(
        status="experimental", last_validated=today.isoformat(),
    ))
    runner = CliRunner()
    result = runner.invoke(cli, [
        "lifecycle", "promote", "rule-x",
        "--path", str(detections),
        "--workspace-id", "ws-abc",
        "--no-workspace-query",
    ])
    assert result.exit_code == 0, result.output
    assert "[skip] fp_rate_threshold" in result.output


def test_cli_lifecycle_promote_with_workspace_runs_fp_gate(
    tmp_path: Path, monkeypatch,
) -> None:
    """With --workspace-id and a mocked query, the fp gate runs live."""
    import contentops.utils.auth as auth_mod
    import contentops.workspace_kql as ws

    class _Tok:
        token = "stub"

    class _Cred:
        def get_token(self, *a, **kw):
            return _Tok()

    monkeypatch.setattr(auth_mod, "get_credential", lambda: _Cred())

    def fake_query(*a, **kw):
        return QueryResult(
            rows=[{"rule_name": "X", "alerts_30d": 50, "incidents_30d": 10, "closed_fp_30d": 2}],
            column_names=["rule_name", "alerts_30d", "incidents_30d", "closed_fp_30d"],
        )

    monkeypatch.setattr(ws, "query", fake_query)

    today = date.today()
    detections = _write(tmp_path, _envelope(
        status="experimental", last_validated=today.isoformat(),
    ))
    runner = CliRunner()
    result = runner.invoke(cli, [
        "lifecycle", "promote", "rule-x",
        "--path", str(detections),
        "--workspace-id", "ws-abc",
        "--dry-run",
    ])
    assert result.exit_code == 0, result.output
    assert "[pass] fp_rate_threshold" in result.output
    assert "fp_rate=0.200" in result.output


def test_cli_lifecycle_promote_workspace_failure_blocks_promotion(
    tmp_path: Path, monkeypatch,
) -> None:
    """Fail-closed: workspace error makes fp_rate gate fail, exit 1."""
    import contentops.utils.auth as auth_mod
    import contentops.workspace_kql as ws

    class _Tok:
        token = "stub"

    class _Cred:
        def get_token(self, *a, **kw):
            return _Tok()

    monkeypatch.setattr(auth_mod, "get_credential", lambda: _Cred())

    def raise_kql(*a, **kw):
        raise WorkspaceKqlError("LA Query returned 503")

    monkeypatch.setattr(ws, "query", raise_kql)

    today = date.today()
    detections = _write(tmp_path, _envelope(
        status="experimental", last_validated=today.isoformat(),
    ))
    runner = CliRunner()
    result = runner.invoke(cli, [
        "lifecycle", "promote", "rule-x",
        "--path", str(detections),
        "--workspace-id", "ws-abc",
        "--dry-run",
    ])
    assert result.exit_code == 1
    assert "[FAIL] fp_rate_threshold" in result.output
    assert "REFUSED" in result.output


# ---------------------------------------------------------------------------
# Bulk promotion (--cohort / --rules / --continue-on-failure)
# ---------------------------------------------------------------------------


def _write_many(
    tmp_path: Path,
    rules: list[tuple[str, str, str | None, str | None]],
) -> Path:
    """Write multiple envelopes under detections/sentinel_analytic/.

    `rules` is a list of (rule_id, status, last_validated, cohort)
    tuples. Returns the detections root.
    """
    detections = tmp_path / "detections" / "sentinel_analytic"
    detections.mkdir(parents=True)
    for rule_id, status, last_validated, cohort in rules:
        metadata_lines = (
            "  owner: secops@example.com\n"
            f"  runbookUrl: https://runbooks.example.com/{rule_id}\n"
            "  severity: medium\n"
            "  tactics: [Execution]\n"
            "  techniques: [T1059]\n"
            "  expectedAlertsPerDay: 1\n"
            "  fpHandling: triage\n"
        )
        if last_validated is not None:
            # YAML auto-parses unquoted ISO dates -> date object ->
            # Pydantic RuleMetadata expects str. Quote to keep it a str.
            metadata_lines += f'  lastValidatedAt: "{last_validated}"\n'
        if cohort is not None:
            metadata_lines += f"  cohort: {cohort}\n"
        body = (
            f"id: {rule_id}\n"
            f"version: 1.0.0\n"
            f"asset: sentinel_analytic\n"
            f"status: {status}\n"
            f"metadata:\n"
            f"{metadata_lines}"
            f"payload:\n"
            f"  displayName: {rule_id}\n"
            f"  query: SecurityEvent | take 1\n"
        )
        (detections / f"{rule_id}.yml").write_text(body, encoding="utf-8")
    return tmp_path / "detections"


def test_promote_bulk_via_rules_csv_promotes_each(tmp_path: Path) -> None:
    """`--rules a,b,c` promotes each rule independently; status:
    production written to disk for each on a non-dry-run."""
    today = date.today().isoformat()
    detections = _write_many(tmp_path, [
        ("rule-a", "experimental", today, None),
        ("rule-b", "experimental", today, None),
        ("rule-c", "experimental", today, None),
    ])
    runner = CliRunner()
    result = runner.invoke(cli, [
        "lifecycle", "promote",
        "--rules", "rule-a,rule-b,rule-c",
        "--path", str(detections),
        "--no-workspace-query",
    ])
    assert result.exit_code == 0, result.output
    assert "Summary: 3 promoted" in result.output
    # disk has the status flips
    for rid in ("rule-a", "rule-b", "rule-c"):
        body = (detections / "sentinel_analytic" / f"{rid}.yml").read_text(encoding="utf-8")
        assert "status: production" in body


def test_promote_bulk_via_cohort_selects_matching_envelopes(
    tmp_path: Path,
) -> None:
    """`--cohort foo` walks every envelope and selects those whose
    metadata.cohort equals 'foo'. Rules with no cohort or a different
    cohort are not touched."""
    today = date.today().isoformat()
    detections = _write_many(tmp_path, [
        ("in-cohort-1", "experimental", today, "m365-tier1"),
        ("in-cohort-2", "experimental", today, "m365-tier1"),
        ("other-cohort", "experimental", today, "endpoints"),
        ("no-cohort", "experimental", today, None),
    ])
    runner = CliRunner()
    result = runner.invoke(cli, [
        "lifecycle", "promote",
        "--cohort", "m365-tier1",
        "--path", str(detections),
        "--no-workspace-query",
    ])
    assert result.exit_code == 0, result.output
    assert "matched 2 envelope(s)" in result.output
    assert "Summary: 2 promoted" in result.output
    # only the matched ones flipped
    for rid in ("in-cohort-1", "in-cohort-2"):
        body = (detections / "sentinel_analytic" / f"{rid}.yml").read_text(encoding="utf-8")
        assert "status: production" in body
    for rid in ("other-cohort", "no-cohort"):
        body = (detections / "sentinel_analytic" / f"{rid}.yml").read_text(encoding="utf-8")
        assert "status: experimental" in body


def test_promote_bulk_failed_rules_exit_1_by_default(tmp_path: Path) -> None:
    """One rule that fails its gate (stale lastValidatedAt) blocks the
    bulk exit code — the default is fail-the-batch-if-any-rule-failed.
    The summary line still shows the other rule's success."""
    today = date.today()
    long_ago = (today.replace(year=today.year - 1)).isoformat()
    detections = _write_many(tmp_path, [
        ("rule-ok", "experimental", today.isoformat(), None),
        ("rule-stale", "experimental", long_ago, None),
    ])
    runner = CliRunner()
    result = runner.invoke(cli, [
        "lifecycle", "promote",
        "--rules", "rule-ok,rule-stale",
        "--path", str(detections),
        "--no-workspace-query",
    ])
    assert result.exit_code == 1, result.output
    assert "REFUSED" in result.output
    assert "Summary: 1 promoted" in result.output
    assert "1 failed" in result.output


def test_promote_bulk_continue_on_failure_exits_0(tmp_path: Path) -> None:
    """`--continue-on-failure` makes the batch exit 0 even if some
    rules failed their gates. The failures are still printed."""
    today = date.today()
    long_ago = (today.replace(year=today.year - 1)).isoformat()
    detections = _write_many(tmp_path, [
        ("rule-ok", "experimental", today.isoformat(), None),
        ("rule-stale", "experimental", long_ago, None),
    ])
    runner = CliRunner()
    result = runner.invoke(cli, [
        "lifecycle", "promote",
        "--rules", "rule-ok,rule-stale",
        "--continue-on-failure",
        "--path", str(detections),
        "--no-workspace-query",
    ])
    assert result.exit_code == 0, result.output
    assert "REFUSED" in result.output
    assert "Summary: 1 promoted" in result.output
    assert "1 failed" in result.output


def test_promote_bulk_unknown_rule_id_synthesizes_locate_failure(
    tmp_path: Path,
) -> None:
    """Unknown rule_id in --rules surfaces as a `locate_envelope` gate
    failure row (instead of crashing the batch). Operator can scan
    the table and see exactly which IDs were typos."""
    today = date.today().isoformat()
    detections = _write_many(tmp_path, [
        ("rule-real", "experimental", today, None),
    ])
    runner = CliRunner()
    result = runner.invoke(cli, [
        "lifecycle", "promote",
        "--rules", "rule-real,rule-typo",
        "--path", str(detections),
        "--no-workspace-query",
    ])
    assert result.exit_code == 1, result.output
    assert "locate_envelope" in result.output
    assert "rule-typo" in result.output
    # rule-real still promoted
    assert "Summary: 1 promoted" in result.output


def test_promote_selectors_mutually_exclusive(tmp_path: Path) -> None:
    """rule_id + --rules + --cohort: exactly one allowed. Two raises."""
    detections = _write_many(tmp_path, [("rule-a", "experimental", "2026-05-01", None)])
    runner = CliRunner()
    result = runner.invoke(cli, [
        "lifecycle", "promote", "rule-a",
        "--rules", "rule-a,rule-b",
        "--path", str(detections),
    ])
    assert result.exit_code == 2
    assert "mutually exclusive" in result.output


def test_promote_no_selector_exits_2(tmp_path: Path) -> None:
    detections = _write_many(tmp_path, [("rule-a", "experimental", "2026-05-01", None)])
    runner = CliRunner()
    result = runner.invoke(cli, [
        "lifecycle", "promote",
        "--path", str(detections),
    ])
    assert result.exit_code == 2
    assert "exactly one selector required" in result.output


def test_promote_cohort_no_matches_exits_1(tmp_path: Path) -> None:
    """`--cohort foo` with zero matching envelopes exits 1 with an
    explicit error — distinct from "matched but all failed" so the
    operator can tell the typo case apart from the gate-failure case."""
    detections = _write_many(tmp_path, [
        ("rule-a", "experimental", "2026-05-01", "different-cohort"),
    ])
    runner = CliRunner()
    result = runner.invoke(cli, [
        "lifecycle", "promote",
        "--cohort", "nonexistent",
        "--path", str(detections),
    ])
    assert result.exit_code == 1
    assert "no envelopes with metadata.cohort='nonexistent'" in result.output
