# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Safety tests for the live Defender shape probe.

The probe (``tests/integration/defender_shape_probe.py``) writes to a real
tenant. These tests run it against an in-memory Graph and pin what must
hold whatever the service answers: it creates disabled rules only, never
writes to a rule it did not create, always deletes what it created, never
puts a tenant value in its report, and flags the answers that mean
"stop".
"""

from __future__ import annotations

import copy
from pathlib import Path

import pytest

from tests.integration import defender_shape_probe as probe
from tests.v2.defender_shapes import FakeGraph, scoped_tenant_rule

SECRET_GROUPS = ["SECRET-GROUP-ALPHA", "SECRET-GROUP-BETA"]
REPO_TESTS = Path(__file__).resolve().parents[1]


def _tenant_rule() -> dict:
    return scoped_tenant_rule(groups=SECRET_GROUPS, name="SECRET existing rule")


def _run(graph: FakeGraph) -> probe.ProbeReport:
    return probe.run_probe(graph, run_id="unit", sleep=lambda _s: None)


def _answers(report: probe.ProbeReport) -> dict[str, str]:
    return {finding.key: finding.answer for finding in report.findings}


def _stop_keys(report: probe.ProbeReport) -> set[str]:
    return {finding.key for finding in report.stops()}


def test_probe_prefix_is_the_one_the_session_sweep_deletes() -> None:
    from tests.integration.conftest import RESOURCE_PREFIX_UNDERSCORE

    assert probe.PREFIX == RESOURCE_PREFIX_UNDERSCORE


def test_live_test_fails_on_stop_abort_or_leftover(tmp_path, monkeypatch) -> None:
    """The live wrapper must turn an abort, a leftover or a STOP answer
    into a failed job, and must still write the report first."""
    from tests.integration import test_defender_rule_shape_probe as live

    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    monkeypatch.setenv(probe.CONFIRM_ENV, "yes")
    graph = FakeGraph(rules=[_tenant_rule()], lose_scope_on_patch=True)
    monkeypatch.setattr(probe.time, "sleep", lambda _s: None)
    with pytest.raises(AssertionError) as failure:
        live.test_defender_rule_shape_probe(graph, "zz-itest-1700000000-abc123")
    report_text = (tmp_path / live.REPORT_FILE).read_text(encoding="utf-8")
    assert "STOP" in report_text
    assert "SECRET" not in report_text
    assert "SECRET" not in str(failure.value)


def test_live_test_passes_on_a_clean_run(tmp_path, monkeypatch) -> None:
    from tests.integration import test_defender_rule_shape_probe as live

    monkeypatch.chdir(tmp_path)
    summary = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    monkeypatch.setenv(probe.CONFIRM_ENV, "yes")
    monkeypatch.setattr(probe.time, "sleep", lambda _s: None)
    graph = FakeGraph(rules=[_tenant_rule()])
    live.test_defender_rule_shape_probe(graph, "zz-itest-1700000000-abc123")
    assert "Defender rule shape probe" in summary.read_text(encoding="utf-8")
    for method, _id, body in graph.calls:
        if method == "POST":
            assert body["displayName"].startswith("zz_itest_1700000000_abc123_")


@pytest.mark.parametrize("value", [None, "", "no", "true", "YES"])
def test_live_probe_refuses_to_run_without_the_production_confirmation(tmp_path, monkeypatch, value) -> None:
    """Defender is tenant-wide, so the probe always writes to the real
    tenant. Without the explicit confirmation it must make no call at
    all, however pytest was started. It skips with the reason: the whole
    live suite also runs on paths that cannot confirm (a PR label)."""
    from tests.integration import test_defender_rule_shape_probe as live

    monkeypatch.chdir(tmp_path)
    if value is None:
        monkeypatch.delenv(probe.CONFIRM_ENV, raising=False)
    else:
        monkeypatch.setenv(probe.CONFIRM_ENV, value)
    graph = FakeGraph(rules=[_tenant_rule()])
    with pytest.raises(pytest.skip.Exception, match="i-know-this-hits-prod"):
        live.test_defender_rule_shape_probe(graph, "zz-itest-1700000000-abc123")
    assert graph.calls == []


def test_live_sweep_refuses_to_run_without_the_production_confirmation(monkeypatch) -> None:
    from tests.integration import test_sweep_leftovers as sweep

    monkeypatch.delenv(probe.CONFIRM_ENV, raising=False)
    graph = FakeGraph(rules=[_tenant_rule()])
    with pytest.raises(pytest.skip.Exception):
        sweep.test_sweep_leftover_defender_rules(graph)
    assert graph.calls == []


def test_the_scope_step_uses_the_device_group_the_operator_names() -> None:
    """A tenant may have no scoped rule to copy a group from. The operator
    names one (``DEFENDER_PROBE_DEVICE_GROUP``); the report still says
    only yes or no, never the name."""
    graph = FakeGraph()
    report = probe.run_probe(graph, run_id="unit", sleep=lambda _s: None, device_group="OPERATOR-GROUP")
    answers = _answers(report)
    assert answers["scope_new_key_only"].startswith("kept")
    assert answers["scope_survives_update"] == "kept"
    assert report.stops() == []
    sent = [body for method, _id, body in graph.calls if method == "PATCH"
            and "organizationalScope" in (body.get("detectionAction") or {})]
    assert {"deviceGroups": ["OPERATOR-GROUP"]} in [b["detectionAction"]["organizationalScope"] for b in sent]
    assert "OPERATOR-GROUP" not in probe.render_report(report) + repr(report)


def test_the_live_test_passes_the_device_group_from_the_environment(tmp_path, monkeypatch) -> None:
    from tests.integration import test_defender_rule_shape_probe as live

    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    monkeypatch.setenv(probe.CONFIRM_ENV, "yes")
    monkeypatch.setenv(probe.DEVICE_GROUP_ENV, "OPERATOR-GROUP")
    monkeypatch.setattr(probe.time, "sleep", lambda _s: None)
    graph = FakeGraph()
    live.test_defender_rule_shape_probe(graph, "zz-itest-1700000000-abc123")
    report_text = (tmp_path / live.REPORT_FILE).read_text(encoding="utf-8")
    assert "skipped: no scoped rule" not in report_text
    assert "OPERATOR-GROUP" not in report_text


def test_asks_whether_an_update_with_detection_action_keeps_scope_and_actions() -> None:
    """A deploy that changes the alert sends ``detectionAction`` with its
    ``alertTemplate``. If the service clears scope and actions that are
    not in that request, the deploy must always send them."""
    report = _run(FakeGraph(rules=[_tenant_rule()]))
    assert _answers(report)["detection_action_keeps_scope_and_actions"] == "scope kept, actions kept"
    assert "detection_action_keeps_scope_and_actions" not in _stop_keys(report)


def test_stop_when_an_update_with_detection_action_clears_scope_and_actions() -> None:
    report = _run(FakeGraph(rules=[_tenant_rule()], drop_omitted_action_parts=True))
    assert _answers(report)["detection_action_keeps_scope_and_actions"] == "scope lost, actions lost"
    assert "detection_action_keeps_scope_and_actions" in _stop_keys(report)
    # The plain updates that do not mention detectionAction still keep both.
    assert "scope_survives_update" not in _stop_keys(report)
    assert "action_survives_update" not in _stop_keys(report)


def test_asks_whether_a_one_week_schedule_is_accepted() -> None:
    graph = FakeGraph(rules=[_tenant_rule()])
    report = _run(graph)
    answers = _answers(report)
    assert answers["frequency_p1w"].startswith("accepted")
    assert answers["lookback_p1w"].startswith("accepted")
    assert "frequency_p1w" not in _stop_keys(report) and "lookback_p1w" not in _stop_keys(report)


def test_reports_a_rejected_one_week_schedule_and_restores_the_schedule() -> None:
    graph = FakeGraph(rules=[_tenant_rule()], reject_schedule_values=("P1W",))
    report = _run(graph)
    answers = _answers(report)
    assert answers["frequency_p1w"].startswith("rejected (400")
    assert answers["lookback_p1w"].startswith("rejected (400")
    assert report.stops() == []


def test_live_sweep_deletes_only_test_rules(monkeypatch) -> None:
    from tests.integration import test_sweep_leftovers as sweep

    monkeypatch.setenv(probe.CONFIRM_ENV, "yes")
    monkeypatch.setattr(sweep.time, "sleep", lambda _s: None)
    existing = _tenant_rule()
    leftover = scoped_tenant_rule(groups=["g"], name=probe.PREFIX + "left_behind")
    leftover["id"] = "6000"  # both helpers start a fresh fake tenant at the same id
    graph = FakeGraph(rules=[existing, leftover])
    assert len(graph.all_rules()) == 2
    sweep.test_sweep_leftover_defender_rules(graph)
    names = [rule["displayName"] for rule in graph.all_rules()]
    assert names == [existing["displayName"]]
    assert [call for call in graph.writes()] == [("DELETE", "6000", None)]


def test_the_confirmed_client_fixture_checks_before_it_asks_for_a_client() -> None:
    """The session client sweeps test rules when it is torn down. The
    live tests therefore get their client through a fixture that checks
    the confirmation first, so an unconfirmed run never creates it."""
    import inspect

    from tests.integration import conftest

    source = inspect.getsource(conftest.confirmed_defender_client)
    assert source.index("require_confirmation()") < source.index('getfixturevalue("defender_client")')
    for module in ("test_defender_rule_shape_probe", "test_sweep_leftovers"):
        text = (REPO_TESTS / "integration" / f"{module}.py").read_text(encoding="utf-8")
        assert "confirmed_defender_client" in text
        assert "(defender_client" not in text


def test_probe_is_not_misled_by_odata_annotations_in_mappings() -> None:
    """If Graph returns ``@odata.type`` in each mapping entry, a blank
    entry must still count as blank, or "replace" would be read as
    "merge"."""
    report = _run(FakeGraph(rules=[_tenant_rule()], annotate_mappings=True))
    assert report.stops() == []
    assert _answers(report)["replace_or_merge"] == "replace"


def test_happy_path_has_no_stop_and_no_abort() -> None:
    report = _run(FakeGraph(rules=[_tenant_rule()]))
    assert report.aborted is None
    assert report.stops() == []
    assert report.leftovers == 0


def test_every_created_rule_is_disabled_and_cannot_return_a_row() -> None:
    graph = FakeGraph(rules=[_tenant_rule()])
    _run(graph)
    posts = [body for method, _id, body in graph.calls if method == "POST"]
    assert posts, "the probe created no rule"
    for body in posts:
        assert body["status"] == "disabled"
        assert "isEnabled" not in body
        assert body["displayName"].startswith(probe.PREFIX)
        assert probe.NO_ROW_DEVICE in body["queryCondition"]["queryText"]
        assert body["detectionAction"]["alertTemplate"]["title"] == body["displayName"]


def test_no_update_ever_enables_a_rule() -> None:
    graph = FakeGraph(rules=[_tenant_rule()])
    _run(graph)
    for method, _id, body in graph.calls:
        if method == "PATCH":
            assert body.get("status", "disabled") == "disabled"


def test_no_test_rule_is_left_behind() -> None:
    graph = FakeGraph(rules=[_tenant_rule()])
    report = _run(graph)
    names = [rule["displayName"] for rule in graph.all_rules()]
    assert not [name for name in names if name.startswith(probe.PREFIX)]
    assert report.leftovers == 0


def test_an_existing_rule_is_never_written() -> None:
    existing = _tenant_rule()
    graph = FakeGraph(rules=[existing])
    before = copy.deepcopy(graph.rule(existing["id"]))
    _run(graph)
    assert graph.rule(existing["id"]) == before
    assert not [call for call in graph.writes() if call[1] == existing["id"]]


def test_aborts_and_deletes_when_a_rule_comes_back_enabled() -> None:
    graph = FakeGraph(rules=[_tenant_rule()], create_status="enabled")
    report = _run(graph)
    assert report.aborted is not None
    assert not [call for call in graph.calls if call[0] == "PATCH"]
    assert [call for call in graph.calls if call[0] == "POST"] and len(
        [call for call in graph.calls if call[0] == "POST"]
    ) == 1
    assert not [r for r in graph.all_rules() if r["displayName"].startswith(probe.PREFIX)]
    assert report.stops()


def test_cleans_up_when_a_request_raises() -> None:
    graph = FakeGraph(rules=[_tenant_rule()], raise_on_patch_number=2)
    report = _run(graph)
    assert not [r for r in graph.all_rules() if r["displayName"].startswith(probe.PREFIX)]
    assert report.leftovers == 0
    assert any("error" in finding.answer for finding in report.findings)


def test_a_step_that_errors_is_a_stop() -> None:
    """A step that raised left its question unanswered. A run with an
    unanswered question is not a passed check, even when everything was
    cleaned up afterwards."""
    report = _run(FakeGraph(rules=[_tenant_rule()], raise_on_patch_number=2))
    errors = [finding for finding in report.findings if finding.answer.startswith("error")]
    assert errors
    assert all(finding in report.stops() for finding in errors)


def test_live_test_fails_when_a_step_errors(tmp_path, monkeypatch) -> None:
    from tests.integration import test_defender_rule_shape_probe as live

    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    monkeypatch.setenv(probe.CONFIRM_ENV, "yes")
    monkeypatch.setattr(probe.time, "sleep", lambda _s: None)
    graph = FakeGraph(rules=[_tenant_rule()], raise_on_patch_number=2)
    with pytest.raises(AssertionError):
        live.test_defender_rule_shape_probe(graph, "zz-itest-1700000000-abc123")
    assert not [r for r in graph.all_rules() if r["displayName"].startswith(probe.PREFIX)]


def test_report_never_contains_a_tenant_value() -> None:
    graph = FakeGraph(rules=[_tenant_rule()])
    report = _run(graph)
    text = probe.render_report(report) + repr(report)
    assert "SECRET" not in text


def test_report_never_contains_a_tenant_value_when_scope_is_lost() -> None:
    graph = FakeGraph(rules=[_tenant_rule()], lose_scope_on_patch=True)
    report = _run(graph)
    text = probe.render_report(report) + repr(report)
    assert "SECRET" not in text


def test_stop_when_graph_rejects_a_rule_without_old_keys() -> None:
    report = _run(FakeGraph(rules=[_tenant_rule()], reject_new_only=True))
    assert "create_new_only" in _stop_keys(report)
    assert report.leftovers == 0


def test_stop_when_scope_is_lost_by_an_unrelated_update() -> None:
    report = _run(FakeGraph(rules=[_tenant_rule()], lose_scope_on_patch=True))
    assert "scope_survives_update" in _stop_keys(report)


def test_stop_when_an_action_is_lost_by_an_unrelated_update() -> None:
    report = _run(FakeGraph(rules=[_tenant_rule()], lose_actions_on_patch=True))
    assert "action_survives_update" in _stop_keys(report)


def test_stop_when_list_and_single_read_disagree() -> None:
    report = _run(FakeGraph(rules=[_tenant_rule()], list_differs=True))
    assert "list_vs_get" in _stop_keys(report)


@pytest.mark.parametrize(
    ("forms", "expected"),
    [
        (("null", "''", "{}"), "null"),
        (("''",), "''"),
        ((), "none"),
    ],
)
def test_reports_which_empty_form_clears_a_text_field(forms, expected) -> None:
    report = _run(FakeGraph(rules=[_tenant_rule()], clearing_forms=forms))
    assert _answers(report)["clear_recommendedActions"] == expected


def test_reports_merge_when_an_update_does_not_replace() -> None:
    report = _run(FakeGraph(rules=[_tenant_rule()], merge_on_patch=True))
    assert _answers(report)["replace_or_merge"] == "merge"


def test_reports_replace_by_default() -> None:
    report = _run(FakeGraph(rules=[_tenant_rule()]))
    assert _answers(report)["replace_or_merge"] == "replace"


def test_scope_probe_is_skipped_without_a_scoped_rule() -> None:
    report = _run(FakeGraph())
    assert _answers(report)["scope_new_key_only"].startswith("skipped")
    assert report.stops() == []


def test_an_annotation_on_the_single_read_is_not_a_difference() -> None:
    """Graph adds ``@odata.context`` to a single-rule read and not to the
    rules of a list. An annotation is not a value. Seen against a tenant:
    the list and single reads were reported as different at it."""
    graph = FakeGraph(rules=[_tenant_rule()], annotate_single_reads=True)
    report = _run(graph)
    assert _answers(report)["list_vs_get"] == "same"
    sent_back = [body for method, _id, body in graph.calls if method == "PATCH"]
    assert not [body for body in sent_back if any(str(k).startswith("@odata.") for k in body)]


def test_answers_wait_for_the_write_to_show_beyond_the_short_window() -> None:
    """Graph can serve the rule as it was for minutes after it acknowledged
    an update. Every answer must be judged on a read that shows the write
    (``lastModifiedDateTime`` at least the one the update returned), also
    the ones that use the short window, or a lag reads as 'not applied',
    'replace' or 'kept'. Seen against a tenant."""
    stale = 12  # longer than the short window, shorter than the long one
    report = probe.run_probe(FakeGraph(rules=[_tenant_rule()], stale_reads=stale),
                             run_id="unit", sleep=lambda _s: None, settle_timeout_s=30.0, poll_s=5.0)
    assert report.stops() == []
    answers = _answers(report)
    assert answers["edit_frequency"] == "applied"
    assert answers["replace_or_merge"] == "replace"
    assert answers["scope_cleared_by_null"] == "removed"
    assert answers["clear_customDetails"] == "null"


def test_a_write_that_never_shows_is_a_stop_not_an_answer() -> None:
    report = probe.run_probe(FakeGraph(rules=[_tenant_rule()], stale_reads=10_000),
                             run_id="unit", sleep=lambda _s: None, converge_timeout_s=20.0, poll_s=5.0)
    answers = _answers(report)
    assert "edit_each_field_error" in _stop_keys(report)
    assert answers["edit_each_field_error"] == "error: WriteNotVisible"
    assert "edit_frequency" not in answers


def test_cleanup_keeps_trying_when_a_list_call_fails() -> None:
    """Graph throttles a busy run (429 past the client's retries). One
    failed list call must not end the cleanup with "unknown"; it waits
    and lists again. Seen against a tenant."""
    graph = FakeGraph(rules=[_tenant_rule()], list_raises_times=2)
    report = _run(graph)
    assert report.leftovers == 0
    assert _answers(report)["cleanup"] == "yes"


def test_a_stale_read_is_waited_out() -> None:
    report = _run(FakeGraph(rules=[_tenant_rule()], stale_reads=2))
    assert report.stops() == []
    assert _answers(report)["replace_or_merge"] == "replace"
