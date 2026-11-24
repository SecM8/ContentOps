# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Defender deploy: what is sent, what counts as changed, what is checked.

The handler runs against ``FakeGraph`` (tests/v2/defender_shapes.py), a
synthetic tenant that mirrors old and new keys, expands every value and
can be told to misbehave. Pinned here:

* a request never carries an ignored old key;
* an edit to any compared field is deployed, and an unchanged rule is
  not written;
* after a write the tenant must hold what the file says, and nothing
  else may have changed;
* a dry run reads and compares, and never writes;
* a message names fields, never a value.
"""

from __future__ import annotations

import copy
from pathlib import Path

import pytest

from contentops.core.asset import Asset
from contentops.core.envelope import EnvelopeV2
from contentops.core.handler import LoadedAsset
from contentops.core.result import PlanAction
from contentops.handlers import defender_custom_detection as handler_module
from contentops.handlers.defender_custom_detection import DefenderCustomDetectionHandler
from tests.v2.defender_shapes import (
    FakeGraph,
    current_payload,
    legacy_only_payload,
    two_shape_payload,
)

OLD_KEYS = {
    "schedule": ("period",),
    "detectionAction.alertTemplate": ("category", "mitreTechniques", "impactedAssets"),
    "detectionAction": ("responseActions",),
    "detectionAction.organizationalScope": ("scopeType", "scopeNames"),
}
SECRET = "SECRET-VALUE"


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    monkeypatch.setattr(handler_module.time, "sleep", lambda *_: None)


def _loaded(payload: dict, *, status: str = "production", arm_name: str | None = None) -> LoadedAsset:
    envelope = EnvelopeV2(
        id="synthetic-rule", version="1.0.0",
        asset=Asset.DEFENDER_CUSTOM_DETECTION, status=status, arm_name=arm_name,
    )
    return LoadedAsset(path=Path("synthetic.yml"), envelope=envelope, payload=copy.deepcopy(payload))


def _tenant_with(payload: dict, **flags) -> tuple[FakeGraph, str]:
    """A synthetic tenant that already holds ``payload`` as one rule."""
    stored = FakeGraph().create_rule(copy.deepcopy(payload)).json()
    graph = FakeGraph(rules=[stored], **flags)
    return graph, stored["id"]


def _handler(graph: FakeGraph) -> DefenderCustomDetectionHandler:
    return DefenderCustomDetectionHandler(lambda: graph)


def _node(body: dict, path: str) -> dict:
    node = body
    for key in path.split("."):
        node = node.get(key) or {}
    return node


def _edited(path: str, value, base=current_payload) -> dict:
    payload = base()
    node = payload
    keys = path.split(".")
    for key in keys[:-1]:
        node = node[key]
    node[keys[-1]] = value
    return payload


# --- which rule a file is -----------------------------------------------------


def test_a_create_whose_alert_title_is_taken_is_not_sent_and_says_how_to_fix_it() -> None:
    """A rule deploy created carries no Graph id in its file until the next
    collect. Renamed in the file before that, it matched nothing; deploy
    posted a second rule and Graph refused it with 409 ("a detection rule
    with this name, title, or rule ID already exists"), with nothing said
    about the cause. Seen against a tenant. Graph keeps alert titles
    unique, so deploy now checks the title before it creates. It does not
    take that rule over: another file may own it."""
    graph, rule_id = _tenant_with(current_payload())
    renamed = current_payload()
    renamed["displayName"] = renamed["displayName"] + " renamed"
    result = _handler(graph).apply(_loaded(renamed))  # no arm_name recorded
    assert result.verified is False
    assert graph.writes() == []
    assert rule_id in (result.error or "")
    assert "arm_name" in (result.error or "")

    dry = _handler(graph).apply(_loaded(renamed), dry_run=True)
    assert rule_id in (dry.detail or "")


# --- what is sent ------------------------------------------------------------


@pytest.mark.parametrize("payload_factory", [current_payload, two_shape_payload])
def test_a_create_never_sends_an_ignored_old_key(payload_factory) -> None:
    graph = FakeGraph()
    result = _handler(graph).apply(_loaded(payload_factory()))
    assert result.action == PlanAction.CREATE
    assert result.verified is True, result.error
    (_method, _id, body), = graph.writes()
    for parent, keys in OLD_KEYS.items():
        for key in keys:
            assert key not in _node(body, parent), f"{parent}.{key} was sent"
    assert "isEnabled" not in body


def test_an_update_never_sends_an_ignored_old_key() -> None:
    graph, rule_id = _tenant_with(current_payload())
    payload = two_shape_payload()
    payload["detectionAction"]["alertTemplate"]["recommendedActions"] = "other actions"
    result = _handler(graph).apply(_loaded(payload, arm_name=rule_id))
    assert result.action == PlanAction.UPDATE
    assert result.verified is True, result.error
    (_method, _id, body), = graph.writes()
    for parent, keys in OLD_KEYS.items():
        for key in keys:
            assert key not in _node(body, parent), f"{parent}.{key} was sent"


def test_a_file_with_old_keys_only_is_sent_as_written_and_verifies() -> None:
    graph = FakeGraph()
    result = _handler(graph).apply(_loaded(legacy_only_payload()))
    assert result.verified is True, result.error
    (_method, _id, body), = graph.writes()
    assert body["schedule"] == {"period": "1H"}
    assert body["detectionAction"]["alertTemplate"]["category"] == "Persistence"
    assert "tactics" not in body["detectionAction"]["alertTemplate"]


# --- what counts as changed ---------------------------------------------------


@pytest.mark.parametrize("payload_factory", [current_payload, two_shape_payload, legacy_only_payload])
def test_an_unchanged_rule_is_not_written(payload_factory) -> None:
    graph, rule_id = _tenant_with(payload_factory())
    result = _handler(graph).apply(_loaded(payload_factory(), arm_name=rule_id))
    assert graph.writes() == []
    assert result.action == PlanAction.NOOP
    assert result.verified is True


@pytest.mark.parametrize(
    ("path", "value"),
    [
        ("description", "another description"),
        ("schedule.lookback", "PT8H"),
        ("detectionAction.alertTemplate.description", "another alert description"),
        ("detectionAction.alertTemplate.recommendedActions", "other actions"),
        ("detectionAction.alertTemplate.customDetails", {"Key": "AccountName"}),
        (
            "detectionAction.alertTemplate.tactics",
            [{"tactic": "Execution", "techniques": [{"technique": "T1059", "subTechniques": []}]}],
        ),
        (
            "detectionAction.alertTemplate.entityMappings",
            {"hosts": [{"deviceIdColumn": "DeviceId"}], "accounts": [{"sidColumn": "AccountSid"}]},
        ),
        ("detectionAction.automatedActions", {"isolateDevices": [{"deviceIdColumn": "DeviceId"}]}),
        ("detectionAction.organizationalScope", {"deviceGroups": ["group-a"]}),
    ],
)
def test_an_edit_outside_the_old_seven_fields_is_deployed(path: str, value) -> None:
    """These edits used to be reported as "no change" and never reached
    the tenant."""
    graph, rule_id = _tenant_with(current_payload())
    result = _handler(graph).apply(_loaded(_edited(path, value), arm_name=rule_id))
    assert [call[0] for call in graph.writes()] == ["PATCH"]
    assert result.action == PlanAction.UPDATE
    assert result.verified is True, result.error


def test_a_second_deploy_of_the_same_file_sends_nothing() -> None:
    graph, rule_id = _tenant_with(current_payload())
    edited = _edited("detectionAction.alertTemplate.recommendedActions", "other actions")
    handler = _handler(graph)
    assert handler.apply(_loaded(edited, arm_name=rule_id)).action == PlanAction.UPDATE
    writes_after_first = len(graph.writes())
    second = handler.apply(_loaded(edited, arm_name=rule_id))
    assert second.action == PlanAction.NOOP
    assert len(graph.writes()) == writes_after_first


# --- what is checked after the write -----------------------------------------


def test_a_new_hand_written_rule_passes_its_check() -> None:
    """The tenant returns more keys than a short file holds (a derived
    lookback, the old keys, every empty collection). That must not fail
    the check of a rule that was created as written."""
    graph = FakeGraph()
    payload = current_payload(schedule={"frequency": "PT1H"})
    result = _handler(graph).apply(_loaded(payload))
    assert result.action == PlanAction.CREATE
    assert result.verified is True, result.error


def test_a_stale_read_after_the_write_is_waited_out() -> None:
    graph, rule_id = _tenant_with(current_payload(), stale_reads=2)
    edited = _edited("detectionAction.alertTemplate.recommendedActions", "other actions")
    result = _handler(graph).apply(_loaded(edited, arm_name=rule_id))
    assert result.verified is True, result.error


def test_a_value_that_did_not_arrive_is_named_without_its_value() -> None:
    graph, rule_id = _tenant_with(current_payload(), merge_on_patch=True)
    edited = _edited(
        "detectionAction.alertTemplate.entityMappings", {"hosts": [{"nameColumn": SECRET}]},
    )
    result = _handler(graph).apply(_loaded(edited, arm_name=rule_id))
    assert result.verified is False
    assert (result.error or "").startswith("post-apply hash mismatch")
    assert "detectionAction.alertTemplate.entityMappings" in (result.error or "")
    assert SECRET not in (result.error or "") + (result.detail or "")


def test_a_scope_lost_by_an_unrelated_update_fails_the_check() -> None:
    graph, rule_id = _tenant_with(current_payload(), lose_scope_on_patch=True)
    edited = _edited("detectionAction.alertTemplate.recommendedActions", "other actions")
    del edited["detectionAction"]["organizationalScope"]
    result = _handler(graph).apply(_loaded(edited, arm_name=rule_id))
    assert result.verified is False
    assert "changed without being sent" in (result.error or "")
    assert "detectionAction.organizationalScope.deviceGroups" in (result.error or "")
    assert "group-a" not in (result.error or "")


def test_an_action_lost_by_an_unrelated_update_fails_the_check() -> None:
    graph, rule_id = _tenant_with(current_payload(), lose_actions_on_patch=True)
    edited = _edited("detectionAction.alertTemplate.recommendedActions", "other actions")
    del edited["detectionAction"]["automatedActions"]
    result = _handler(graph).apply(_loaded(edited, arm_name=rule_id))
    assert result.verified is False
    assert "detectionAction.automatedActions" in (result.error or "")


def test_file_empty_and_tenant_filled_is_reported_and_does_not_fail() -> None:
    graph, rule_id = _tenant_with(current_payload())
    payload = current_payload()
    payload["detectionAction"]["alertTemplate"]["recommendedActions"] = None
    result = _handler(graph).apply(_loaded(payload, arm_name=rule_id))
    assert graph.writes() == []
    assert result.action == PlanAction.NOOP
    assert result.verified is True
    assert "detectionAction.alertTemplate.recommendedActions" in (result.detail or "")


# --- an update never sends an empty value over a filled one --------------------
#
# The synthetic tenant honours ``null``, ``''`` and ``{}`` as "clear" (the
# usual PATCH meaning). A file that is empty where the tenant holds a value
# must therefore not travel as it is: the scope of a rule would be cleared,
# and the rule broadened to every device, before any check could notice.


@pytest.mark.parametrize("empty", [None, {}, {"deviceGroups": []}])
def test_an_update_never_clears_a_scope_the_file_leaves_empty(empty) -> None:
    graph, rule_id = _tenant_with(current_payload())
    payload = _edited("detectionAction.alertTemplate.recommendedActions", "other actions")
    payload["detectionAction"]["organizationalScope"] = empty
    result = _handler(graph).apply(_loaded(payload, arm_name=rule_id))
    (_method, _id, body), = graph.writes()
    assert body["detectionAction"]["organizationalScope"] == {"deviceGroups": ["group-a", "group-b"]}
    assert graph.rule(rule_id)["detectionAction"]["organizationalScope"]["deviceGroups"] == ["group-a", "group-b"]
    assert result.verified is True, result.error
    assert "organizationalScope" in result.detail


def test_an_update_never_clears_a_value_the_file_leaves_empty() -> None:
    graph, rule_id = _tenant_with(current_payload())
    before = graph.rule(rule_id)
    payload = _edited("detectionAction.alertTemplate.title", "Another title")
    payload["description"] = None
    payload["detectionAction"]["alertTemplate"]["recommendedActions"] = ""
    payload["detectionAction"]["alertTemplate"]["customDetails"] = None
    payload["detectionAction"]["alertTemplate"]["tactics"] = []
    payload["detectionAction"]["alertTemplate"]["entityMappings"] = {}
    payload["detectionAction"]["automatedActions"] = {}
    result = _handler(graph).apply(_loaded(payload, arm_name=rule_id))
    after = graph.rule(rule_id)
    assert result.verified is True, result.error
    assert after["description"] == before["description"]
    for key in ("recommendedActions", "customDetails", "tactics", "entityMappings"):
        assert after["detectionAction"]["alertTemplate"][key] == before["detectionAction"]["alertTemplate"][key], key
    assert after["detectionAction"]["automatedActions"] == before["detectionAction"]["automatedActions"]
    assert after["detectionAction"]["alertTemplate"]["title"] == "Another title"


def test_an_update_keeps_a_lookback_the_file_leaves_empty() -> None:
    graph, rule_id = _tenant_with(current_payload(schedule={"frequency": "PT1H", "lookback": "PT8H"}))
    payload = _edited("detectionAction.alertTemplate.title", "Another title")
    payload["schedule"] = {"frequency": "PT1H", "lookback": None}
    result = _handler(graph).apply(_loaded(payload, arm_name=rule_id))
    assert result.verified is True, result.error
    assert graph.rule(rule_id)["schedule"]["lookback"] == "PT8H"


def test_a_new_frequency_lets_the_service_derive_the_lookback() -> None:
    """The old lookback may not fit the new frequency, so it is not sent
    back when the frequency itself is what changes."""
    graph, rule_id = _tenant_with(current_payload(schedule={"frequency": "PT1H", "lookback": "PT8H"}))
    payload = current_payload(schedule={"frequency": "PT3H", "lookback": None})
    result = _handler(graph).apply(_loaded(payload, arm_name=rule_id))
    (_method, _id, body), = graph.writes()
    assert body["schedule"] == {"frequency": "PT3H", "lookback": None}
    assert result.verified is True, result.error
    assert graph.rule(rule_id)["schedule"]["frequency"] == "PT3H"


# --- the enabled state keeps its own rule -------------------------------------


def test_a_disable_is_sent_although_the_content_is_unchanged() -> None:
    graph, rule_id = _tenant_with(current_payload())
    result = _handler(graph).apply(_loaded(current_payload(), status="deprecated", arm_name=rule_id))
    assert result.action == PlanAction.DISABLE
    assert result.verified is True, result.error
    assert graph.rule(rule_id)["status"] == "disabled"


# --- dry run -------------------------------------------------------------------


def test_a_dry_run_never_writes_and_says_what_a_deploy_would_do() -> None:
    graph, rule_id = _tenant_with(current_payload())
    handler = _handler(graph)

    same = handler.apply(_loaded(two_shape_payload(), arm_name=rule_id), dry_run=True)
    assert (same.action, same.status) == (PlanAction.NOOP, "dry-run")

    edited = _edited("detectionAction.alertTemplate.recommendedActions", SECRET)
    update = handler.apply(_loaded(edited, arm_name=rule_id), dry_run=True)
    assert (update.action, update.status) == (PlanAction.UPDATE, "dry-run")
    assert "detectionAction.alertTemplate.recommendedActions" in update.detail
    assert SECRET not in update.detail

    new = current_payload(displayName="A rule the tenant does not have")
    create = handler.apply(_loaded(new), dry_run=True)
    assert (create.action, create.status) == (PlanAction.CREATE, "dry-run")

    assert graph.writes() == []
    assert {call[0] for call in graph.calls} <= {"LIST", "GET"}


def test_a_dry_run_client_cannot_write() -> None:
    graph, rule_id = _tenant_with(current_payload())
    read_only = handler_module.ReadOnlyDefenderClient(graph)
    assert read_only.get_rule(rule_id) is not None
    assert read_only.list_rules()
    for call in (
        lambda: read_only.create_rule({}),
        lambda: read_only.update_rule(rule_id, {}),
        lambda: read_only.delete_rule(rule_id),
    ):
        with pytest.raises(PermissionError):
            call()
    assert graph.writes() == []


def test_a_dry_run_disable_is_reported_as_a_disable() -> None:
    graph, rule_id = _tenant_with(current_payload())
    result = _handler(graph).apply(
        _loaded(current_payload(), status="deprecated", arm_name=rule_id), dry_run=True,
    )
    assert (result.action, result.status) == (PlanAction.DISABLE, "dry-run")
    assert graph.writes() == []


def test_a_dry_run_without_a_client_still_answers() -> None:
    result = DefenderCustomDetectionHandler(lambda: None).apply(_loaded(current_payload()), dry_run=True)
    assert result.status == "dry-run"


class _UnreadableTenant:
    def list_rules(self) -> list[dict]:
        raise RuntimeError("simulated: the tenant cannot be read")

    def close(self) -> None:
        return None


@pytest.mark.parametrize("factory", [lambda: None, lambda: _UnreadableTenant()], ids=["no client", "list fails"])
def test_a_dry_run_that_could_not_read_the_tenant_says_not_compared(factory) -> None:
    """With no reading of the tenant nothing is known about the rule. It
    must not be counted as "would create": that would read as "the tenant
    was checked and the rule is not there"."""
    from contentops.cli.commands.apply import _defender_dry_run_totals

    result = DefenderCustomDetectionHandler(factory).apply(_loaded(current_payload()), dry_run=True)
    assert result.status == "dry-run"
    assert result.detail.startswith("not compared")
    assert _defender_dry_run_totals([result]) == (
        "Defender dry run: 1 rule(s) checked against the tenant: "
        "0 no change, 0 would update, 0 would create, 1 not compared."
    )


def test_a_dry_run_ends_with_one_line_of_totals() -> None:
    """The line an operator reads to decide: how many rules a real
    deploy would touch."""
    from contentops.cli.commands.apply import _defender_dry_run_totals

    graph, rule_id = _tenant_with(current_payload())
    handler = _handler(graph)
    results = [
        handler.apply(_loaded(two_shape_payload(), arm_name=rule_id), dry_run=True),
        handler.apply(
            _loaded(_edited("description", "another description"), arm_name=rule_id), dry_run=True,
        ),
        handler.apply(_loaded(current_payload(displayName="Not in the tenant")), dry_run=True),
    ]
    line = _defender_dry_run_totals(results)
    assert line == (
        "Defender dry run: 3 rule(s) checked against the tenant: "
        "1 no change, 1 would update, 1 would create, 0 not compared."
    )
    assert _defender_dry_run_totals([]) is None


# --- the real files ------------------------------------------------------------

REAL_FILES = sorted(
    (Path(__file__).resolve().parents[2] / "detections" / "defender_custom_detection").glob("*.yml")
)


class _TenantHoldingTheFile:
    """A tenant whose one rule is exactly what the file holds, plus the
    server-managed fields a real read carries. Every write fails the test."""

    def __init__(self, graph_id: str, payload: dict) -> None:
        self._rule = {
            **copy.deepcopy(payload),
            "id": graph_id,
            "createdDateTime": "2026-01-01T00:00:00Z",
            "lastModifiedDateTime": "2026-01-02T00:00:00Z",
            "detectorId": "synthetic-detector",
        }
        self._rule["schedule"] = {**(payload.get("schedule") or {}), "nextRunDateTime": "2026-01-03T00:00:00Z"}

    def list_rules(self) -> list[dict]:
        return [copy.deepcopy(self._rule)]

    def get_rule(self, _graph_id: str) -> dict:
        return copy.deepcopy(self._rule)

    def _write(self, *_args, **_kwargs):
        raise AssertionError("an unchanged rule was written")

    create_rule = update_rule = delete_rule = _write

    def close(self) -> None:
        return None


@pytest.mark.parametrize("path", REAL_FILES, ids=lambda p: p.stem)
def test_a_real_file_that_equals_the_tenant_is_left_alone(path: Path) -> None:
    """Every Defender file here was written from the tenant. Against a
    tenant that still holds that content, a dry run must say "no change"
    and a deploy must send nothing, for the file as it is on disk."""
    import yaml

    doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    graph_id = str((doc.get("metadata") or {}).get("arm_name") or "synthetic-id")
    tenant = _TenantHoldingTheFile(graph_id, doc["payload"])
    loaded = _loaded(doc["payload"], status=doc.get("status", "production"), arm_name=graph_id)
    if loaded.envelope.status == "experimental":
        pytest.skip("experimental rules are not deployed")

    handler = DefenderCustomDetectionHandler(lambda: tenant)
    handler.validate(loaded)
    dry = handler.apply(loaded, dry_run=True)
    assert (dry.action, dry.status, dry.detail) == (PlanAction.NOOP, "dry-run", "")
    real = handler.apply(loaded)
    assert (real.action, real.verified) == (PlanAction.NOOP, True)


# --- validation ------------------------------------------------------------------


def test_validation_checks_the_file_and_what_would_be_sent() -> None:
    handler = _handler(FakeGraph())
    for payload in (current_payload(), two_shape_payload(), legacy_only_payload()):
        handler.validate(_loaded(payload))
    blank = two_shape_payload()
    blank["schedule"]["frequency"] = ""
    with pytest.raises(ValueError):
        handler.validate(_loaded(blank))
