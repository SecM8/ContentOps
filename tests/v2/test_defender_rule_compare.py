# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""What differs between a Defender rule file and the rule in the tenant.

``diff_rule`` decides two things for a deploy: whether anything has to
be sent, and whether what was sent arrived. These tests pin its rules
against a synthetic tenant (``FakeGraph``), which mirrors old and new
keys and returns every value in its expanded form.
"""

from __future__ import annotations

import copy
from pathlib import Path

import pytest
import yaml

from contentops.defender import rule_compare
from contentops.defender.rule_shape import to_current_shape
from contentops.defender.rule_status import to_wire_body
from tests.v2.defender_shapes import (
    FakeGraph,
    current_payload,
    legacy_only_payload,
    two_shape_payload,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
REAL_FILES = sorted((REPO_ROOT / "detections" / "defender_custom_detection").glob("*.yml"))


def _tenant(payload: dict) -> dict:
    """The rule as the synthetic tenant stores and returns it."""
    return FakeGraph().create_rule(copy.deepcopy(payload)).json()


def _changed(file_payload: dict, remote: dict) -> list[str]:
    return list(rule_compare.diff_rule(to_wire_body(file_payload), remote).changed)


# --- a file equals the tenant in every shape it can be written in --------


@pytest.mark.parametrize("payload_factory", [current_payload, two_shape_payload, legacy_only_payload])
def test_no_difference_when_the_tenant_holds_what_the_file_says(payload_factory) -> None:
    payload = payload_factory()
    diff = rule_compare.diff_rule(to_wire_body(payload), _tenant(payload))
    assert diff.changed == ()
    assert diff.not_cleared == ()


def test_short_hand_written_mapping_equals_the_expanded_form() -> None:
    payload = current_payload()
    remote = _tenant(payload)
    hosts = remote["detectionAction"]["alertTemplate"]["entityMappings"]["hosts"]
    assert len(hosts[0]) > 1, "the synthetic tenant no longer expands a mapping"
    assert _changed(payload, remote) == []


def test_annotations_the_tenant_adds_to_a_mapping_are_not_a_difference() -> None:
    payload = current_payload()
    remote = FakeGraph(annotate_mappings=True).create_rule(copy.deepcopy(payload)).json()
    assert _changed(payload, remote) == []


def test_a_blank_mapping_entry_stays_blank_when_the_tenant_annotates_it() -> None:
    """An entry with no column filled is empty. The ``@odata.type`` the
    tenant adds to it names a type, not a value, and must not make it
    count as filled: the rule would look changed on every deploy."""
    payload = current_payload()
    payload["detectionAction"]["alertTemplate"]["entityMappings"] = {
        "hosts": [{"deviceIdColumn": "DeviceId"}],
        "accounts": [{"nameColumn": ""}],
    }
    remote = FakeGraph(annotate_mappings=True).create_rule(copy.deepcopy(payload)).json()
    accounts = remote["detectionAction"]["alertTemplate"]["entityMappings"]["accounts"]
    assert accounts and "@odata.type" in accounts[0]
    diff = rule_compare.diff_rule(to_wire_body(payload), remote)
    assert diff.changed == ()
    assert diff.not_cleared == ()


def test_the_type_of_an_old_style_asset_still_counts() -> None:
    """Annotations are only set aside where one side lacks them. In the
    old keys ``@odata.type`` says which kind of asset or action is meant,
    so a different type there is a difference."""
    payload = legacy_only_payload()
    remote = _tenant(legacy_only_payload())
    remote["detectionAction"]["alertTemplate"]["impactedAssets"][0]["@odata.type"] = (
        "#microsoft.graph.security.impactedUserAsset"
    )
    assert _changed(payload, remote) == ["detectionAction.alertTemplate.impactedAssets"]


def test_list_order_line_endings_and_trailing_spaces_are_not_a_difference() -> None:
    payload = current_payload()
    payload["queryCondition"]["queryText"] = "DeviceProcessEvents\n| take 1"
    payload["detectionAction"]["organizationalScope"]["deviceGroups"] = ["group-b", "group-a"]
    remote = _tenant(payload)
    remote["queryCondition"]["queryText"] = "DeviceProcessEvents  \r\n| take 1\r\n"
    remote["detectionAction"]["organizationalScope"]["deviceGroups"] = ["group-a", "group-b"]
    assert _changed(payload, remote) == []


def test_durations_are_compared_as_durations() -> None:
    payload = current_payload(schedule={"frequency": "PT60M", "lookback": "PT240M"})
    remote = _tenant(current_payload())
    assert remote["schedule"]["frequency"] == "PT1H"
    assert _changed(payload, remote) == []


def test_false_is_a_value_not_an_empty_one() -> None:
    payload = current_payload()
    payload["detectionAction"]["incidentConfiguration"] = {"isExcludedFromIncidentCorrelation": True}
    remote = _tenant(current_payload())
    assert remote["detectionAction"]["incidentConfiguration"] == {"isExcludedFromIncidentCorrelation": False}
    assert _changed(payload, remote) == ["detectionAction.incidentConfiguration"]


# --- every compared field is seen when it is edited -----------------------


def _edit(path: str, value) -> dict:
    payload = current_payload()
    node = payload
    keys = path.split(".")
    for key in keys[:-1]:
        node = node[key]
    node[keys[-1]] = value
    return payload


@pytest.mark.parametrize(
    ("path", "value"),
    [
        ("displayName", "Renamed rule"),
        ("description", "another description"),
        ("queryCondition.queryText", "DeviceProcessEvents | take 2"),
        ("schedule.frequency", "PT3H"),
        ("schedule.lookback", "PT8H"),
        ("detectionAction.alertTemplate.title", "Another title"),
        ("detectionAction.alertTemplate.description", "another alert description"),
        ("detectionAction.alertTemplate.severity", "high"),
        ("detectionAction.alertTemplate.recommendedActions", "other actions"),
        ("detectionAction.alertTemplate.customDetails", {"Key": "AccountName"}),
        ("detectionAction.alertTemplate.tactics", [{"tactic": "Execution", "techniques": []}]),
        (
            "detectionAction.alertTemplate.tactics",
            [{"tactic": "Persistence", "techniques": [{"technique": "T1136", "subTechniques": []}]}],
        ),
        ("detectionAction.alertTemplate.entityMappings", {"hosts": [{"nameColumn": "DeviceName"}]}),
        (
            "detectionAction.alertTemplate.entityMappings",
            {"hosts": [{"deviceIdColumn": "DeviceId"}], "accounts": [{"sidColumn": "AccountSid"}]},
        ),
        ("detectionAction.automatedActions", {"isolateDevices": [{"deviceIdColumn": "DeviceId"}]}),
        ("detectionAction.organizationalScope", {"deviceGroups": ["group-a"]}),
    ],
)
def test_an_edit_to_a_compared_field_is_reported_by_its_name(path: str, value) -> None:
    remote = _tenant(current_payload())
    changed = _changed(_edit(path, value), remote)
    expected = path if not path.endswith("organizationalScope") else path + ".deviceGroups"
    assert changed == [expected]


def test_an_edit_made_through_old_keys_is_seen_when_the_file_has_old_keys_only() -> None:
    remote = _tenant(legacy_only_payload())
    payload = legacy_only_payload()
    payload["schedule"]["period"] = "3H"
    payload["detectionAction"]["alertTemplate"]["category"] = "Execution"
    payload["detectionAction"]["organizationalScope"]["scopeNames"] = ["group-a"]
    assert _changed(payload, remote) == [
        "schedule.period",
        "detectionAction.alertTemplate.category",
        "detectionAction.organizationalScope.scopeNames",
    ]


def test_an_ignored_old_key_is_not_compared() -> None:
    """Next to a filled new key the old key is not sent, so a stale value
    in it must not make the rule look changed."""
    payload = two_shape_payload()
    payload["schedule"]["period"] = "24H"
    payload["detectionAction"]["alertTemplate"]["category"] = "Impact"
    payload["detectionAction"]["alertTemplate"]["mitreTechniques"] = ["T9999"]
    assert _changed(payload, _tenant(current_payload())) == []


# --- what the file does not say is left alone -----------------------------


def test_a_field_the_file_does_not_mention_is_not_compared() -> None:
    payload = current_payload()
    del payload["description"]
    del payload["detectionAction"]["alertTemplate"]["recommendedActions"]
    del payload["detectionAction"]["organizationalScope"]
    diff = rule_compare.diff_rule(to_wire_body(payload), _tenant(current_payload()))
    assert diff.changed == ()
    assert diff.not_cleared == ()


@pytest.mark.parametrize("empty", [None, "", [], {}])
def test_file_empty_and_tenant_filled_is_reported_but_is_not_a_difference(empty) -> None:
    payload = current_payload()
    payload["description"] = empty
    payload["detectionAction"]["alertTemplate"]["recommendedActions"] = empty
    payload["detectionAction"]["organizationalScope"] = empty
    diff = rule_compare.diff_rule(to_wire_body(payload), _tenant(current_payload()))
    assert diff.changed == ()
    assert set(diff.not_cleared) == {
        "description",
        "detectionAction.alertTemplate.recommendedActions",
        "detectionAction.organizationalScope",
    }


def test_values_the_service_fills_in_are_skipped_when_the_file_leaves_them_empty() -> None:
    payload = current_payload(schedule={"frequency": "PT1H", "lookback": None})
    payload["detectionAction"]["alertTemplate"]["eventGroupingKind"] = None
    payload["detectionAction"]["incidentConfiguration"] = None
    diff = rule_compare.diff_rule(to_wire_body(payload), _tenant(current_payload()))
    assert diff.changed == ()
    assert diff.not_cleared == ()


def test_empty_on_both_sides_is_equal_whatever_the_empty_form() -> None:
    payload = current_payload()
    payload["description"] = ""
    payload["detectionAction"]["alertTemplate"]["customDetails"] = {}
    remote = _tenant(current_payload())
    remote["description"] = None
    remote["detectionAction"]["alertTemplate"]["customDetails"] = None
    diff = rule_compare.diff_rule(to_wire_body(payload), remote)
    assert diff.changed == ()
    assert diff.not_cleared == ()


def test_the_inputs_are_not_changed() -> None:
    body = to_wire_body(current_payload())
    remote = _tenant(current_payload())
    before = (copy.deepcopy(body), copy.deepcopy(remote))
    rule_compare.diff_rule(body, remote)
    assert (body, remote) == before


# --- nothing else may change ----------------------------------------------


def test_only_the_intended_field_changed() -> None:
    graph = FakeGraph(rules=[_tenant(current_payload())])
    rule_id = graph.all_rules()[0]["id"]
    before = graph.rule(rule_id)
    body = to_wire_body(_edit("detectionAction.alertTemplate.recommendedActions", "other actions"))
    intended = rule_compare.diff_rule(body, before).changed
    graph.update_rule(rule_id, body)
    assert rule_compare.unexpected_changes(before, graph.rule(rule_id), intended) == []


def test_the_mirrored_keys_of_an_intended_change_are_expected() -> None:
    """Sending new tactics also changes ``category`` and
    ``mitreTechniques`` in what the tenant returns; a new frequency also
    changes ``period`` and the derived ``lookback``."""
    graph = FakeGraph(rules=[_tenant(current_payload())])
    rule_id = graph.all_rules()[0]["id"]
    before = graph.rule(rule_id)
    payload = _edit("detectionAction.alertTemplate.tactics", [{"tactic": "Execution", "techniques": []}])
    payload["schedule"] = {"frequency": "PT3H"}
    body = to_wire_body(payload)
    intended = rule_compare.diff_rule(body, before).changed
    graph.update_rule(rule_id, body)
    assert rule_compare.unexpected_changes(before, graph.rule(rule_id), intended) == []


def test_a_lost_scope_is_named() -> None:
    graph = FakeGraph(rules=[_tenant(current_payload())], lose_scope_on_patch=True)
    rule_id = graph.all_rules()[0]["id"]
    before = graph.rule(rule_id)
    payload = _edit("detectionAction.alertTemplate.recommendedActions", "other actions")
    del payload["detectionAction"]["organizationalScope"]
    body = to_wire_body(payload)
    intended = rule_compare.diff_rule(body, before).changed
    graph.update_rule(rule_id, body)
    unexpected = rule_compare.unexpected_changes(before, graph.rule(rule_id), intended)
    assert "detectionAction.organizationalScope.deviceGroups" in unexpected
    assert "detectionAction.organizationalScope.scopeNames" in unexpected


def test_a_lost_action_is_named() -> None:
    graph = FakeGraph(rules=[_tenant(current_payload())], lose_actions_on_patch=True)
    rule_id = graph.all_rules()[0]["id"]
    before = graph.rule(rule_id)
    payload = _edit("detectionAction.alertTemplate.recommendedActions", "other actions")
    del payload["detectionAction"]["automatedActions"]
    body = to_wire_body(payload)
    intended = rule_compare.diff_rule(body, before).changed
    graph.update_rule(rule_id, body)
    unexpected = rule_compare.unexpected_changes(before, graph.rule(rule_id), intended)
    assert unexpected == ["detectionAction.automatedActions", "detectionAction.responseActions"]


# --- the real files --------------------------------------------------------


@pytest.mark.parametrize("path", REAL_FILES, ids=lambda p: p.stem)
def test_a_real_file_equals_itself_as_the_tenant_would_return_it(path: Path) -> None:
    """Every Defender file in this repository was written from what the
    tenant returned. Compared against that same content it must show no
    difference: neither as it is on disk, nor reduced to new keys only."""
    payload = (yaml.safe_load(path.read_text(encoding="utf-8")) or {}).get("payload") or {}
    for local in (payload, to_current_shape(payload)):
        diff = rule_compare.diff_rule(to_wire_body(local), copy.deepcopy(payload))
        assert diff.changed == ()
        assert diff.not_cleared == ()
