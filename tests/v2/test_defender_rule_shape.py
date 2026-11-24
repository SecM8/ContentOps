# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""``contentops.defender.rule_shape``: one source key per old/new pair.

Graph deprecates ``period``, ``category``, ``mitreTechniques``,
``impactedAssets``, ``responseActions`` and ``scopeType`` / ``scopeNames``
in favour of ``frequency``, ``tactics``, ``entityMappings``,
``automatedActions`` and ``deviceGroups``. For each pair the pipeline
uses exactly one of the two keys:

* the new key when it has content;
* the old key when the new key has no content and the old one has, so a
  filled value is never dropped in favour of an empty one;
* otherwise the (empty) new key when it is in the payload, else the old
  key as written.
"""

from __future__ import annotations

import copy
from pathlib import Path

import pytest
import yaml

from contentops.defender import rule_shape
from contentops.defender.rule_shape import (
    entity_columns,
    legacy_keys,
    tactic_names,
    technique_ids,
    to_current_shape,
)
from contentops.models import validate_defender_payload
from tests.v2.defender_shapes import current_payload, legacy_only_payload, two_shape_payload

REPO_ROOT = Path(__file__).resolve().parents[2]
_OLD_PATHS = (
    ("schedule", "period"),
    ("detectionAction", "alertTemplate", "category"),
    ("detectionAction", "alertTemplate", "mitreTechniques"),
    ("detectionAction", "alertTemplate", "impactedAssets"),
    ("detectionAction", "responseActions"),
    ("detectionAction", "organizationalScope", "scopeType"),
    ("detectionAction", "organizationalScope", "scopeNames"),
)


def _has(payload: dict, path: tuple[str, ...]) -> bool:
    node = payload
    for key in path:
        if not isinstance(node, dict) or key not in node:
            return False
        node = node[key]
    return True


def _template(payload: dict) -> dict:
    return payload["detectionAction"]["alertTemplate"]


# -- whole payloads -----------------------------------------------------


def test_two_shape_payload_loses_every_old_key() -> None:
    out = to_current_shape(two_shape_payload())
    assert [path for path in _OLD_PATHS if _has(out, path)] == []


def test_two_shape_payload_keeps_every_new_value() -> None:
    before = two_shape_payload()
    out = to_current_shape(before)
    assert out["schedule"] == {"frequency": "PT1H", "lookback": "PT4H"}
    assert _template(out)["tactics"] == _template(before)["tactics"]
    assert _template(out)["entityMappings"] == _template(before)["entityMappings"]
    assert out["detectionAction"]["automatedActions"] == before["detectionAction"]["automatedActions"]
    assert out["detectionAction"]["organizationalScope"] == {"deviceGroups": ["group-a", "group-b"]}


def test_payload_with_new_keys_only_is_unchanged() -> None:
    payload = current_payload()
    assert to_current_shape(payload) == payload


def test_payload_with_old_keys_only_is_unchanged() -> None:
    payload = legacy_only_payload()
    assert to_current_shape(payload) == payload


def test_input_is_not_changed() -> None:
    payload = two_shape_payload()
    snapshot = copy.deepcopy(payload)
    to_current_shape(payload)
    assert payload == snapshot


def test_result_shares_nothing_with_the_input() -> None:
    payload = two_shape_payload()
    out = to_current_shape(payload)
    _template(out)["tactics"].append({"tactic": "X", "techniques": []})
    out["schedule"]["frequency"] = "P1D"
    assert payload == two_shape_payload()


def test_applying_it_twice_changes_nothing_more() -> None:
    once = to_current_shape(two_shape_payload())
    assert to_current_shape(once) == once


# -- schedule -----------------------------------------------------------


@pytest.mark.parametrize(
    ("schedule", "expected"),
    [
        ({"period": "1H", "frequency": "PT1H"}, {"frequency": "PT1H"}),
        ({"period": "3H", "frequency": "PT1H"}, {"frequency": "PT1H"}),
        ({"period": "1H", "frequency": ""}, {"period": "1H"}),
        ({"period": "1H", "frequency": None}, {"period": "1H"}),
        ({"period": "1H"}, {"period": "1H"}),
        ({"period": "0"}, {"period": "0"}),
        ({"period": "0", "frequency": "PT0S", "lookback": None}, {"frequency": "PT0S", "lookback": None}),
        ({"frequency": "PT1H", "lookback": "PT4H"}, {"frequency": "PT1H", "lookback": "PT4H"}),
    ],
)
def test_schedule_keeps_one_source(schedule, expected) -> None:
    out = to_current_shape(current_payload(schedule=schedule))
    assert out["schedule"] == expected


# -- tactics and techniques ----------------------------------------------


def _with_template(**keys) -> dict:
    payload = current_payload()
    template = _template(payload)
    for name in ("tactics", "category", "mitreTechniques", "entityMappings", "impactedAssets"):
        template.pop(name, None)
    template.update(keys)
    if "entityMappings" not in keys and "impactedAssets" not in keys:
        template["entityMappings"] = {"hosts": [{"deviceIdColumn": "DeviceId"}]}
    return payload


_TACTIC_WITH_TECHNIQUE = [{"tactic": "Discovery", "techniques": [{"technique": "T1083", "subTechniques": []}]}]
_TACTIC_WITHOUT_TECHNIQUE = [{"tactic": "Discovery", "techniques": []}]


@pytest.mark.parametrize(
    ("keys", "kept", "dropped"),
    [
        # new key has content -> new key
        ({"tactics": _TACTIC_WITH_TECHNIQUE, "category": "Discovery", "mitreTechniques": ["T1083"]},
         {"tactics"}, {"category", "mitreTechniques"}),
        ({"tactics": _TACTIC_WITHOUT_TECHNIQUE, "category": "Discovery", "mitreTechniques": []},
         {"tactics"}, {"category", "mitreTechniques"}),
        ({"tactics": _TACTIC_WITHOUT_TECHNIQUE}, {"tactics"}, set()),
        # techniques only in the old key -> the filled old keys win
        ({"tactics": _TACTIC_WITHOUT_TECHNIQUE, "category": "Discovery", "mitreTechniques": ["T1083", "T1082"]},
         {"category", "mitreTechniques"}, {"tactics"}),
        ({"tactics": [], "category": "Discovery", "mitreTechniques": []},
         {"category", "mitreTechniques"}, {"tactics"}),
        ({"category": "Discovery", "mitreTechniques": ["T1083"]}, {"category", "mitreTechniques"}, set()),
        # both empty: the empty new key, when it is there
        ({"tactics": [], "category": None, "mitreTechniques": []}, {"tactics"}, {"category", "mitreTechniques"}),
        ({"category": None, "mitreTechniques": []}, {"category", "mitreTechniques"}, set()),
    ],
)
def test_tactics_keep_one_source(keys, kept, dropped) -> None:
    template = _template(to_current_shape(_with_template(**keys)))
    assert kept <= set(template)
    assert not dropped & set(template)


# -- entities -----------------------------------------------------------

_ASSET = [{"@odata.type": "#microsoft.graph.security.impactedDeviceAsset", "identifier": "deviceId"}]
_EMPTY_MAPPINGS = {"hosts": [{"deviceIdColumn": "", "nameColumn": ""}], "accounts": []}
_FILLED_MAPPINGS = {"hosts": [{"deviceIdColumn": "DeviceId", "nameColumn": ""}], "accounts": []}


@pytest.mark.parametrize(
    ("keys", "kept", "dropped"),
    [
        ({"entityMappings": _FILLED_MAPPINGS, "impactedAssets": _ASSET}, {"entityMappings"}, {"impactedAssets"}),
        ({"entityMappings": _FILLED_MAPPINGS, "impactedAssets": []}, {"entityMappings"}, {"impactedAssets"}),
        ({"entityMappings": _EMPTY_MAPPINGS, "impactedAssets": _ASSET}, {"impactedAssets"}, {"entityMappings"}),
        ({"entityMappings": None, "impactedAssets": _ASSET}, {"impactedAssets"}, {"entityMappings"}),
        ({"impactedAssets": _ASSET}, {"impactedAssets"}, set()),
        ({"entityMappings": _EMPTY_MAPPINGS, "impactedAssets": []}, {"entityMappings"}, {"impactedAssets"}),
    ],
)
def test_entities_keep_one_source(keys, kept, dropped) -> None:
    template = _template(to_current_shape(_with_template(**keys)))
    assert kept <= set(template)
    assert not dropped & set(template)


# -- automated actions --------------------------------------------------

_OLD_ACTION = [{"@odata.type": "#microsoft.graph.security.runAntivirusScanResponseAction", "identifier": "deviceId"}]
_NEW_ACTION = {"runAntivirusScans": [{"deviceIdColumn": "DeviceId"}], "isolateDevices": []}
_NO_ACTION = {"runAntivirusScans": [], "isolateDevices": []}


@pytest.mark.parametrize(
    ("keys", "kept", "dropped"),
    [
        ({"automatedActions": _NEW_ACTION, "responseActions": _OLD_ACTION}, {"automatedActions"}, {"responseActions"}),
        ({"automatedActions": _NO_ACTION, "responseActions": _OLD_ACTION}, {"responseActions"}, {"automatedActions"}),
        ({"automatedActions": _NO_ACTION, "responseActions": []}, {"automatedActions"}, {"responseActions"}),
        ({"responseActions": []}, {"responseActions"}, set()),
        ({"responseActions": _OLD_ACTION}, {"responseActions"}, set()),
        ({"automatedActions": _NEW_ACTION}, {"automatedActions"}, set()),
    ],
)
def test_actions_keep_one_source(keys, kept, dropped) -> None:
    payload = current_payload()
    action = payload["detectionAction"]
    action.pop("automatedActions", None)
    action.update(copy.deepcopy(keys))
    out = to_current_shape(payload)["detectionAction"]
    assert kept <= set(out)
    assert not dropped & set(out)


# -- scope ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("scope", "expected"),
    [
        ({"scopeType": "deviceGroup", "scopeNames": ["a"], "deviceGroups": ["a"]}, {"deviceGroups": ["a"]}),
        ({"scopeType": "deviceGroup", "scopeNames": ["a"], "deviceGroups": ["b"]}, {"deviceGroups": ["b"]}),
        # an empty new key never removes a filled scope
        ({"scopeType": "deviceGroup", "scopeNames": ["a"], "deviceGroups": []},
         {"scopeType": "deviceGroup", "scopeNames": ["a"]}),
        ({"scopeType": "deviceGroup", "scopeNames": ["a"]}, {"scopeType": "deviceGroup", "scopeNames": ["a"]}),
        ({"scopeType": "deviceGroup", "scopeNames": [], "deviceGroups": []}, {"deviceGroups": []}),
        ({"scopeType": "deviceGroup", "scopeNames": []}, {"scopeType": "deviceGroup", "scopeNames": []}),
        ({"deviceGroups": ["a"]}, {"deviceGroups": ["a"]}),
        (None, None),
    ],
)
def test_scope_keeps_one_source(scope, expected) -> None:
    payload = current_payload()
    payload["detectionAction"]["organizationalScope"] = copy.deepcopy(scope)
    assert to_current_shape(payload)["detectionAction"]["organizationalScope"] == expected


# -- enabled state ---------------------------------------------------------


def test_is_enabled_is_dropped_when_status_is_there() -> None:
    out = to_current_shape(current_payload(isEnabled=True))
    assert "isEnabled" not in out and out["status"] == "enabled"


def test_is_enabled_stays_when_it_is_the_only_state() -> None:
    payload = current_payload(isEnabled=False)
    del payload["status"]
    assert to_current_shape(payload)["isEnabled"] is False


# -- what passes validation today still passes ------------------------------


def _valid_today() -> list[dict]:
    mixed_entities = _with_template(entityMappings=_EMPTY_MAPPINGS, impactedAssets=_ASSET)
    # null means "not set". (A blank string is a value and is rejected by
    # the validator before any projection matters.)
    null_frequency = current_payload(schedule={"period": "1H", "frequency": None})
    return [two_shape_payload(), current_payload(), legacy_only_payload(), mixed_entities, null_frequency]


@pytest.mark.parametrize("payload", _valid_today(), ids=["two-shape", "new-only", "old-only", "old-entity", "null-frequency"])
def test_a_payload_that_validates_today_still_validates(payload) -> None:
    validate_defender_payload(payload)
    validate_defender_payload(to_current_shape(payload))


def _repository_defender_files() -> list[Path]:
    return sorted((REPO_ROOT / "detections" / "defender_custom_detection").glob("*.yml"))


@pytest.mark.parametrize("path", _repository_defender_files(), ids=lambda p: p.stem[:40])
def test_every_defender_file_in_this_repository_projects_cleanly(path: Path) -> None:
    """Whatever Defender rules this repository holds: the projected
    payload validates, and an old key survives only where its new key has
    no content."""
    payload = (yaml.safe_load(path.read_text(encoding="utf-8")) or {}).get("payload") or {}
    validate_defender_payload(payload)
    out = to_current_shape(payload)
    validate_defender_payload(out)
    sent_old = [key.path for key in legacy_keys(payload) if key.sent]
    for path_ in _OLD_PATHS:
        dotted = ".".join(path_)
        assert _has(out, path_) == (dotted in sent_old), dotted


# -- readers ---------------------------------------------------------------


def test_readers_use_the_new_keys() -> None:
    payload = two_shape_payload()
    assert tactic_names(payload) == ["Persistence"]
    assert technique_ids(payload) == ["T1136", "T1136.001"]
    assert entity_columns(payload) == ["DeviceId"]


def test_readers_fall_back_to_the_old_keys() -> None:
    payload = legacy_only_payload()
    assert tactic_names(payload) == ["Persistence"]
    assert technique_ids(payload) == ["T1136", "T1136.001"]
    assert entity_columns(payload) == []


def test_readers_follow_the_source_when_old_and_new_disagree() -> None:
    payload = _with_template(
        tactics=_TACTIC_WITH_TECHNIQUE, category="Persistence", mitreTechniques=["T1136"],
    )
    assert tactic_names(payload) == ["Discovery"]
    assert technique_ids(payload) == ["T1083"]


def test_every_tactic_and_every_technique_is_read() -> None:
    payload = _with_template(tactics=[
        {"tactic": "Persistence", "techniques": [{"technique": "T1098", "subTechniques": ["T1098.007"]}]},
        {"tactic": "SuspiciousActivity", "techniques": [{"technique": "T1059", "subTechniques": []}]},
        {"tactic": "PrivilegeEscalation", "techniques": [{"technique": "T1098", "subTechniques": ["T1098.007"]}]},
    ])
    assert tactic_names(payload) == ["Persistence", "SuspiciousActivity", "PrivilegeEscalation"]
    assert technique_ids(payload) == ["T1098", "T1098.007", "T1059"]


def test_entity_columns_skip_empty_columns_and_keep_order() -> None:
    payload = _with_template(entityMappings={
        "hosts": [{"deviceIdColumn": "DeviceId", "nameColumn": ""}],
        "accounts": [{"sidColumn": "AccountSid", "nameColumn": "AccountName"}],
        "files": [],
    })
    assert entity_columns(payload) == ["DeviceId", "AccountSid", "AccountName"]


def test_entity_columns_leave_out_odata_annotations() -> None:
    """``@odata.type`` names the mapping's type, not a query column."""
    payload = _with_template(entityMappings={
        "hosts": [{
            "@odata.type": "#microsoft.graph.security.hostEntityMapping",
            "deviceIdColumn": "DeviceId", "nameColumn": "",
        }],
    })
    assert entity_columns(payload) == ["DeviceId"]


def test_readers_tolerate_a_payload_without_detection_action() -> None:
    assert tactic_names({}) == []
    assert technique_ids({"detectionAction": None}) == []
    assert entity_columns({"detectionAction": {"alertTemplate": None}}) == []


# -- old keys, for lint ------------------------------------------------------


def test_legacy_keys_of_a_two_shape_payload_are_all_ignored_and_agree() -> None:
    keys = legacy_keys(two_shape_payload())
    assert {key.path for key in keys} == {".".join(path) for path in _OLD_PATHS}
    assert not [key.path for key in keys if key.sent]
    assert not [key.path for key in keys if key.differs]


def test_legacy_keys_of_an_old_only_payload_are_all_sent() -> None:
    keys = legacy_keys(legacy_only_payload())
    assert keys and all(key.sent for key in keys)


def test_legacy_keys_report_none_for_new_keys_only() -> None:
    assert legacy_keys(current_payload()) == []


@pytest.mark.parametrize(
    ("change", "path"),
    [
        (lambda p: p["schedule"].__setitem__("period", "3H"), "schedule.period"),
        (lambda p: _template(p).__setitem__("category", "Discovery"), "detectionAction.alertTemplate.category"),
        (lambda p: _template(p).__setitem__("mitreTechniques", ["T1083"]),
         "detectionAction.alertTemplate.mitreTechniques"),
        (lambda p: p["detectionAction"]["organizationalScope"].__setitem__("scopeNames", ["group-z"]),
         "detectionAction.organizationalScope.scopeNames"),
    ],
)
def test_legacy_keys_flag_an_old_value_that_differs_from_the_new_one(change, path) -> None:
    payload = two_shape_payload()
    change(payload)
    flagged = [key.path for key in legacy_keys(payload) if key.differs]
    assert flagged == [path]


def test_legacy_keys_include_is_enabled_next_to_status() -> None:
    keys = legacy_keys(current_payload(isEnabled=True))
    assert [(key.path, key.sent) for key in keys] == [("isEnabled", False)]


def test_module_names_every_pair() -> None:
    assert {pair.name for pair in rule_shape.PAIRS} == {"schedule", "tactics", "entities", "actions", "scope"}
