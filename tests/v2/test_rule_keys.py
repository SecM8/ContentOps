# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Rule identity keys: how repo detections are found in workspace telemetry.

Regression tests for the review finding that telemetry was joined to
rules by display name only, so a rule using ``alertDisplayNameFormat``
(or a renamed incident) looked silent.
"""

from __future__ import annotations

import pytest

from contentops.core.asset import Asset
from contentops.rule_keys import (
    RuleKeys,
    TelemetryIndex,
    normalise_rule_id,
    normalise_rule_name,
    rule_keys,
    rule_keys_from_raw,
)

WS = "0b3c1f2e-1111-4a2b-9c3d-abcdefabcdef"


@pytest.mark.parametrize("value, expected", [
    ("Brute-Force", "brute-force"),
    (f"{WS}_Brute-Force", "brute-force"),
    (f"{WS.upper()}_6BABF568-0000-4000-8000-000000000001",
     "6babf568-0000-4000-8000-000000000001"),
    ("/subscriptions/s/resourceGroups/rg/providers/Microsoft.OperationalInsights/"
     "workspaces/w/providers/Microsoft.SecurityInsights/alertRules/abc-123", "abc-123"),
    ("/subscriptions/s/.../alertRules/abc-123/", "abc-123"),
    # A rule name that itself contains "_" keeps it (only a GUID prefix is stripped).
    ("my_rule_v2", "my_rule_v2"),
    (f"{WS}_my_rule_v2", "my_rule_v2"),
    ("  padded  ", "padded"),
    ("", None),
    ("   ", None),
    (None, None),
    (42, None),
])
def test_normalise_rule_id(value, expected) -> None:
    assert normalise_rule_id(value) == expected


def test_normalise_rule_name() -> None:
    assert normalise_rule_name("  Brute Force From {{IP}} ") == "brute force from {{ip}}"
    assert normalise_rule_name("") is None
    assert normalise_rule_name(None) is None


def test_sentinel_rule_is_keyed_by_the_name_it_deploys_under() -> None:
    authored = rule_keys(
        Asset.SENTINEL_ANALYTIC, envelope_id="brute-force", arm_name=None,
        payload={"displayName": "Brute Force"},
    )
    assert authored == RuleKeys(ids=("brute-force",), names=("brute force",))
    collected = rule_keys(
        Asset.SENTINEL_ANALYTIC, envelope_id="brute-force",
        arm_name="6BABF568-0000-4000-8000-000000000001",
        payload={"displayName": "Brute Force"},
    )
    # The handler deploys to metadata.arm_name when set, so that is the id.
    assert collected.ids == ("6babf568-0000-4000-8000-000000000001",)
    assert collected.candidates() == (
        "id:6babf568-0000-4000-8000-000000000001", "name:brute force",
    )


def test_defender_rule_also_answers_to_its_alert_title() -> None:
    keys = rule_keys(
        "defender_custom_detection", envelope_id="lsass-dump", arm_name="18210",
        payload={
            "displayName": "LSASS dump",
            "detectionAction": {"alertTemplate": {"title": "Credential dumping via LSASS"}},
        },
    )
    assert keys.names == ("lsass dump", "credential dumping via lsass")
    same = rule_keys(
        "defender_custom_detection", envelope_id="x", arm_name=None,
        payload={"displayName": "Same", "detectionAction": {"alertTemplate": {"title": "same"}}},
    )
    assert same.names == ("same",)


def test_rule_keys_from_raw_tolerates_missing_fields() -> None:
    assert rule_keys_from_raw({}) == RuleKeys()
    assert rule_keys_from_raw({"metadata": "bad", "payload": None, "id": 3}) == RuleKeys()
    keys = rule_keys_from_raw({
        "id": "r1", "asset": "sentinel_analytic",
        "metadata": {"arm_name": "GUID-1"}, "payload": {"displayName": "R One"},
    })
    assert keys == RuleKeys(ids=("guid-1",), names=("r one",))


def test_candidates_round_trip() -> None:
    keys = RuleKeys(ids=("a", "b"), names=("x",))
    assert RuleKeys.from_candidates(keys.candidates()) == keys


def test_index_sums_a_rules_id_and_name_rows() -> None:
    """A rule's telemetry can be split across keys: alerts under its rule
    id, an incident without RelatedAnalyticRuleIds under its title. The
    KQL puts each alert / incident in one row, so the rows are summed."""
    by_id = {"rule_key": "id:brute-force", "rule_name": "Brute Force from 10.0.0.1",
             "alerts_30d": 12, "incidents_30d": 2, "closed_tp_30d": 1}
    by_name = {"rule_key": "name:brute force", "rule_name": "Brute Force",
               "alerts_30d": 0, "incidents_30d": 1, "closed_fp_30d": 1}
    keys = RuleKeys(ids=("brute-force",), names=("brute force",))
    index = TelemetryIndex([by_name, by_id])
    assert index.rows_for(keys) == [by_id, by_name]
    merged = index.lookup(keys)
    assert (merged["alerts_30d"], merged["incidents_30d"]) == (12, 3)
    assert (merged["closed_tp_30d"], merged["closed_fp_30d"]) == (1, 1)
    assert merged["rule_keys"] == ["id:brute-force", "name:brute force"]
    # Only a name row (the old behaviour) still matches.
    assert TelemetryIndex([by_name]).lookup(keys)["incidents_30d"] == 1


def test_incident_only_id_row_does_not_hide_alerts_under_the_name() -> None:
    """Review of #395: taking the first match returned the incident-only id
    row (zero alerts), so a firing rule looked silent and took the silence
    penalty. Summing keeps the alerts."""
    incidents_only = {"rule_key": "id:r1", "rule_name": "Rule One",
                      "alerts_30d": 0, "incidents_30d": 2}
    alerts = {"rule_key": "name:rule one", "rule_name": "Rule One",
              "alerts_30d": 7, "incidents_30d": 0}
    merged = TelemetryIndex([incidents_only, alerts]).lookup(
        RuleKeys(ids=("r1",), names=("rule one",)),
    )
    assert (merged["alerts_30d"], merged["incidents_30d"]) == (7, 2)


def test_defender_rule_sums_its_display_name_and_alert_title_rows() -> None:
    title_row = {"rule_key": "name:credential dumping via lsass", "alerts_30d": 4}
    display_row = {"rule_key": "name:lsass dump", "alerts_30d": 0, "incidents_30d": 3}
    keys = RuleKeys(ids=("18210",), names=("lsass dump", "credential dumping via lsass"))
    merged = TelemetryIndex([title_row, display_row]).lookup(keys)
    assert (merged["alerts_30d"], merged["incidents_30d"]) == (4, 3)


def test_a_row_reached_through_two_keys_counts_once() -> None:
    row = {"rule_name": "Same", "alerts_30d": 5}
    index = TelemetryIndex([row])
    keys = RuleKeys(names=("same", "same"))
    assert index.rows_for(keys) == [row]
    assert index.lookup(keys)["alerts_30d"] == 5


def test_index_falls_back_to_the_name_of_an_id_row() -> None:
    """A rule whose id the telemetry doesn't carry as the repo expects still
    matches by the alert name, as before rule keys existed -- but only when
    none of its own rows exist."""
    row = {"rule_key": "id:some-guid", "rule_name": "Brute Force", "alerts_30d": 3}
    keys = RuleKeys(ids=("brute-force",), names=("brute force",))
    assert TelemetryIndex([row]).lookup(keys)["alerts_30d"] == 3
    own = {"rule_key": "id:brute-force", "rule_name": "x", "alerts_30d": 1}
    assert TelemetryIndex([row, own]).rows_for(keys) == [own]


def test_merge_keeps_absent_columns_absent() -> None:
    """A count no row carries stays absent, so 'unknown' isn't turned into 0."""
    merged = TelemetryIndex([{"rule_name": "X", "alerts_30d": 2}]).lookup(
        RuleKeys(names=("x",)),
    )
    assert merged["alerts_30d"] == 2
    assert "closed_tp_30d" not in merged


def test_index_accepts_rows_without_a_rule_key() -> None:
    row = {"rule_name": "  Failed Logins ", "alerts_30d": 5}
    assert TelemetryIndex([row]).lookup(RuleKeys(names=("failed logins",)))["alerts_30d"] == 5
    assert TelemetryIndex([row]).lookup(RuleKeys(ids=("failed-logins",))) is None
    assert TelemetryIndex([]).lookup(RuleKeys(ids=("x",), names=("y",))) is None
