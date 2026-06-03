# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for SentinelHuntingPayload + ARM body builder."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from contentops.handlers.sentinel_hunting_models import (
    HUNTING_CATEGORY,
    SentinelHuntingPayload,
    to_savedsearch_arm_body,
)


def _payload(**overrides):
    base = {
        "displayName": "Test hunt",
        "query": "DeviceProcessEvents | take 10",
    }
    base.update(overrides)
    return base


def test_minimal_hunting_query_validates() -> None:
    p = SentinelHuntingPayload(**_payload())
    assert p.category == HUNTING_CATEGORY
    assert p.version == 2


def test_non_hunting_category_rejected() -> None:
    with pytest.raises(ValidationError):
        SentinelHuntingPayload(**_payload(category="Saved Searches"))


def test_empty_query_rejected() -> None:
    with pytest.raises(ValidationError):
        SentinelHuntingPayload(**_payload(query=""))


def test_arm_body_minimal_shape() -> None:
    body = to_savedsearch_arm_body(_payload())
    assert "properties" in body
    props = body["properties"]
    assert props["category"] == HUNTING_CATEGORY
    assert props["displayName"] == "Test hunt"
    assert props["query"].startswith("DeviceProcessEvents")
    assert props["version"] == 2
    # No tags when description/tactics absent.
    assert "tags" not in props


def test_arm_body_encodes_metadata_as_tags() -> None:
    body = to_savedsearch_arm_body(_payload(
        description="Hunts for X",
        tactics=["Execution", "DefenseEvasion"],
        techniques=["T1059.001"],
        tags=[{"name": "owner", "value": "blue-team"}],
    ))
    tags = body["properties"]["tags"]
    by_name = {t["name"]: t["value"] for t in tags}
    assert by_name["description"] == "Hunts for X"
    assert by_name["tactics"] == "Execution,DefenseEvasion"
    assert by_name["techniques"] == "T1059.001"
    assert by_name["owner"] == "blue-team"


def test_arm_body_includes_function_alias_when_set() -> None:
    body = to_savedsearch_arm_body(_payload(
        functionAlias="MyHunt",
        functionParameters="lookback:timespan = 7d",
    ))
    props = body["properties"]
    assert props["functionAlias"] == "MyHunt"
    assert props["functionParameters"] == "lookback:timespan = 7d"
