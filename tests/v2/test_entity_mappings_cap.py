# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Test for the entityMappings cap on Sentinel scheduled / NRT payloads.

Background: prior to 2026-05-18 the cap was 5 (matching an old MS doc
page). An adopter test surfaced a real production-deployed rule
with 6 entries — Sentinel had accepted the deploy, but our validator
rejected it on collect-back, blocking the chore(collect): PR. The
2025-07-01-preview ARM contract allows up to 10 entries. Bumped the
cap accordingly. Pin both the allow-up-to-10 behaviour and the
reject-at-11 boundary so a future field rename or refactor can't
silently re-tighten the limit.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from contentops.models import (
    SentinelNRTPayload,
    SentinelScheduledPayload,
)


def _mapping() -> dict:
    """Minimal valid EntityMapping shape."""
    return {
        "entityType": "Account",
        "fieldMappings": [{"identifier": "Name", "columnName": "User"}],
    }


def _scheduled_payload(n_mappings: int) -> dict:
    """Minimal valid SentinelScheduledPayload with n entityMappings entries."""
    return {
        "kind": "Scheduled",
        "displayName": "test",
        "severity": "Medium",
        "query": "SecurityEvent | take 1",
        "queryFrequency": "PT5M",
        "queryPeriod": "PT5M",
        "triggerOperator": "GreaterThan",
        "triggerThreshold": 0,
        "entityMappings": [_mapping() for _ in range(n_mappings)],
    }


def _nrt_payload(n_mappings: int) -> dict:
    """Minimal valid SentinelNRTPayload with n entityMappings entries."""
    return {
        "kind": "NRT",
        "displayName": "test",
        "severity": "Medium",
        "query": "SecurityEvent | take 1",
        "entityMappings": [_mapping() for _ in range(n_mappings)],
    }


@pytest.mark.parametrize("n", [0, 1, 5, 6, 10])
def test_scheduled_accepts_up_to_ten_entity_mappings(n: int) -> None:
    """Cap is 10, not the old 5. An adopter's deployed 6-mapping rule
    surfaced the discrepancy."""
    SentinelScheduledPayload(**_scheduled_payload(n))


def test_scheduled_rejects_eleven_entity_mappings() -> None:
    """Boundary: 11 entries is over the cap."""
    with pytest.raises(ValidationError) as excinfo:
        SentinelScheduledPayload(**_scheduled_payload(11))
    msg = str(excinfo.value)
    assert "entityMappings" in msg
    assert "at most 10" in msg


@pytest.mark.parametrize("n", [0, 1, 5, 6, 10])
def test_nrt_accepts_up_to_ten_entity_mappings(n: int) -> None:
    """Same cap applies to NRT rules — both payload schemas had the
    old max_length=5."""
    SentinelNRTPayload(**_nrt_payload(n))


def test_nrt_rejects_eleven_entity_mappings() -> None:
    with pytest.raises(ValidationError) as excinfo:
        SentinelNRTPayload(**_nrt_payload(11))
    assert "at most 10" in str(excinfo.value)
