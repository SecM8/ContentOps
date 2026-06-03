# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for RuleMetadata (M1)."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from contentops.core.metadata import RuleMetadata


def _base() -> dict:
    return {
        "owner": "blue-team@contoso.com",
        "runbookUrl": "https://wiki/runbooks/x",
        "severity": "high",
        "tactics": ["InitialAccess", "Execution"],
        "techniques": ["T1059.001", "T1059"],
        "expectedAlertsPerDay": 5,
        "fpHandling": "Known FP: domain-joined service accounts.\nSuppress via watchlist.",
    }


def test_valid_metadata_parses() -> None:
    m = RuleMetadata(**_base())
    assert m.severity == "high"
    assert m.tactics == ["InitialAccess", "Execution"]
    assert m.techniques == ["T1059.001", "T1059"]
    assert m.expectedAlertsPerDay == 5


def test_techniques_default_empty() -> None:
    data = _base()
    del data["techniques"]
    m = RuleMetadata(**data)
    assert m.techniques == []


@pytest.mark.parametrize(
    "missing",
    ["owner", "runbookUrl", "severity", "tactics", "expectedAlertsPerDay", "fpHandling"],
)
def test_required_field_missing(missing: str) -> None:
    data = _base()
    del data[missing]
    with pytest.raises(ValidationError):
        RuleMetadata(**data)


def test_invalid_severity_rejected() -> None:
    data = _base()
    data["severity"] = "critical"
    with pytest.raises(ValidationError):
        RuleMetadata(**data)


def test_empty_tactics_rejected() -> None:
    data = _base()
    data["tactics"] = []
    with pytest.raises(ValidationError):
        RuleMetadata(**data)


def test_invalid_tactic_rejected() -> None:
    data = _base()
    data["tactics"] = ["NotARealTactic"]
    with pytest.raises(ValidationError):
        RuleMetadata(**data)


@pytest.mark.parametrize("bad", ["T123", "T12345", "1059", "T1059.1", "T1059.0001"])
def test_invalid_technique_format(bad: str) -> None:
    data = _base()
    data["techniques"] = [bad]
    with pytest.raises(ValidationError):
        RuleMetadata(**data)


@pytest.mark.parametrize("url", ["wiki/runbooks/x", "ftp://wiki/x", "/runbooks/x", ""])
def test_runbook_requires_http(url: str) -> None:
    data = _base()
    data["runbookUrl"] = url
    with pytest.raises(ValidationError):
        RuleMetadata(**data)


def test_expected_alerts_must_be_non_negative() -> None:
    data = _base()
    data["expectedAlertsPerDay"] = -1
    with pytest.raises(ValidationError):
        RuleMetadata(**data)


def test_expected_alerts_zero_allowed() -> None:
    data = _base()
    data["expectedAlertsPerDay"] = 0
    assert RuleMetadata(**data).expectedAlertsPerDay == 0


def test_fp_handling_blank_rejected() -> None:
    data = _base()
    data["fpHandling"] = "   \n  "
    with pytest.raises(ValidationError):
        RuleMetadata(**data)


def test_owner_must_look_like_email() -> None:
    data = _base()
    data["owner"] = "not-an-email"
    with pytest.raises(ValidationError):
        RuleMetadata(**data)
