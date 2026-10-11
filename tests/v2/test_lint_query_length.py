# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""KQL009 (query-length advisory) and the removal of the hard query cap.

Background: the payload models used to reject any Sentinel ``query`` or
Defender ``queryText`` longer than 10,000 characters, the figure
Microsoft documents for Sentinel analytics rules. Rules collected back
from live tenants exceed it -- the ARM / Graph APIs accept and run them
-- so the cap turned a deployment fork's first ``collect`` snapshot into
a ``plan`` that exited 1 for the whole tree. The cap is now the
warning-severity lint rule KQL009 and the models accept any non-empty
query. Pin both halves so a refactor cannot silently re-tighten the
models or downgrade the advisory.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from contentops.lint.kql import QUERY_LENGTH_ADVISORY, at_or_above, lint_kql
from contentops.models import (
    DefenderQueryCondition,
    SentinelNRTPayload,
    SentinelScheduledPayload,
)


def _query_of_length(n: int) -> str:
    """A query of exactly ``n`` characters that trips no other rule."""
    head = "T\n// "
    assert n >= len(head)
    return head + "x" * (n - len(head))


def _kql009(findings):
    return [f for f in findings if f.rule_id == "KQL009"]


# ---------------------------------------------------------------------------
# KQL009
# ---------------------------------------------------------------------------


def test_kql009_silent_at_the_advisory_threshold() -> None:
    q = _query_of_length(QUERY_LENGTH_ADVISORY)
    assert len(q) == 10_000
    assert _kql009(lint_kql(q, kind="sentinel_analytic")) == []


def test_kql009_fires_one_character_above_the_threshold() -> None:
    q = _query_of_length(QUERY_LENGTH_ADVISORY + 1)
    found = _kql009(lint_kql(q, kind="sentinel_analytic"))
    assert len(found) == 1
    f = found[0]
    assert f.severity == "warning"
    assert f.line == 1
    assert "10,001" in f.message
    assert "watchlist" in f.message


def test_kql009_only_finding_on_an_otherwise_clean_long_query() -> None:
    q = _query_of_length(QUERY_LENGTH_ADVISORY + 500)
    assert [f.rule_id for f in lint_kql(q, kind="sentinel_analytic")] == ["KQL009"]


@pytest.mark.parametrize("kind", ["sentinel_analytic", "sentinel_hunting", None])
def test_kql009_sentinel_message_cites_the_documented_limit(kind) -> None:
    f = _kql009(lint_kql(_query_of_length(12_000), kind=kind))[0]
    assert "Sentinel" in f.message
    assert "10,000" in f.message


def test_kql009_defender_message_is_advisory() -> None:
    f = _kql009(lint_kql(_query_of_length(12_000), kind="defender_custom_detection"))[0]
    assert "Defender" in f.message
    assert "advisory" in f.message


def test_kql009_does_not_reach_the_error_threshold() -> None:
    """The default ``validate`` gate fails on errors only; a warning must
    not block a PR."""
    findings = lint_kql(_query_of_length(12_000), kind="sentinel_analytic")
    assert _kql009(findings)
    assert at_or_above(findings, "error") == []


# ---------------------------------------------------------------------------
# Models: no hard cap, non-empty still enforced for Sentinel
# ---------------------------------------------------------------------------


def _scheduled(query: str) -> dict:
    return {
        "kind": "Scheduled",
        "displayName": "test",
        "severity": "Medium",
        "query": query,
        "queryFrequency": "PT5M",
        "queryPeriod": "PT5M",
        "triggerOperator": "GreaterThan",
        "triggerThreshold": 0,
    }


def _nrt(query: str) -> dict:
    return {
        "kind": "NRT",
        "displayName": "test",
        "severity": "Medium",
        "query": query,
    }


@pytest.mark.parametrize("length", [10_001, 12_000, 40_000])
def test_models_accept_queries_longer_than_the_old_cap(length: int) -> None:
    q = _query_of_length(length)
    assert SentinelScheduledPayload.model_validate(_scheduled(q)).query == q
    assert SentinelNRTPayload.model_validate(_nrt(q)).query == q
    assert DefenderQueryCondition.model_validate({"queryText": q}).queryText == q


def test_models_still_reject_an_empty_sentinel_query() -> None:
    with pytest.raises(ValidationError):
        SentinelScheduledPayload.model_validate(_scheduled(""))
    with pytest.raises(ValidationError):
        SentinelNRTPayload.model_validate(_nrt(""))
