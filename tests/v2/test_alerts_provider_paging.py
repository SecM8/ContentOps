# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Time-sliced alerts_v2 pagination (``list_graph_alerts_windowed``).

Regression coverage for the backfill truncation bug: alerts_v2's
``@odata.nextLink`` silently stops after the first ``$top`` page, so a
single wide-window pull returned only ``PAGE_SIZE`` records (in the field:
500 alerts for a 30-day backfill, all on day one). The fix paginates by
time instead — these tests drive the adaptive-halving against a fake
single-page fetch that reproduces the API's per-window cap.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from contentops.alerts.provider import GRAPH_ALERTS_PAGE_SIZE, GraphAlertsProvider


def _provider_over(store: list[dict]) -> GraphAlertsProvider:
    """A provider whose single-page fetch serves ``store`` with the real
    API's behaviour: filter by ``[since, until)`` and cap the response at
    ``page_size`` (oldest first), exactly the truncation the windowing is
    built to defeat."""
    prov = GraphAlertsProvider.__new__(GraphAlertsProvider)

    def _fake_page(*, since: datetime, until: datetime, page_size: int) -> list[dict]:
        matched = sorted(
            (a for a in store if since <= a["_created"] < until),
            key=lambda a: a["_created"],
        )
        return [{"id": a["id"]} for a in matched[:page_size]]

    prov._fetch_graph_alerts_single_page = _fake_page  # type: ignore[assignment]
    return prov


def _store(n: int, since: datetime, span: timedelta) -> list[dict]:
    """``n`` alerts spread evenly across ``[since, since+span)``."""
    step = span / n
    return [{"id": f"a-{i}", "_created": since + step * i} for i in range(n)]


def test_windowed_recovers_all_alerts_past_the_page_cap() -> None:
    since = datetime(2026, 5, 15, tzinfo=timezone.utc)
    span = timedelta(days=1)
    store = _store(1500, since, span)  # 3x the 500 cap in one day

    prov = _provider_over(store)
    got = prov.list_graph_alerts_windowed(since=since, until=since + span)

    # All 1500 recovered (vs the 500 a single capped page would return).
    assert len(got) == 1500
    assert {a["id"] for a in got} == {a["id"] for a in store}


def test_windowed_single_slice_when_under_cap() -> None:
    since = datetime(2026, 5, 15, tzinfo=timezone.utc)
    span = timedelta(days=1)
    store = _store(120, since, span)  # well under the cap

    prov = _provider_over(store)
    got = prov.list_graph_alerts_windowed(since=since, until=since + span)

    assert len(got) == 120
    assert {a["id"] for a in got} == {a["id"] for a in store}


def test_windowed_no_duplicates_at_exactly_the_cap() -> None:
    since = datetime(2026, 5, 15, tzinfo=timezone.utc)
    span = timedelta(days=1)
    store = _store(GRAPH_ALERTS_PAGE_SIZE, since, span)  # exactly 500

    prov = _provider_over(store)
    got = prov.list_graph_alerts_windowed(since=since, until=since + span)

    ids = [a["id"] for a in got]
    assert len(ids) == GRAPH_ALERTS_PAGE_SIZE
    assert len(ids) == len(set(ids))  # halving must not double-count boundaries


def test_windowed_warns_and_terminates_when_floor_is_saturated(
    caplog,
) -> None:
    # 600 alerts inside a 10-minute window: below the 15-min floor, so the
    # slice cannot be subdivided further. The fetch must terminate (no
    # infinite recursion), return the capped page, and log a WARNING.
    since = datetime(2026, 5, 15, tzinfo=timezone.utc)
    span = timedelta(minutes=10)
    store = _store(600, since, span)

    prov = _provider_over(store)
    with caplog.at_level(logging.WARNING):
        got = prov.list_graph_alerts_windowed(since=since, until=since + span)

    assert len(got) == GRAPH_ALERTS_PAGE_SIZE  # truncated at the floor
    assert any("hit the" in r.message and "page cap" in r.message for r in caplog.records)
