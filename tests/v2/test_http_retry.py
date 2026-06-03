# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for the shared HTTP retry + pagination helpers.

Regression coverage for PR2:
    P-1 — 5xx retried with exp backoff, not a single sleep(1).
    P-2 — pagination cycle detection.
    P-3 — single unified retry counter (no 1+3+3 implicit budget).
    P-4 — Retry-After header honoured.
"""

from __future__ import annotations

from email.utils import format_datetime
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from contentops.utils.http_retry import (
    MAX_PAGES,
    paginate,
    parse_retry_after,
    request_with_retry,
)


def _resp(status: int, *, headers: dict | None = None, body: dict | None = None) -> httpx.Response:
    # Attaching a Request makes ``raise_for_status`` usable — paginate
    # calls it before consuming the body.
    response = httpx.Response(
        status_code=status,
        headers=headers or {},
        json=body or {},
        request=httpx.Request("GET", "http://test"),
    )
    return response


# ----- parse_retry_after ---------------------------------------------------


def test_parse_retry_after_delta_seconds() -> None:
    assert parse_retry_after(_resp(429, headers={"Retry-After": "5"})) == 5.0


def test_parse_retry_after_http_date_in_future() -> None:
    when = datetime.now(timezone.utc) + timedelta(seconds=10)
    response = _resp(429, headers={"Retry-After": format_datetime(when)})
    delta = parse_retry_after(response)
    assert delta is not None
    assert 5 <= delta <= 15


def test_parse_retry_after_absent_returns_none() -> None:
    assert parse_retry_after(_resp(429)) is None


def test_parse_retry_after_garbage_returns_none() -> None:
    assert parse_retry_after(_resp(429, headers={"Retry-After": "not-a-number"})) is None


# ----- request_with_retry --------------------------------------------------


def test_5xx_retried_three_times_with_exp_backoff() -> None:
    """P-1: 5xx must be retried up to 3 times, not just once."""
    sleeps: list[float] = []
    calls = iter([_resp(503), _resp(503), _resp(503), _resp(200, body={"ok": True})])
    result = request_with_retry(lambda: next(calls), sleep=sleeps.append)
    assert result.status_code == 200
    assert len(sleeps) == 3
    # Exp backoff: 2, 4, 8 (in absence of Retry-After).
    assert sleeps == [2.0, 4.0, 8.0]


def test_retry_after_overrides_exp_backoff_when_longer() -> None:
    """P-4: Retry-After is honoured when it's longer than the heuristic."""
    sleeps: list[float] = []
    calls = iter([_resp(429, headers={"Retry-After": "30"}), _resp(200)])
    request_with_retry(lambda: next(calls), sleep=sleeps.append)
    assert sleeps == [30.0]


def test_unified_retry_counter_caps_at_max_retries() -> None:
    """P-3: 5xx that flips to 429 still uses the same counter."""
    sleeps: list[float] = []
    calls = iter([
        _resp(503), _resp(429), _resp(503), _resp(429),  # 4 retryable
    ])
    result = request_with_retry(lambda: next(calls), sleep=sleeps.append, max_retries=3)
    # First call + 3 retries = 4 total responses examined; the 4th response
    # is still 429 but we stop retrying because attempts == max_retries.
    assert result.status_code == 429
    assert len(sleeps) == 3


def test_non_retryable_status_returns_immediately() -> None:
    sleeps: list[float] = []
    request_with_retry(lambda: _resp(404), sleep=sleeps.append)
    assert sleeps == []


def test_success_returns_immediately() -> None:
    sleeps: list[float] = []
    response = request_with_retry(lambda: _resp(200, body={"ok": True}), sleep=sleeps.append)
    assert response.status_code == 200
    assert sleeps == []


# ----- paginate ------------------------------------------------------------


def test_paginate_follows_nextlink() -> None:
    pages = {
        "/p1": _resp(200, body={"value": [{"id": 1}], "nextLink": "/p2"}),
        "/p2": _resp(200, body={"value": [{"id": 2}]}),
    }
    items = paginate(lambda url: pages[url], "/p1", next_link_key="nextLink")
    assert items == [{"id": 1}, {"id": 2}]


def test_paginate_breaks_on_cycle() -> None:
    """P-2: a nextLink loop must not hang."""
    page = _resp(200, body={"value": [{"id": 1}], "nextLink": "/loop"})
    with pytest.raises(RuntimeError, match="pagination cycle"):
        paginate(lambda url: page, "/loop", next_link_key="nextLink")


def test_paginate_caps_at_max_pages() -> None:
    """P-2: belt-and-braces upper bound on page count."""
    counter = {"n": 0}

    def fetch(url: str) -> httpx.Response:
        counter["n"] += 1
        return _resp(200, body={"value": [], "nextLink": f"/p{counter['n']}"})

    with pytest.raises(RuntimeError):
        paginate(fetch, "/p0", next_link_key="nextLink", max_pages=5)


def test_paginate_uses_odata_nextlink_key() -> None:
    pages = {
        "/p1": _resp(200, body={"value": [{"a": 1}], "@odata.nextLink": "/p2"}),
        "/p2": _resp(200, body={"value": [{"a": 2}]}),
    }
    items = paginate(lambda url: pages[url], "/p1", next_link_key="@odata.nextLink")
    assert items == [{"a": 1}, {"a": 2}]
