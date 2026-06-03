# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Shared HTTP retry + pagination helpers used by ARM and Graph clients.

Both `SentinelArmProvider` and `DefenderClient` need the same shape of
retry: 429 and 5xx are retryable up to N times with exponential
backoff, but a `Retry-After` header from the server overrides the
heuristic. Pagination loops also need a cycle/max-page guard so a buggy
``nextLink`` cannot hang the deploy job.
"""

from __future__ import annotations

import email.utils
import logging
import time
from typing import Callable
from urllib.parse import urlparse

import httpx

logger = logging.getLogger(__name__)


# Status codes the unified retry loop considers transient. Any other
# 4xx (auth/permission/payload errors) is the caller's responsibility
# to surface — retrying them just burns quota.
RETRYABLE_STATUS = frozenset({429, 500, 502, 503, 504})

# Belt-and-braces upper bound for pagination loops. Real ARM/Graph
# tenants top out well below this; anything higher is almost certainly
# a broken nextLink cycle.
MAX_PAGES = 1000
MAX_RETRY_AFTER_SECONDS: float = 120.0


def parse_retry_after(response: httpx.Response) -> float | None:
    """Return the ``Retry-After`` header in seconds, or None if absent/invalid.

    The header is either ``delta-seconds`` (an integer string) or an
    HTTP-date. Both forms are valid per RFC 7231 §7.1.3; servers in the
    wild emit a mix.
    """
    raw = response.headers.get("Retry-After")
    if not raw:
        return None
    raw = raw.strip()
    try:
        return min(float(raw), MAX_RETRY_AFTER_SECONDS)
    except ValueError:
        pass
    # HTTP-date fallback.
    try:
        when = email.utils.parsedate_to_datetime(raw)
    except (TypeError, ValueError):
        return None
    if when is None:
        return None
    delta = when.timestamp() - time.time()
    return min(max(delta, 0.0), MAX_RETRY_AFTER_SECONDS)


def request_with_retry(
    do_request: Callable[[], httpx.Response],
    *,
    max_retries: int = 3,
    sleep: Callable[[float], None] = time.sleep,
    label: str = "request",
) -> httpx.Response:
    """Issue ``do_request()`` and retry up to ``max_retries`` times on transient status.

    A single loop handles both 429 and 5xx — the previous design used
    two sequential loops that allowed up to 7 total attempts and never
    re-retried a 5xx that flipped to 429 on a follow-up. Backoff is
    ``max(Retry-After, 2**attempt)`` so a server that explicitly asks
    for a longer wait wins, but we never retry faster than the
    exponential default.
    """
    response = do_request()
    attempts = 0
    while response.status_code in RETRYABLE_STATUS and attempts < max_retries:
        attempts += 1
        header_wait = parse_retry_after(response)
        backoff = 2 ** attempts
        wait = max(header_wait or 0.0, float(backoff))
        logger.warning(
            "%s: retryable %s (attempt %d/%d), sleeping %.1fs",
            label, response.status_code, attempts, max_retries, wait,
        )
        sleep(wait)
        response = do_request()
    return response


def paginate(
    fetch_page: Callable[[str], httpx.Response],
    first_url: str,
    next_link_key: str = "nextLink",
    *,
    max_pages: int = MAX_PAGES,
) -> list[dict]:
    """Walk pages until ``next_link_key`` is missing, with cycle detection.

    ``fetch_page(url)`` is expected to return a successful ``httpx.Response``
    whose JSON body contains ``"value": [...]`` and optionally
    ``next_link_key``. A nextLink that points back to a previously
    visited URL, or a run that exceeds ``max_pages``, raises
    ``RuntimeError`` instead of looping forever.
    """
    items: list[dict] = []
    url: str | None = first_url
    visited: set[str] = set()
    parsed_origin = urlparse(first_url)
    allowed_origin = (
        f"{parsed_origin.scheme}://{parsed_origin.netloc}".lower()
        if parsed_origin.scheme
        else None
    )
    while url:
        parsed_url = urlparse(url)
        if parsed_url.scheme and allowed_origin:
            url_origin = f"{parsed_url.scheme}://{parsed_url.netloc}".lower()
            if url_origin != allowed_origin:
                raise RuntimeError(
                    f"nextLink host mismatch: expected {allowed_origin!r}, "
                    f"got {url_origin!r} — refusing to follow cross-host redirect"
                )
        elif parsed_url.scheme and not allowed_origin:
            allowed_origin = f"{parsed_url.scheme}://{parsed_url.netloc}".lower()
        if url in visited:
            raise RuntimeError(f"pagination cycle detected at {url}")
        visited.add(url)
        if len(visited) > max_pages:
            raise RuntimeError(
                f"pagination exceeded {max_pages} pages — refusing to continue"
            )
        response = fetch_page(url)
        response.raise_for_status()
        data = response.json()
        items.extend(data.get("value", []))
        url = data.get(next_link_key) or None
    return items


__all__ = [
    "MAX_PAGES",
    "RETRYABLE_STATUS",
    "paginate",
    "parse_retry_after",
    "request_with_retry",
]
