# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Defender XDR Graph Security Beta API client."""

from __future__ import annotations

import logging
import time  # noqa: F401 — kept so tests that monkeypatch `defender.client.time.sleep` to no-op still find the attribute; the actual retry sleep is shared via contentops.utils.http_retry which references the same `time` module.
from typing import Any

import httpx

from contentops.utils.http_retry import paginate, request_with_retry
from contentops.utils.token_auth import BearerTokenAuth

logger = logging.getLogger(__name__)

BASE_URL = "https://graph.microsoft.com/beta/security/rules"


# Explicit per-phase timeout. Read-timeout matches the prior scalar
# default; connect/pool drop to 10s so a DNS or TCP-reachability
# failure surfaces in seconds rather than waiting the full read budget
# on each of the 3 retry attempts (~120s saved on a fully unreachable
# Graph endpoint). Tuned for the deploy.yml 30-min job budget.
GRAPH_HTTP_TIMEOUT = httpx.Timeout(connect=10.0, read=30.0, write=30.0, pool=10.0)


class DefenderClient:
    """HTTP client for the Microsoft Graph Security Beta API."""

    def __init__(
        self,
        token: str | None = None,
        *,
        credential: Any | None = None,
    ) -> None:
        if token is None and credential is None:
            raise ValueError("DefenderClient requires either token or credential")
        headers: dict[str, str] = {"Content-Type": "application/json"}
        auth: httpx.Auth | None = None
        if credential is not None:
            from contentops.utils.auth import get_graph_access_token
            # Use the AccessToken-returning helper so BearerTokenAuth
            # can refresh proactively before the ~1h Graph token TTL
            # elapses.
            auth = BearerTokenAuth(lambda: get_graph_access_token(credential))
        else:
            headers["Authorization"] = f"Bearer {token}"
        self._client = httpx.Client(
            base_url=BASE_URL,
            headers=headers,
            auth=auth,
            timeout=GRAPH_HTTP_TIMEOUT,
        )

    def _request_with_retry(
        self, method: str, url: str, **kwargs: object
    ) -> httpx.Response:
        """Issue a request, retrying transient 429/5xx up to 3 times.

        Backoff honours ``Retry-After`` (delta-seconds or HTTP-date) and
        otherwise falls back to ``2**attempt`` exponential. 5xx is
        treated symmetrically with 429 — the previous design retried
        5xx exactly once with a 1s sleep and ignored ``Retry-After``,
        which lost every multi-second Graph flap.
        """
        return request_with_retry(
            lambda: self._client.request(method, url, **kwargs),
            label=f"Graph {method} {url}",
        )

    def list_rules(self) -> list[dict]:
        """GET all detection rules, following @odata.nextLink pagination.

        Bounded by a cycle-detection + max-page guard
        (``contentops.utils.http_retry.paginate``): a buggy
        ``@odata.nextLink`` that loops back to a prior URL raises
        ``RuntimeError`` rather than hanging the deploy.
        """
        return paginate(
            lambda u: self._request_with_retry("GET", u),
            "/detectionRules",
            next_link_key="@odata.nextLink",
        )

    def get_rule(self, graph_id: str) -> dict | None:
        """GET a single detection rule by Graph ID. Returns None on 404."""
        response = self._request_with_retry("GET", f"/detectionRules/{graph_id}")
        if response.status_code == 404:
            return None
        response.raise_for_status()
        return response.json()

    def create_rule(self, body: dict) -> httpx.Response:
        """POST a new detection rule."""
        return self._request_with_retry("POST", "/detectionRules", json=body)

    def update_rule(self, graph_id: str, body: dict) -> httpx.Response:
        """PATCH an existing detection rule."""
        return self._request_with_retry("PATCH", f"/detectionRules/{graph_id}", json=body)

    def delete_rule(self, graph_id: str) -> httpx.Response:
        """DELETE a detection rule."""
        return self._request_with_retry("DELETE", f"/detectionRules/{graph_id}")

    def close(self) -> None:
        """Close the HTTP client."""
        self._client.close()
