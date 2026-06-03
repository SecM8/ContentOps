# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for BearerTokenAuth — refresh on 401 + per-request token factory."""

from __future__ import annotations

import respx
from httpx import Client, Response

from contentops.utils.token_auth import BearerTokenAuth


@respx.mock
def test_token_factory_invoked_lazily_and_attached_as_bearer() -> None:
    calls: list[int] = []

    def factory() -> str:
        calls.append(1)
        return "tok-1"

    auth = BearerTokenAuth(factory)
    route = respx.get("https://api.test/x").mock(return_value=Response(200))

    with Client(base_url="https://api.test", auth=auth) as client:
        client.get("/x")
        client.get("/x")

    # Cached after first call: only one factory invocation despite two requests.
    assert sum(calls) == 1
    sent = route.calls.last.request
    assert sent.headers["authorization"] == "Bearer tok-1"


@respx.mock
def test_401_triggers_force_refresh_and_retry_once() -> None:
    tokens = iter(["expired", "fresh"])

    def factory() -> str:
        return next(tokens)

    auth = BearerTokenAuth(factory)
    # First call: 401. Second call (after refresh): 200.
    route = respx.get("https://api.test/x").mock(
        side_effect=[Response(401), Response(200, json={"ok": True})]
    )

    with Client(base_url="https://api.test", auth=auth) as client:
        response = client.get("/x")

    assert response.status_code == 200
    assert response.json() == {"ok": True}
    assert route.call_count == 2
    assert route.calls[0].request.headers["authorization"] == "Bearer expired"
    assert route.calls[1].request.headers["authorization"] == "Bearer fresh"


@respx.mock
def test_persistent_401_does_not_loop() -> None:
    auth = BearerTokenAuth(lambda: "still-bad")
    route = respx.get("https://api.test/x").mock(return_value=Response(401))

    with Client(base_url="https://api.test", auth=auth) as client:
        response = client.get("/x")

    # One refresh attempt then we surface the 401 — no infinite retry loop.
    assert response.status_code == 401
    assert route.call_count == 2


# ---------------------------------------------------------------------------
# S4 — proactive expiry refresh
# ---------------------------------------------------------------------------


class _FakeAccessToken:
    """Stand-in for ``azure.core.credentials.AccessToken``.

    A NamedTuple-like object with ``.token`` (str) and ``.expires_on``
    (int, Unix epoch seconds). The duck-type that BearerTokenAuth's
    proactive-refresh path looks for.
    """

    def __init__(self, token: str, expires_on: int) -> None:
        self.token = token
        self.expires_on = expires_on


@respx.mock
def test_proactive_refresh_when_token_within_skew_of_expiry(monkeypatch) -> None:
    """When the cached token has less than ``SKEW_SECONDS`` left on
    its TTL, the next request triggers a factory call BEFORE the
    server has a chance to 401.

    This is the S4 behaviour: in a long apply batch we used to wait
    for the ARM/Graph 401 to trigger refresh; now we refresh ahead
    of expiry so the apply never sees a transient auth failure.
    """
    import time as _time

    # Freeze "now" so we can construct expired vs. fresh deterministically.
    base_t = 1_000_000_000
    monkeypatch.setattr(_time, "time", lambda: base_t)

    # First factory call returns a token that expires inside the skew
    # window (would normally be valid for SKEW_SECONDS - 1 more seconds,
    # but the proactive layer treats anything inside the skew as
    # expired). Second call returns a fresh token good for 1h.
    tokens = iter([
        _FakeAccessToken("about-to-expire", base_t + 200),    # 200s left
        _FakeAccessToken("fresh-1h", base_t + 3600),
    ])
    factory_calls: list[int] = []

    def factory():
        factory_calls.append(1)
        return next(tokens)

    auth = BearerTokenAuth(factory)
    route = respx.get("https://api.test/x").mock(
        side_effect=[Response(200), Response(200)],
    )

    with Client(base_url="https://api.test", auth=auth) as client:
        client.get("/x")
        client.get("/x")

    # Two factory invocations even though both responses were 200 —
    # the second was triggered by the proactive expiry check.
    assert sum(factory_calls) == 2
    assert route.calls[0].request.headers["authorization"] == "Bearer about-to-expire"
    assert route.calls[1].request.headers["authorization"] == "Bearer fresh-1h"


@respx.mock
def test_no_proactive_refresh_when_token_well_within_ttl(monkeypatch) -> None:
    """A token with plenty of TTL left is reused across requests
    without invoking the factory again — the proactive layer only
    fires inside the skew window."""
    import time as _time

    base_t = 1_000_000_000
    monkeypatch.setattr(_time, "time", lambda: base_t)

    factory_calls: list[int] = []

    def factory():
        factory_calls.append(1)
        return _FakeAccessToken("fresh-1h", base_t + 3600)  # 1h left

    auth = BearerTokenAuth(factory)
    respx.get("https://api.test/x").mock(return_value=Response(200))

    with Client(base_url="https://api.test", auth=auth) as client:
        client.get("/x")
        client.get("/x")
        client.get("/x")

    assert sum(factory_calls) == 1


@respx.mock
def test_bare_string_factory_keeps_legacy_behaviour() -> None:
    """When the factory returns a bare str (no expiry info), the
    proactive layer no-ops — refresh-on-401 stays the only safety
    net. Used by some test fixtures and is the pre-S4 contract."""
    calls: list[int] = []

    def factory() -> str:
        calls.append(1)
        return "tok"

    auth = BearerTokenAuth(factory)
    respx.get("https://api.test/x").mock(return_value=Response(200))

    with Client(base_url="https://api.test", auth=auth) as client:
        client.get("/x")
        client.get("/x")

    # Cached after first call, never refreshed (no expiry info).
    assert sum(calls) == 1
