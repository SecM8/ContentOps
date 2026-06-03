# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for the token helpers in ``contentops.utils.auth``.

Two families:

  * ``get_arm_token`` / ``get_graph_token`` — legacy string-returning
    helpers. Backward-compatible surface for v1 paths.
  * ``get_arm_access_token`` / ``get_graph_access_token`` — return
    the full ``azure.core.credentials.AccessToken`` so callers
    routing through :class:`contentops.utils.token_auth.BearerTokenAuth`
    can refresh proactively before expiry.

These tests pin:

  * Both families call ``credential.get_token`` with the right scope.
  * The string helpers return the bare ``.token``.
  * The AccessToken helpers return the full object, expires_on
    preserved.
  * The provider/client modules wire the AccessToken helpers into
    their BearerTokenAuth factories (not the string ones) so
    proactive refresh actually happens in production.

No live Azure — the credential is a fake whose ``get_token``
returns a hand-built ``AccessToken``.
"""

from __future__ import annotations

from typing import Any

from azure.core.credentials import AccessToken

from contentops.utils.auth import (
    ARM_SCOPE,
    GRAPH_SCOPE,
    get_arm_access_token,
    get_arm_token,
    get_graph_access_token,
    get_graph_token,
)


# ---------------------------------------------------------------------------
# Fake credential — captures every get_token() call so tests can inspect
# the scope the helper asked for.
# ---------------------------------------------------------------------------


class _FakeCredential:
    """Replaces DefaultAzureCredential for token-helper tests."""

    def __init__(self, token: str = "fake-token", expires_on: int = 1_999_999_999) -> None:
        self._token = token
        self._expires_on = expires_on
        self.calls: list[tuple[tuple, dict]] = []

    def get_token(self, *args: Any, **kwargs: Any) -> AccessToken:
        self.calls.append((args, kwargs))
        return AccessToken(self._token, self._expires_on)


# ---------------------------------------------------------------------------
# String-returning helpers
# ---------------------------------------------------------------------------


def test_get_arm_token_returns_bare_string_with_arm_scope() -> None:
    cred = _FakeCredential(token="arm-tok-1")
    out = get_arm_token(cred)
    assert isinstance(out, str)
    assert out == "arm-tok-1"
    # Called with the ARM scope literal (positional arg).
    assert cred.calls == [((ARM_SCOPE,), {})]


def test_get_graph_token_returns_bare_string_with_graph_scope() -> None:
    cred = _FakeCredential(token="graph-tok-1")
    out = get_graph_token(cred)
    assert isinstance(out, str)
    assert out == "graph-tok-1"
    assert cred.calls == [((GRAPH_SCOPE,), {})]


# ---------------------------------------------------------------------------
# AccessToken-returning helpers
# ---------------------------------------------------------------------------


def test_get_arm_access_token_returns_full_access_token() -> None:
    cred = _FakeCredential(token="arm-tok-2", expires_on=1_700_000_000)
    out = get_arm_access_token(cred)
    # Duck-typed AccessToken: .token + .expires_on both present.
    assert out.token == "arm-tok-2"
    assert out.expires_on == 1_700_000_000
    assert cred.calls == [((ARM_SCOPE,), {})]


def test_get_graph_access_token_returns_full_access_token() -> None:
    cred = _FakeCredential(token="graph-tok-2", expires_on=1_800_000_000)
    out = get_graph_access_token(cred)
    assert out.token == "graph-tok-2"
    assert out.expires_on == 1_800_000_000
    assert cred.calls == [((GRAPH_SCOPE,), {})]


# ---------------------------------------------------------------------------
# Wiring contract: providers + clients must use the AccessToken helper,
# not the string helper. If a future refactor accidentally swaps them
# back, BearerTokenAuth's proactive refresh silently degrades to
# "reactive 401 retry only" — the providers still work, but they don't
# refresh ahead of expiry. These tests catch that regression at the
# import-graph level.
# ---------------------------------------------------------------------------


def test_sentinel_arm_provider_routes_through_arm_access_token(monkeypatch) -> None:
    """Constructing ``SentinelArmProvider(credential=...)`` builds its
    BearerTokenAuth factory by calling ``get_arm_access_token`` —
    not ``get_arm_token`` — so the resulting auth has access to
    ``expires_on`` for proactive refresh."""
    cred = _FakeCredential(token="provider-arm-tok")

    # Spy on get_arm_access_token to assert it's the one called by
    # the provider's lambda. (We can't trivially assert "not
    # get_arm_token" because import-level swaps would silently
    # rebind both names; instead we count calls to the new helper.)
    import contentops.utils.auth as auth_module
    real = auth_module.get_arm_access_token
    spy_calls: list[int] = []

    def spy(credential):
        spy_calls.append(1)
        return real(credential)

    monkeypatch.setattr(auth_module, "get_arm_access_token", spy)

    from contentops.config import SentinelConfig
    from contentops.providers.sentinel_arm import SentinelArmProvider

    config = SentinelConfig(
        subscriptionId="sub", resourceGroup="rg", workspaceName="ws",
    )
    provider = SentinelArmProvider(config, credential=cred)
    try:
        # Force the BearerTokenAuth factory to fire by accessing the
        # internal auth and pulling a token. The auth_flow only runs
        # on actual requests, but ``_token()`` is the same code path.
        from contentops.utils.token_auth import BearerTokenAuth
        auth = provider._client.auth
        assert isinstance(auth, BearerTokenAuth)
        tok = auth._token()
        assert tok == "provider-arm-tok"
        assert sum(spy_calls) == 1
        # Proactive refresh is enabled because expires_on flowed through.
        assert auth._cached_expires_on == 1_999_999_999
    finally:
        provider.close()


def test_defender_client_routes_through_graph_access_token(monkeypatch) -> None:
    """The legacy-shaped DefenderClient still uses
    ``get_graph_access_token`` when constructed with ``credential=``,
    even though the static-token path remains for v1 callers."""
    cred = _FakeCredential(token="defender-client-tok", expires_on=1_700_000_002)

    import contentops.utils.auth as auth_module
    real = auth_module.get_graph_access_token
    spy_calls: list[int] = []

    def spy(credential):
        spy_calls.append(1)
        return real(credential)

    monkeypatch.setattr(auth_module, "get_graph_access_token", spy)

    from contentops.defender.client import DefenderClient

    client = DefenderClient(credential=cred)
    try:
        from contentops.utils.token_auth import BearerTokenAuth
        auth = client._client.auth
        assert isinstance(auth, BearerTokenAuth)
        tok = auth._token()
        assert tok == "defender-client-tok"
        assert sum(spy_calls) == 1
        assert auth._cached_expires_on == 1_700_000_002
    finally:
        client.close()
