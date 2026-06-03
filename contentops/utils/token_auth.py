# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""httpx auth flow that refreshes Azure bearer tokens transparently.

Static-token construction (e.g. ``DefenderClient(token=str)``) holds a
single bearer string in the ``Authorization`` header for the lifetime of
the ``httpx.Client``. ARM / Graph access tokens expire after ~60-75 min,
so any apply batch that runs longer than that 401s silently and is
treated as a per-asset failure rather than an auth failure.

``BearerTokenAuth`` solves that with two layers of refresh:

  1. **Proactive expiry** (S4) — when the factory hands back an
     ``AccessToken``-shaped object (``.token`` + ``.expires_on``), we
     cache both and force a refresh when ``now >= expires_on - SKEW``.
     ``DefaultAzureCredential.get_token(scope)`` already returns this
     shape, so the production callers in
     ``contentops.providers.*`` / ``pipeline.{sentinel,defender}.client``
     get expiry-aware refresh automatically once they pass the
     ``AccessToken`` through rather than extracting ``.token`` upfront.

  2. **Reactive 401 retry** — defence-in-depth against clock skew,
     proactive revocation, or factories that don't expose expiry.

When the factory returns a bare string (legacy contract, used by some
tests), the proactive layer disables itself for that auth instance and
the flow falls back to refresh-on-401 only. No caller is forced to
migrate just to keep working.
"""

from __future__ import annotations

import threading
import time
from typing import Any, Callable, Generator

import httpx


class BearerTokenAuth(httpx.Auth):
    """httpx auth flow with proactive + reactive bearer-token refresh.

    Pass ``token_factory`` returning either:

      * an ``AccessToken``-shaped object — any value exposing ``.token``
        (``str``) and ``.expires_on`` (``int``, Unix epoch seconds). This
        is what ``DefaultAzureCredential.get_token(scope)`` returns.
        Enables proactive refresh ``SKEW_SECONDS`` before expiry.

      * a bare ``str`` (legacy / test fixture contract). The proactive
        layer no-ops; tokens are kept until a 401 forces a refresh.

    The active token is cached between requests so ``get_token`` isn't
    re-invoked on every call — only when the cached token is missing,
    expired (proactive), or rejected (reactive 401 retry).
    """

    requires_response_body = False

    # Refresh this many seconds before ``expires_on``. Five minutes
    # matches the internal pre-expiry refresh window
    # ``DefaultAzureCredential`` uses, so we'll proactively pull a new
    # token at roughly the same time the credential would have refreshed
    # under the hood — no surprise 401s mid-batch.
    SKEW_SECONDS: int = 300

    def __init__(self, token_factory: Callable[[], Any]) -> None:
        self._token_factory = token_factory
        self._cached_token: str | None = None
        self._cached_expires_on: int | None = None
        self._lock = threading.Lock()

    def _is_expired(self) -> bool:
        """True when the cached token is within ``SKEW_SECONDS`` of expiry.

        Returns False when there's no expiry info on the cached token
        (legacy string-returning factory) — the reactive 401 path is
        the only safety net for that case.
        """
        if self._cached_expires_on is None:
            return False
        return time.time() >= (self._cached_expires_on - self.SKEW_SECONDS)

    def _token(self, *, force_refresh: bool = False) -> str:
        with self._lock:
            return self._token_unlocked(force_refresh=force_refresh)

    def _token_unlocked(self, *, force_refresh: bool = False) -> str:
        if force_refresh or self._cached_token is None or self._is_expired():
            value = self._token_factory()
            # Duck-type AccessToken (token + expires_on). A bare string
            # is accepted for the legacy factory contract; anything
            # else is a programmer bug — refuse it loudly instead of
            # stringifying ``None`` / a tuple into the bearer header.
            tok_attr = getattr(value, "token", None)
            exp_attr = getattr(value, "expires_on", None)
            if isinstance(tok_attr, str) and isinstance(exp_attr, int):
                self._cached_token = tok_attr
                self._cached_expires_on = exp_attr
            elif isinstance(value, str):
                self._cached_token = value
                self._cached_expires_on = None
            else:
                raise TypeError(
                    "BearerTokenAuth token factory returned unsupported type "
                    f"{type(value).__name__}; expected str or AccessToken-shaped "
                    "(token: str + expires_on: int)"
                )
        return self._cached_token

    def auth_flow(
        self, request: httpx.Request
    ) -> Generator[httpx.Request, httpx.Response, None]:
        request.headers["Authorization"] = f"Bearer {self._token()}"
        response = yield request
        if response.status_code == 401:
            request.headers["Authorization"] = (
                f"Bearer {self._token(force_refresh=True)}"
            )
            yield request
