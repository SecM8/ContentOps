# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Token acquisition: .env client secret, else OIDC / az login.

Priority:
  1. .env client-secret (AZURE_CLIENT_ID + TENANT_ID + CLIENT_SECRET)
  2. OIDC / federated credentials (GitHub Actions, managed identity)
  3. AzureCliCredential (local ``az login``)

When a client secret is configured, step 1 is the identity. If it fails
(expired secret, wrong value) the default is to raise
:class:`CredentialFallbackRefused`: silently switching to OIDC or the
operator's ``az login`` would run as a different -- often more
privileged -- identity, possibly in another tenant, and audit records
would name the wrong actor. Set ``CONTENTOPS_AUTH_FALLBACK=1`` to allow
the fallback for local work; it is never allowed inside GitHub Actions.

Two token families:

  * ``get_arm_token`` / ``get_graph_token`` — bare token string.
    Legacy callers only (bootstrap, integration test fixtures).
  * ``get_arm_access_token`` / ``get_graph_access_token`` — full
    ``AccessToken`` (token + expires_on) for proactive refresh via
    :class:`contentops.utils.token_auth.BearerTokenAuth`.
"""

from __future__ import annotations

import logging
import os

from azure.core.credentials import AccessToken, TokenCredential
from azure.core.exceptions import ClientAuthenticationError
from azure.identity import (
    ClientSecretCredential,
    CredentialUnavailableError,
    DefaultAzureCredential,
)

log = logging.getLogger(__name__)

ARM_SCOPE = "https://management.azure.com/.default"
GRAPH_SCOPE = "https://graph.microsoft.com/.default"


# Opt-in switch for falling back from a failed .env client secret to
# OIDC / az login. Truthy values: 1, true, yes (case-insensitive).
FALLBACK_ENV_VAR = "CONTENTOPS_AUTH_FALLBACK"
_TRUTHY = frozenset({"1", "true", "yes"})


def fallback_allowed() -> bool:
    """Whether a failed client-secret sign-in may fall back to another identity.

    Never inside GitHub Actions: a CI run must authenticate as the identity
    it was configured with. Locally, only when ``CONTENTOPS_AUTH_FALLBACK``
    is truthy.
    """
    if os.environ.get("GITHUB_ACTIONS", "").strip().lower() == "true":
        return False
    return os.environ.get(FALLBACK_ENV_VAR, "").strip().lower() in _TRUTHY


class CredentialFallbackRefused(ClientAuthenticationError):
    """The .env client secret failed and falling back to OIDC / az login
    (a different identity) is not enabled."""


class _FallbackCredential:
    """Use the .env client secret; fall back to OIDC/az-login only when allowed.

    ``allow_fallback=None`` (the default) decides at failure time via
    :func:`fallback_allowed`; tests pass an explicit bool.
    """

    def __init__(
        self,
        primary: TokenCredential,
        fallback: TokenCredential,
        *,
        allow_fallback: bool | None = None,
    ) -> None:
        self._primary = primary
        self._fallback = fallback
        self._allow_fallback = allow_fallback
        self._primary_failed = False

    def get_token(
        self, *scopes: str, **kwargs: object
    ) -> AccessToken:
        if not self._primary_failed:
            try:
                token = self._primary.get_token(*scopes, **kwargs)
                log.debug("Auth: .env credentials succeeded (client-secret)")
                return token
            except ClientAuthenticationError as exc:
                import re as _re
                msg = getattr(exc, "message", str(exc))
                code_match = _re.search(r"AADSTS\d+", msg)
                safe_msg = code_match.group(0) if code_match else type(exc).__name__
                allowed = (
                    self._allow_fallback
                    if self._allow_fallback is not None
                    else fallback_allowed()
                )
                if not allowed:
                    raise CredentialFallbackRefused(
                        message=(
                            f"Client-secret sign-in from .env failed ({safe_msg}). "
                            "ContentOps does not switch to another identity "
                            "(OIDC / az login) on its own: actions and audit "
                            "records would be attributed to the wrong actor. "
                            "Fix AZURE_CLIENT_SECRET, or remove it to sign in "
                            "with OIDC / az login, or set "
                            f"{FALLBACK_ENV_VAR}=1 to allow the fallback for "
                            "local work (never honoured in GitHub Actions)."
                        ),
                    ) from exc
                log.warning(
                    "Auth: .env credentials failed (%s); fallback enabled via "
                    "%s, switching to OIDC/az-login — the active identity changes",
                    safe_msg, FALLBACK_ENV_VAR,
                )
                self._primary_failed = True
        return self._fallback.get_token(*scopes, **kwargs)


_credential_cache: TokenCredential | None = None


def get_credential() -> TokenCredential:
    """Return the credential: .env client secret, else OIDC / az login.

    When AZURE_CLIENT_SECRET is set (typically via ``.env``), that
    service principal is the identity. If it fails, the call raises
    :class:`CredentialFallbackRefused` unless ``CONTENTOPS_AUTH_FALLBACK``
    allows falling back to DefaultAzureCredential (see
    :func:`fallback_allowed`).

    Without AZURE_CLIENT_SECRET, goes straight to OIDC/az-login.

    The result is cached for the process lifetime so ``_primary_failed``
    state is shared across all callers.
    """
    global _credential_cache
    if _credential_cache is not None:
        return _credential_cache

    client_secret = os.environ.get("AZURE_CLIENT_SECRET")
    client_id = os.environ.get("AZURE_CLIENT_ID")
    tenant_id = os.environ.get("AZURE_TENANT_ID")

    fallback = DefaultAzureCredential(
        exclude_shared_token_cache_credential=True,
        exclude_visual_studio_code_credential=True,
        exclude_environment_credential=True,
    )

    if client_secret and client_id and tenant_id:
        log.debug("Auth: .env client secret detected; fallback to OIDC/az-login is opt-in")
        primary = ClientSecretCredential(
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret,
        )
        _credential_cache = _FallbackCredential(primary, fallback)
    else:
        log.debug("Auth: no client secret, using OIDC/az-login")
        _credential_cache = fallback

    return _credential_cache


def _reset_credential_cache() -> None:
    """Reset the credential cache (for tests only)."""
    global _credential_cache
    _credential_cache = None


def get_arm_token(credential: TokenCredential) -> str:
    """Acquire a token for the ARM API. Returns the bare token string."""
    return credential.get_token(ARM_SCOPE).token


def get_graph_token(credential: TokenCredential) -> str:
    """Acquire a token for the Microsoft Graph API. Returns the bare token string."""
    return credential.get_token(GRAPH_SCOPE).token


def get_arm_access_token(credential: TokenCredential) -> AccessToken:
    """Acquire an ARM AccessToken (token + expires_on)."""
    return credential.get_token(ARM_SCOPE)


def get_graph_access_token(credential: TokenCredential) -> AccessToken:
    """Acquire a Microsoft Graph AccessToken (token + expires_on)."""
    return credential.get_token(GRAPH_SCOPE)
