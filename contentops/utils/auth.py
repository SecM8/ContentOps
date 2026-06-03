# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Token acquisition with .env → OIDC → az-login fallback.

Priority:
  1. .env client-secret (AZURE_CLIENT_ID + TENANT_ID + CLIENT_SECRET)
  2. OIDC / federated credentials (GitHub Actions, managed identity)
  3. AzureCliCredential (local ``az login``)

If step 1 fails with an auth error (expired secret, wrong value),
falls through to step 2/3 with a warning instead of crashing. The
``_FallbackCredential`` wrapper handles this transparently so all
downstream code (providers, token_auth) sees a single credential.

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


class _FallbackCredential:
    """Try .env credentials first, fall back to OIDC/az-login on auth failure."""

    def __init__(self, primary: TokenCredential, fallback: TokenCredential) -> None:
        self._primary = primary
        self._fallback = fallback
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
                log.warning(
                    "Auth: .env credentials failed (%s), falling back to OIDC/az-login",
                    safe_msg,
                )
                self._primary_failed = True
        return self._fallback.get_token(*scopes, **kwargs)


_credential_cache: TokenCredential | None = None


def get_credential() -> TokenCredential:
    """Return a credential with .env → OIDC → az-login fallback.

    When AZURE_CLIENT_SECRET is set (typically via ``.env``), tries
    client-secret auth first. On failure (expired secret, wrong
    value), falls back to DefaultAzureCredential which covers OIDC
    (CI federated tokens) and AzureCliCredential (local ``az login``).

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
        log.debug("Auth: .env detected, trying client-secret with OIDC/az-login fallback")
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
