# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Generic Sentinel ARM provider.

Builds URLs for any Sentinel sub-resource — alertRules, watchlists,
watchlistItems, etc. — so handlers can share retry/auth logic.
"""

from __future__ import annotations

import logging
import time  # noqa: F401 — kept so tests that monkeypatch `sentinel_arm.time.sleep` to no-op still find the attribute; the actual retry sleep is shared via contentops.utils.http_retry which references the same `time` module.
from typing import Any

import httpx

from contentops.config import SentinelConfig
from contentops.utils.http_retry import paginate, request_with_retry
from contentops.utils.token_auth import BearerTokenAuth

logger = logging.getLogger(__name__)

API_VERSION = "2025-07-01-preview"
ARM_BASE_URL = "https://management.azure.com"


# Explicit per-phase timeout. Read-timeout keeps the historical 30s
# scalar default; connect/pool drop to 10s so a DNS or TCP-reachability
# failure surfaces fast rather than each retry attempt burning the full
# read budget. Bounded so a hung ARM endpoint can never eat the
# deploy.yml 30-min job timeout. Constructor still accepts a scalar
# ``timeout=...`` for tests that want a simple override.
ARM_HTTP_TIMEOUT = httpx.Timeout(connect=10.0, read=30.0, write=30.0, pool=10.0)


class SentinelArmProvider:
    """Low-level ARM client for any Sentinel sub-resource."""

    def __init__(
        self,
        config: SentinelConfig | None = None,
        token: str | None = None,
        *,
        credential: Any | None = None,
        subscription_id: str | None = None,
        resource_group: str | None = None,
        workspace_name: str | None = None,
        timeout: float | httpx.Timeout = ARM_HTTP_TIMEOUT,
    ) -> None:
        if config is None:
            if not (subscription_id and resource_group and workspace_name):
                raise ValueError(
                    "SentinelArmProvider requires either a SentinelConfig or explicit "
                    "subscription_id/resource_group/workspace_name kwargs"
                )
            config = SentinelConfig(
                subscriptionId=subscription_id,
                resourceGroup=resource_group,
                workspaceName=workspace_name,
            )
        if token is None and credential is None:
            raise ValueError(
                "SentinelArmProvider requires either an ARM bearer token or a credential"
            )
        self._config = config
        self._la_workspace_path = (
            f"/subscriptions/{config.subscriptionId}"
            f"/resourceGroups/{config.resourceGroup}"
            f"/providers/Microsoft.OperationalInsights"
            f"/workspaces/{config.workspaceName}"
        )
        self._workspace_path = (
            f"{self._la_workspace_path}/providers/Microsoft.SecurityInsights"
        )
        headers: dict[str, str] = {"Content-Type": "application/json"}
        auth: httpx.Auth | None = None
        if credential is not None:
            from contentops.utils.auth import get_arm_access_token
            # Return the full AccessToken (token + expires_on) so
            # BearerTokenAuth can refresh proactively before expiry —
            # see ``BearerTokenAuth.SKEW_SECONDS``. The
            # ``get_arm_access_token`` helper preserves the
            # expires_on field; the older ``get_arm_token`` would
            # strip it and force fallback to reactive 401 retries.
            auth = BearerTokenAuth(lambda: get_arm_access_token(credential))
        else:
            headers["Authorization"] = f"Bearer {token}"
        self._client = httpx.Client(
            base_url=ARM_BASE_URL,
            headers=headers,
            auth=auth,
            timeout=timeout,
        )

    @property
    def workspace_path(self) -> str:
        return self._workspace_path

    @property
    def loganalytics_workspace_path(self) -> str:
        """Workspace path WITHOUT the Microsoft.SecurityInsights suffix.

        Required for resource types that live directly under the Log
        Analytics workspace (e.g. savedSearches for hunting queries).
        """
        return self._la_workspace_path

    def la_resource_url(self, resource_type: str, name: str | None = None,
                        *, api_version: str = "2023-09-01") -> str:
        """Build a URL for a Log Analytics workspace sub-resource.

        Used for `savedSearches` (hunting queries). The default
        api-version is the latest stable savedSearches version.
        """
        path = f"{self._la_workspace_path}/{resource_type}"
        if name:
            path = f"{path}/{name}"
        return f"{path}?api-version={api_version}"

    def resource_url(self, resource_type: str, name: str | None = None,
                     *, api_version: str = API_VERSION) -> str:
        """Build a fully-qualified URL for a Sentinel sub-resource.

        Example:
            resource_url("alertRules", "abc-123")
            resource_url("watchlists", "high-value-assets")
            resource_url("watchlists/high-value-assets/watchlistItems")
        """
        path = f"{self._workspace_path}/{resource_type}"
        if name:
            path = f"{path}/{name}"
        return f"{path}?api-version={api_version}"

    def subscription_resource_url(
        self,
        rp_namespace: str,
        resource_type: str,
        name: str | None = None,
        *,
        api_version: str,
    ) -> str:
        """Build a URL for a resource in the same subscription/RG but a
        different resource provider namespace (e.g. Microsoft.Logic/workflows).

        Example:
            subscription_resource_url(
                "Microsoft.Logic", "workflows", "my-playbook",
                api_version="2019-05-01",
            )
        """
        path = (
            f"/subscriptions/{self._config.subscriptionId}"
            f"/resourceGroups/{self._config.resourceGroup}"
            f"/providers/{rp_namespace}/{resource_type}"
        )
        if name:
            path = f"{path}/{name}"
        return f"{path}?api-version={api_version}"

    def request(self, method: str, url: str, **kwargs: object) -> httpx.Response:
        """Issue a request, retrying transient 429/5xx up to 3 times.

        Backoff honours ``Retry-After`` (delta-seconds or HTTP-date) and
        otherwise falls back to ``2**attempt`` exponential. The retry
        loop is unified — a 5xx that flips to 429 on retry (or vice
        versa) is still retried by the same counter, capped at 3 total
        retries.
        """
        return request_with_retry(
            lambda: self._client.request(method, url, **kwargs),
            label=f"ARM {method} {url}",
        )

    def list_resource(self, resource_type: str) -> list[dict]:
        """GET a collection sub-resource, following ARM ``nextLink`` pagination.

        ARM caps page size (typically ~500). Callers iterating over
        collections (drift, prune, doctor) need every entry, not just
        page 1 — without following ``nextLink`` the tail of the
        collection looks remote-only and can be flagged as orphaned.

        Pagination is bounded by a cycle-detection + max-page guard
        (see ``contentops.utils.http_retry.paginate``): a broken
        ``nextLink`` that points back to a prior URL raises rather
        than hanging the deploy until the 30-min job timeout.
        """
        return paginate(
            lambda u: self.request("GET", u),
            self.resource_url(resource_type),
            next_link_key="nextLink",
        )

    def get_resource(self, resource_type: str, name: str) -> dict | None:
        response = self.request("GET", self.resource_url(resource_type, name))
        if response.status_code == 404:
            return None
        response.raise_for_status()
        return response.json()

    def put_resource(
        self, resource_type: str, name: str, body: dict,
        *, etag: str | None = None,
    ) -> httpx.Response:
        """PUT (upsert) a Sentinel sub-resource.

        When ``etag`` is provided, the request includes ``If-Match``
        for optimistic concurrency. ARM returns ``412 Precondition
        Failed`` when the remote resource has moved since the etag
        was captured — handlers surface that as a per-rule failure
        ("re-run plan and resolve drift") instead of clobbering
        a concurrent edit.
        """
        headers = {"If-Match": etag} if etag else None
        return self.request(
            "PUT", self.resource_url(resource_type, name),
            json=body, headers=headers,
        )

    def delete_resource(self, resource_type: str, name: str) -> httpx.Response:
        return self.request("DELETE", self.resource_url(resource_type, name))

    @classmethod
    def from_env(cls, *, timeout: float = 30.0) -> SentinelArmProvider:
        """Construct a provider from the on-disk tenant config + ambient credentials.

        Reads `config/tenant.yml` via `load_tenant_config()` and acquires an
        ARM bearer token via `DefaultAzureCredential`. This is the convenience
        path for CLI commands; library callers should prefer the explicit
        constructor for testability and (future) multi-tenant use.
        """
        # Imported lazily to avoid pulling azure-identity into unit tests
        # that construct the provider with explicit config + a fake token.
        import os
        from contentops.config import load_tenant_config
        from contentops.utils.auth import get_credential

        cfg = load_tenant_config()
        if not cfg.sentinelWorkspaces:
            raise ValueError(
                f"tenant {cfg.name!r} has no Sentinel workspaces configured"
            )
        ws_name = os.environ.get("PIPELINE_WORKSPACE_NAME")
        if ws_name:
            workspace = cfg.workspace_by_name(ws_name)
        elif len(cfg.sentinelWorkspaces) == 1:
            workspace = cfg.sentinelWorkspaces[0]
        else:
            raise RuntimeError(
                "PIPELINE_WORKSPACE_NAME unset and the tenant has multiple "
                "Sentinel workspaces. The CLI orchestrator should set it; "
                "if you're calling from_env() directly, set the env var first."
            )
        return cls(workspace, credential=get_credential(), timeout=timeout)

    def close(self) -> None:
        self._client.close()
