# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Dual-source alert provider: Graph alerts_v2 + Sentinel ARM incidents.

Probes both sources independently and fetches from whichever is
available. When both are reachable, returns results from both so
the caller can merge them (see :mod:`contentops.alerts.merge`).

Source detection:
- Graph ``alerts_v2``: probe ``GET /alerts_v2?$top=1``. 403 = unavailable.
- Sentinel ARM: probe incidents endpoint. Absent config = unavailable.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

import httpx

from contentops.utils.http_retry import paginate, request_with_retry
from contentops.utils.token_auth import BearerTokenAuth

logger = logging.getLogger(__name__)

GRAPH_ALERTS_BASE = "https://graph.microsoft.com/v1.0/security"


@dataclass
class SourcedAlerts:
    """Results from a dual-source fetch."""

    graph_alerts: list[dict] = field(default_factory=list)
    sentinel_incidents: list[dict] = field(default_factory=list)
    graph_error: str | None = None
    sentinel_error: str | None = None

# Per-phase timeout mirroring the Defender client pattern.
GRAPH_ALERTS_TIMEOUT = httpx.Timeout(connect=10.0, read=30.0, write=30.0, pool=10.0)


class GraphAlertsProvider:
    """Fetch alerts from Microsoft Graph Security alerts_v2 endpoint.

    Falls back to Sentinel ARM incidents when Graph alerts_v2 is
    unavailable (missing permission or standalone Sentinel).

    Parameters
    ----------
    credential
        An Azure credential object (e.g. from ``get_credential()``).
    sentinel_provider
        Optional :class:`SentinelArmProvider` for fallback incident
        listing. When ``None``, fallback is disabled and a 403 on Graph
        raises.
    """

    def __init__(
        self,
        credential: Any,
        *,
        sentinel_provider: Any | None = None,
        workspace_id: str | None = None,
    ) -> None:
        from contentops.utils.auth import get_graph_access_token

        self._credential = credential
        auth = BearerTokenAuth(lambda: get_graph_access_token(credential))
        self._client = httpx.Client(
            base_url=GRAPH_ALERTS_BASE,
            headers={"Content-Type": "application/json"},
            auth=auth,
            timeout=GRAPH_ALERTS_TIMEOUT,
        )
        self._sentinel = sentinel_provider
        self._workspace_id = workspace_id
        self._source: str | None = None
        self._available_sources: set[str] | None = None

    @property
    def source(self) -> str | None:
        """Which data source was used after ``detect_source()``."""
        return self._source

    def _request_with_retry(
        self, method: str, url: str, **kwargs: object
    ) -> httpx.Response:
        return request_with_retry(
            lambda: self._client.request(method, url, **kwargs),
            label=f"GraphAlerts {method} {url}",
        )

    # ------------------------------------------------------------------
    # Source detection
    # ------------------------------------------------------------------

    def detect_available_sources(self) -> set[str]:
        """Probe which alert sources are reachable.

        Returns a set of ``{"graph", "sentinel"}`` depending on
        availability. Cached for the provider lifetime.
        """
        if self._available_sources is not None:
            return self._available_sources

        available: set[str] = set()

        # Probe Graph
        try:
            resp = self._request_with_retry("GET", "/alerts_v2?$top=1")
            if resp.status_code == 403:
                logger.info("Graph alerts_v2 returned 403 — Graph source unavailable")
            elif resp.status_code < 400:
                available.add("graph")
                logger.info("Graph alerts_v2 reachable")
            else:
                logger.warning("Graph alerts_v2 returned %d", resp.status_code)
        except httpx.HTTPError as exc:
            logger.warning("Graph alerts_v2 probe failed: %s", exc)

        # Probe Sentinel via LA SecurityAlert table (KQL)
        if self._workspace_id:
            try:
                from contentops.workspace_kql import LA_SCOPE, query as kql_query
                token = self._credential.get_token(LA_SCOPE).token
                result = kql_query(
                    "SecurityAlert | take 1",
                    workspace_id=self._workspace_id,
                    token=token,
                )
                available.add("sentinel")
                logger.info("Sentinel SecurityAlert table reachable via KQL")
            except Exception as exc:
                logger.warning("Sentinel KQL probe failed: %s", exc)
        elif self._sentinel is not None:
            try:
                probe_url = self._sentinel.resource_url("incidents") + "&$top=1"
                resp = self._sentinel.request("GET", probe_url)
                if resp.status_code < 400:
                    available.add("sentinel")
                    logger.info("Sentinel ARM incidents reachable (fallback)")
                else:
                    logger.warning("Sentinel incidents probe returned %d", resp.status_code)
            except Exception as exc:
                logger.warning("Sentinel incidents probe failed: %s", exc)

        self._available_sources = available
        return available

    def detect_source(self) -> str:
        """Probe which alert source to use.

        Returns ``"both"``, ``"graph"``, or ``"sentinel"``. Raises when
        no source is available.
        """
        if self._source is not None:
            return self._source

        sources = self.detect_available_sources()
        if "graph" in sources and "sentinel" in sources:
            self._source = "both"
        elif "graph" in sources:
            self._source = "graph"
        elif "sentinel" in sources:
            self._source = "sentinel"
        else:
            raise RuntimeError(
                "No alert sources available. Grant SecurityAlert.Read.All "
                "for Graph and/or configure a Sentinel workspace."
            )
        logger.info("Alert source: %s", self._source)
        return self._source

    def list_alerts_dual(
        self,
        *,
        since: datetime | None = None,
        until: datetime | None = None,
        service_source: str | None = None,
        status: str | None = None,
        classification: str | None = None,
    ) -> SourcedAlerts:
        """Fetch alerts, preferring KQL SecurityAlert as the complete source.

        SecurityAlert KQL returns ALL alerts from ALL sources (Sentinel,
        Defender, Fusion, etc.) with unique SystemAlertIds. Graph
        alerts_v2 is used only as fallback when KQL is unavailable.

        The two systems use different ID schemes (SystemAlertId ≠ Graph
        alert.id) so they cannot be precisely deduplicated. Since KQL is
        the superset, we use it as primary and skip Graph when KQL
        succeeds.
        """
        sources = self.detect_available_sources()
        result = SourcedAlerts()

        # KQL SecurityAlert is the complete source — prefer it
        if "sentinel" in sources:
            try:
                if self._workspace_id:
                    result.sentinel_incidents = self._list_sentinel_kql_alerts(
                        since=since, until=until,
                    )
                else:
                    result.sentinel_incidents = self._list_sentinel_incidents(
                        since=since, until=until,
                        status=status, classification=classification,
                    )
                logger.info("Fetched %d Sentinel alerts (primary source)", len(result.sentinel_incidents))
            except Exception as exc:
                result.sentinel_error = str(exc)
                logger.warning("Sentinel fetch failed: %s", exc)

        # Graph only as fallback when Sentinel/KQL unavailable
        if not result.sentinel_incidents and "graph" in sources:
            try:
                result.graph_alerts = self._list_graph_alerts(
                    since=since, until=until,
                    service_source=service_source,
                    status=status, classification=classification,
                )
                logger.info("Fetched %d Graph alerts (fallback)", len(result.graph_alerts))
            except Exception as exc:
                result.graph_error = str(exc)
                logger.warning("Graph fetch failed: %s", exc)

        if not result.graph_alerts and not result.sentinel_incidents:
            if result.graph_error and result.sentinel_error:
                raise RuntimeError(
                    f"Both alert sources failed. "
                    f"Graph: {result.graph_error}; "
                    f"Sentinel: {result.sentinel_error}"
                )

        return result

    # ------------------------------------------------------------------
    # Alert listing
    # ------------------------------------------------------------------

    def list_alerts(
        self,
        *,
        since: datetime | None = None,
        until: datetime | None = None,
        service_source: str | None = None,
        status: str | None = None,
        classification: str | None = None,
    ) -> list[dict]:
        """List alerts from the detected source (single-source compat).

        For dual-source fetch + merge, use :meth:`list_alerts_dual`.
        """
        source = self.detect_source()

        if source == "sentinel":
            return self._list_sentinel_incidents(
                since=since, until=until, status=status,
                classification=classification,
            )

        # "graph" or "both" — return Graph alerts for backward compat
        return self._list_graph_alerts(
            since=since, until=until, service_source=service_source,
            status=status, classification=classification,
        )

    def _list_graph_alerts(
        self,
        *,
        since: datetime | None = None,
        until: datetime | None = None,
        service_source: str | None = None,
        status: str | None = None,
        classification: str | None = None,
    ) -> list[dict]:
        """Fetch alerts from Graph alerts_v2 with OData $filter."""
        filters: list[str] = []
        if since:
            filters.append(
                f"createdDateTime ge {since.strftime('%Y-%m-%dT%H:%M:%SZ')}"
            )
        if until:
            filters.append(
                f"createdDateTime lt {until.strftime('%Y-%m-%dT%H:%M:%SZ')}"
            )
        if service_source:
            filters.append(f"serviceSource eq '{service_source}'")
        if status:
            filters.append(f"status eq '{status}'")
        if classification:
            filters.append(f"classification eq '{classification}'")

        url = "/alerts_v2"
        params: list[str] = []
        if filters:
            params.append("$filter=" + " and ".join(filters))
        params.append("$top=500")

        if params:
            url = url + "?" + "&".join(params)

        return paginate(
            lambda u: self._request_with_retry("GET", u),
            url,
            next_link_key="@odata.nextLink",
        )

    def _list_sentinel_incidents(
        self,
        *,
        since: datetime | None = None,
        until: datetime | None = None,
        status: str | None = None,
        classification: str | None = None,
    ) -> list[dict]:
        """Fetch incidents from Sentinel ARM with server-side time filter.

        The Sentinel ARM incidents API supports OData ``$filter`` on
        ``properties/createdTimeUtc``. We push the time range to the
        server to avoid fetching the full incident history.
        """
        if self._sentinel is None:
            raise RuntimeError("Sentinel fallback requested but no provider configured")

        base_url = self._sentinel.resource_url("incidents")
        filters: list[str] = []
        if since:
            filters.append(
                f"properties/createdTimeUtc ge {since.strftime('%Y-%m-%dT%H:%M:%SZ')}"
            )
        if until:
            filters.append(
                f"properties/createdTimeUtc lt {until.strftime('%Y-%m-%dT%H:%M:%SZ')}"
            )
        if filters:
            base_url += "&$filter=" + " and ".join(filters)
        base_url += "&$top=500"

        all_incidents = paginate(
            lambda u: self._sentinel.request("GET", u),
            base_url,
            next_link_key="nextLink",
        )

        # Time filtering is server-side; status/classification still client-side
        if not status and not classification:
            return all_incidents

        filtered: list[dict] = []
        for inc in all_incidents:
            props = inc.get("properties", inc)
            if status:
                inc_status = (props.get("status") or "").lower()
                status_map = {
                    "new": "new",
                    "inprogress": "active",
                    "resolved": "closed",
                }
                target = status_map.get(status.lower(), status.lower())
                if inc_status != target:
                    continue
            if classification:
                inc_class = (props.get("classification") or "").lower()
                if inc_class != classification.lower():
                    continue
            filtered.append(inc)

        return filtered

    def list_alerts_for_date(self, target_date: str) -> list[dict]:
        """Fetch alerts for a single date via KQL. Falls back to Graph.

        ``target_date`` is ``YYYY-MM-DD``. Returns deduplicated rows.
        """
        if self._workspace_id:
            from contentops.workspace_kql import (
                LA_SCOPE,
                query as kql_query,
                security_alerts_for_date_query,
            )
            kql = security_alerts_for_date_query(target_date=target_date)
            token = self._credential.get_token(LA_SCOPE).token
            result = kql_query(kql, workspace_id=self._workspace_id, token=token)
            logger.info("KQL SecurityAlert for %s: %d rows", target_date, len(result.rows))
            return result.rows

        # Fallback: Graph with date filter
        from datetime import datetime as _dt, timedelta as _td, timezone as _tz
        d = _dt.fromisoformat(target_date).replace(tzinfo=_tz.utc)
        return self._list_graph_alerts(since=d, until=d + _td(days=1))

    def list_alerts_for_date_joined(self, target_date: str) -> list[dict]:
        """Fetch alerts for a single date via joined KQL (SecurityAlert+SecurityIncident).

        Falls back to ``list_alerts_for_date`` (non-joined) on failure.
        """
        if self._workspace_id:
            try:
                from contentops.workspace_kql import (
                    LA_SCOPE,
                    query as kql_query,
                    security_alerts_joined_for_date_query,
                )
                kql = security_alerts_joined_for_date_query(target_date=target_date)
                token = self._credential.get_token(LA_SCOPE).token
                result = kql_query(kql, workspace_id=self._workspace_id, token=token)
                logger.info("KQL joined SecurityAlert+SecurityIncident for %s: %d rows", target_date, len(result.rows))
                return result.rows
            except Exception as exc:
                logger.warning("Joined KQL failed for %s, falling back to non-joined: %s", target_date, exc)

        return self.list_alerts_for_date(target_date)

    def list_recently_modified_incidents(
        self,
        *,
        modified_days: int = 30,
    ) -> list[dict]:
        """Fetch ARM incidents modified in the last N days.

        Used for the ARM overlay: patches daily files with incident
        lifecycle updates (closures, reclassifications, reopenings).
        """
        if self._sentinel is None:
            logger.info("ARM overlay: no Sentinel provider configured, skipping")
            return []

        from datetime import datetime as _dt, timedelta as _td, timezone as _tz
        since = _dt.now(_tz.utc) - _td(days=modified_days)
        since_str = since.strftime("%Y-%m-%dT%H:%M:%SZ")

        base_url = self._sentinel.resource_url("incidents")
        base_url += f"&$filter=properties/lastModifiedTimeUtc ge {since_str}"
        base_url += "&$top=500"

        try:
            from contentops.utils.http_retry import paginate
            incidents = paginate(
                lambda u: self._sentinel.request("GET", u),
                base_url,
                next_link_key="nextLink",
            )
            logger.info("ARM overlay: fetched %d recently modified incidents (last %d days)", len(incidents), modified_days)
            return incidents
        except Exception as exc:
            logger.warning("ARM overlay: failed to fetch incidents: %s", exc)
            return []

    def list_graph_alerts_for_date(self, target_date: str) -> list[dict]:
        """Fetch Graph alerts_v2 for a single date (for enrichment pass)."""
        from datetime import datetime as _dt, timedelta as _td, timezone as _tz
        d = _dt.fromisoformat(target_date).replace(tzinfo=_tz.utc)
        try:
            return self._list_graph_alerts(since=d, until=d + _td(days=1))
        except Exception as exc:
            logger.warning("Graph enrichment: failed for %s: %s", target_date, exc)
            return []

    def _list_sentinel_kql_alerts(
        self,
        *,
        since: datetime | None = None,
        until: datetime | None = None,
    ) -> list[dict]:
        """Fetch individual alerts from the SecurityAlert table via KQL.

        Returns raw dicts (one per alert row) with ``SystemAlertId`` as
        the unique key. Much richer than ARM incidents and directly
        joinable with Graph alerts via ``providerAlertId``.
        """
        from contentops.workspace_kql import LA_SCOPE, query as kql_query, security_alerts_query

        since_days = 30
        if since and until:
            since_days = max(1, (until - since).days)

        kql = security_alerts_query(since_days=since_days)
        token = self._credential.get_token(LA_SCOPE).token
        result = kql_query(
            kql,
            workspace_id=self._workspace_id,
            token=token,
        )
        logger.info("KQL SecurityAlert returned %d rows", len(result.rows))
        return result.rows

    def close(self) -> None:
        """Close the HTTP client."""
        self._client.close()


__all__ = [
    "GraphAlertsProvider",
    "GRAPH_ALERTS_BASE",
    "GRAPH_ALERTS_TIMEOUT",
    "SourcedAlerts",
]
