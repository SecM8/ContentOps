# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Fetch Defender XDR table schemas via Microsoft Graph Advanced Hunting.

Refreshes ``tools/kql_strict/schemas_defender.json`` from the live
tenant by running ``<table> | getschema | project ColumnName,
ColumnType`` for each known Defender table. The Defender schema is
tenant-invariant on a given license tier, so this fetcher is the
"keep the vendored file current" half of PR-H — the file remains the
canonical source for public-mirror adopters but the column lists no
longer drift behind Microsoft's releases.

Required Graph permission: ``ThreatHunting.Read.All`` (application
scope; no delegated alternative). Manual admin consent on the App
Registration; see ``docs/operations/authentication-setup.md``.

API contract:

    POST https://graph.microsoft.com/v1.0/security/runHuntingQuery
    body: {"Query": "DeviceEvents | getschema | project ColumnName, ColumnType"}
    -> 200 {"schema": [{"name": "ColumnName", "type": "String"},
                       {"name": "ColumnType", "type": "String"}],
            "results": [{"ColumnName": "DeviceId", "ColumnType": "string"},
                        ...]}

The `schema` block describes the result-projection types (here:
strings). The `results` rows carry the actual table schema.
"""

from __future__ import annotations

from typing import Any

import httpx

from contentops.utils.http_retry import request_with_retry
from contentops.utils.token_auth import BearerTokenAuth


GRAPH_BASE_URL = "https://graph.microsoft.com"
HUNTING_PATH = "/v1.0/security/runHuntingQuery"
GRAPH_HTTP_TIMEOUT = httpx.Timeout(connect=10.0, read=180.0, write=30.0, pool=10.0)


class DefenderSchemaError(RuntimeError):
    """Raised when the Graph runHuntingQuery call returns an unrecoverable error."""


def _build_client(
    *, credential: Any | None, token: str | None,
    transport: httpx.BaseTransport | None,
) -> httpx.Client:
    headers: dict[str, str] = {"Content-Type": "application/json"}
    auth: httpx.Auth | None = None
    if credential is not None:
        from contentops.utils.auth import get_graph_access_token
        auth = BearerTokenAuth(lambda: get_graph_access_token(credential))
    elif token is not None:
        headers["Authorization"] = f"Bearer {token}"
    else:
        raise ValueError(
            "fetch requires either a credential or an explicit bearer token"
        )
    return httpx.Client(
        base_url=GRAPH_BASE_URL,
        headers=headers,
        auth=auth,
        timeout=GRAPH_HTTP_TIMEOUT,
        transport=transport,
    )


def fetch_table_schema(
    table_name: str, *,
    credential: Any | None = None,
    token: str | None = None,
    transport: httpx.BaseTransport | None = None,
) -> list[dict[str, str]]:
    """Return ``[{name, type}, ...]`` for one Defender table.

    Raises ``DefenderSchemaError`` on:
      * empty / whitespace table name
      * Graph 401 / 403 (carries a hint to grant ``ThreatHunting.Read.All``)
      * Graph 404 / "table unknown" (caller decides whether to skip or
        bubble — typically used to keep the baseline entry intact)
      * Other 4xx / 5xx
      * Malformed response body

    The `request_with_retry` wrapper handles 429 + 5xx Retry-After
    transparently, so callers see only terminal failures.
    """
    if not table_name or not table_name.strip():
        raise DefenderSchemaError("table_name is required")

    client = _build_client(
        credential=credential, token=token, transport=transport,
    )
    body = {
        "Query": f"{table_name} | getschema | project ColumnName, ColumnType",
    }
    try:
        response = request_with_retry(
            lambda: client.post(HUNTING_PATH, json=body),
            label=f"Graph runHuntingQuery {table_name} getschema",
        )
    finally:
        client.close()

    status = response.status_code
    if status in (401, 403):
        raise DefenderSchemaError(
            f"Graph runHuntingQuery returned {status} for {table_name!r}; "
            "grant ThreatHunting.Read.All on the App Registration "
            "(see docs/operations/authentication-setup.md)."
        )
    if status == 404:
        raise DefenderSchemaError(
            f"Graph runHuntingQuery returned 404 for {table_name!r}; "
            "table not reachable in this tenant's Defender entitlement."
        )
    if status == 400:
        # The Graph hunting parser returns 400 + "Failed to resolve
        # table" when the tenant's entitlement doesn't include the
        # table (e.g. Defender Vulnerability Management Add-on
        # tables on a Defender-for-Endpoint-only tenant). Treat the
        # same as 404 — preserve the existing baseline entry rather
        # than failing the whole refresh.
        body_text = response.text or ""
        if (
            "Failed to resolve table" in body_text
            or "resolve table or column" in body_text
        ):
            raise DefenderSchemaError(
                f"Graph runHuntingQuery returned 400 for {table_name!r}; "
                "table not reachable in this tenant's Defender entitlement."
            )
        raise DefenderSchemaError(
            f"Graph runHuntingQuery returned 400 for {table_name!r}: "
            f"{body_text[:200]}"
        )
    if status >= 400:
        raise DefenderSchemaError(
            f"Graph runHuntingQuery returned {status} for {table_name!r}: "
            f"{response.text[:200]}"
        )

    try:
        payload = response.json()
    except Exception as exc:
        raise DefenderSchemaError(
            f"Graph response for {table_name!r} not JSON: {exc}"
        ) from exc

    rows = payload.get("results") or []
    out: list[dict[str, str]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        col_name = str(row.get("ColumnName") or "").strip()
        col_type = str(row.get("ColumnType") or "").strip().lower()
        if not col_name or not col_type:
            continue
        out.append({"name": col_name, "type": col_type})
    return out


def fetch_defender_schemas(
    seed_tables: list[str], *,
    credential: Any | None = None,
    token: str | None = None,
    transport: httpx.BaseTransport | None = None,
    fetch_fn: Any | None = None,
) -> tuple[list[dict[str, Any]], list[str]]:
    """Refresh schemas for every name in ``seed_tables``.

    Returns ``(refreshed_tables, skipped_table_names)``:
      * ``refreshed_tables`` is a list of ``{name, columns}`` dicts
        in input order, ready to merge into the existing baseline.
      * ``skipped_table_names`` is the subset for which Graph
        returned 404 (table not in this tenant's Defender
        entitlement). Callers preserve those tables' existing
        baseline columns -- don't accidentally drop a Defender
        table from the vendored file when the refreshing tenant's
        license doesn't include it.

    The ``fetch_fn`` parameter is for tests; defaults to
    ``fetch_table_schema``.
    """
    fetcher = fetch_fn if fetch_fn is not None else fetch_table_schema
    refreshed: list[dict[str, Any]] = []
    skipped: list[str] = []
    for name in seed_tables:
        try:
            columns = fetcher(
                name,
                credential=credential, token=token, transport=transport,
            )
        except DefenderSchemaError as exc:
            # Per-table entitlement gaps (404 OR 400 with the parser's
            # "Failed to resolve table" message) are downgraded to a
            # skip-and-preserve so one ungranted Add-on table can't
            # take down the whole refresh. 401/403 (permission missing)
            # and other unexpected errors propagate.
            msg = str(exc)
            if "entitlement" in msg or "404" in msg:
                skipped.append(name)
                continue
            raise
        refreshed.append({"name": name, "columns": columns})
    return refreshed, skipped


__all__ = [
    "DefenderSchemaError",
    "GRAPH_BASE_URL",
    "GRAPH_HTTP_TIMEOUT",
    "HUNTING_PATH",
    "fetch_defender_schemas",
    "fetch_table_schema",
]
