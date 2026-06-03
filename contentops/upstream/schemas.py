# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Fetch + normalise Log Analytics workspace schema metadata (F1.1).

Closes the schema-loading half of G1. The KQL strict-lint wrapper at
`tools/kql_strict/` reads a JSON file produced from this fetcher and
loads it into the Kusto.Language parser's `GlobalState`, so semantic
diagnostics (KS204 / KS142 / …) reflect the real Sentinel + Defender
XDR table surface instead of bare Azure Data Explorer.

The Log Analytics Query API endpoint `/v1/workspaces/<id>/metadata`
returns every table connected to the workspace -- including the
Defender XDR pseudo-tables (`DeviceEvents`, `DeviceProcessEvents`,
…) when the Microsoft 365 Defender connector is wired up. A single
fetch covers both halves of the schema surface.
"""

from __future__ import annotations

import fnmatch
from typing import Any

import httpx

from contentops.utils.http_retry import request_with_retry


METADATA_PATH = "/v1/workspaces/{workspace_id}/metadata"
METADATA_BASE_URL = "https://api.loganalytics.io"


def fetch_schemas(
    *,
    workspace_id: str,
    token: str,
    transport: httpx.BaseTransport | None = None,
    timeout: float | httpx.Timeout = httpx.Timeout(
        connect=10.0, read=30.0, write=30.0, pool=10.0,
    ),
) -> list[dict[str, Any]]:
    """Query LA metadata and return a normalised list of table entries.

    Each entry has the shape consumed by ``tools/kql_strict/schemas.json``:

        {
          "name": "<table-name>",
          "columns": [{"name": "<col>", "type": "<kql-type>"}, ...]
        }

    Tables without a name are dropped. Columns without a name OR type
    are dropped. The Kusto.Language parser accepts the LA-flavoured
    type strings (``string``, ``datetime``, ``long``, ``int``,
    ``real``, ``bool``, ``dynamic``, ``guid``, ``timespan``) directly.
    """
    if not workspace_id:
        raise ValueError("workspace_id is required")
    url = METADATA_PATH.format(workspace_id=workspace_id)
    client = httpx.Client(
        base_url=METADATA_BASE_URL,
        headers={"Authorization": f"Bearer {token}"},
        timeout=timeout,
        transport=transport,
    )
    try:
        response = request_with_retry(
            lambda: client.get(url),
            label="LA schema fetch",
        )
        response.raise_for_status()
        body = response.json()
    finally:
        client.close()

    out: list[dict[str, Any]] = []
    for table in body.get("tables") or []:
        name = str(table.get("name") or "").strip()
        if not name:
            continue
        columns: list[dict[str, str]] = []
        for col in table.get("columns") or []:
            col_name = str(col.get("name") or "").strip()
            col_type = str(col.get("type") or "").strip()
            if not col_name or not col_type:
                continue
            columns.append({"name": col_name, "type": col_type})
        out.append({"name": name, "columns": columns})
    out.sort(key=lambda t: t["name"])
    return out


def filter_excluded_tables(
    tables: list[dict[str, Any]],
    exclude_patterns: tuple[str, ...] | list[str],
) -> tuple[list[dict[str, Any]], list[str]]:
    """Drop tables whose name matches any case-insensitive glob pattern.

    Returns ``(kept_tables, dropped_names)``. Used to keep operator
    scratch / test custom-log tables (``TestMe_KQL_CL`` and friends) out
    of the committed, publicly-mirrored ``tools/kql_strict/schemas.json``.
    A table the operator excludes is also one no shipped detection queries,
    so dropping it from the lint schema has no real-world cost. No-op (and
    no copy) when ``exclude_patterns`` is empty."""
    if not exclude_patterns:
        return tables, []
    pats = [p.lower() for p in exclude_patterns if p]
    kept: list[dict[str, Any]] = []
    dropped: list[str] = []
    for table in tables:
        name = str(table.get("name") or "")
        if name and any(fnmatch.fnmatch(name.lower(), p) for p in pats):
            dropped.append(name)
        else:
            kept.append(table)
    return kept, dropped


__all__ = [
    "fetch_schemas",
    "filter_excluded_tables",
    "METADATA_PATH",
    "METADATA_BASE_URL",
]
