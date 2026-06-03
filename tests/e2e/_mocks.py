# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Reusable respx route bundles for the e2e capability matrix.

Each bundle registers a coherent set of mock HTTP routes against the
shared ``respx.MockRouter`` so the capability test can exercise the
real CLI code path for Azure-needing commands without touching a live
tenant.

The bundles are functions because activation order matters: the matrix
test loads only the bundles each capability declares in
``Capability.mock_routes``. Idempotent — registering a bundle twice is
harmless (respx returns the same route).

Bundles share two tiny in-memory stores (``_ArmStore`` / ``_GraphStore``)
so a PUT followed by a GET reads back the same payload. That's what
makes ``drift`` / ``collect`` / ``*-roundtrip-diff`` exercise their
real diff logic rather than always seeing an empty tenant.
"""

from __future__ import annotations

import json
import re
from typing import Any

import httpx
import respx


# ---------------------------------------------------------------------------
# In-memory stores backing the mock endpoints
# ---------------------------------------------------------------------------


class _ArmStore:
    """Per-resource-type map: {resource_type: {name: body}}.

    Keys are the ARM resource collection name (``alertRules``,
    ``watchlists``, ``dataConnectors``). Values are the JSON bodies the
    tenant would store. Seeded empty; PUTs populate, GETs read back.
    """

    def __init__(self) -> None:
        self._data: dict[str, dict[str, dict[str, Any]]] = {}

    def list(self, resource: str) -> list[dict[str, Any]]:
        return list(self._data.get(resource, {}).values())

    def get(self, resource: str, name: str) -> dict[str, Any] | None:
        return (self._data.get(resource) or {}).get(name)

    def put(self, resource: str, name: str, body: dict[str, Any]) -> dict[str, Any]:
        body = dict(body)
        body.setdefault("name", name)
        body.setdefault("id", f"/synthetic/{resource}/{name}")
        bucket = self._data.setdefault(resource, {})
        bucket[name] = body
        return body

    def delete(self, resource: str, name: str) -> bool:
        bucket = self._data.get(resource) or {}
        return bucket.pop(name, None) is not None


class _GraphStore:
    """Defender Graph custom detection rule store."""

    def __init__(self) -> None:
        self._data: dict[str, dict[str, Any]] = {}
        self._counter = 0

    def list(self) -> list[dict[str, Any]]:
        return list(self._data.values())

    def get(self, rule_id: str) -> dict[str, Any] | None:
        return self._data.get(rule_id)

    def create(self, body: dict[str, Any]) -> dict[str, Any]:
        self._counter += 1
        rid = body.get("id") or f"graph-rule-{self._counter:04d}"
        stored = dict(body)
        stored["id"] = rid
        self._data[rid] = stored
        return stored

    def update(self, rule_id: str, body: dict[str, Any]) -> dict[str, Any] | None:
        if rule_id not in self._data:
            return None
        self._data[rule_id].update(body)
        return self._data[rule_id]

    def delete(self, rule_id: str) -> bool:
        return self._data.pop(rule_id, None) is not None


# Shared singletons for the session. The conftest resets them between
# capability invocations via ``reset_stores``.
ARM_STORE = _ArmStore()
GRAPH_STORE = _GraphStore()


def reset_stores() -> None:
    """Clear the in-memory stores between capability invocations."""
    ARM_STORE._data.clear()  # noqa: SLF001
    GRAPH_STORE._data.clear()  # noqa: SLF001
    GRAPH_STORE._counter = 0  # noqa: SLF001


# ---------------------------------------------------------------------------
# Bundle: OIDC / token endpoints
# ---------------------------------------------------------------------------


_TOKEN_RESPONSE = {
    "token_type": "Bearer",
    "expires_in": 3600,
    "ext_expires_in": 3600,
    "access_token": "mock.access.token.for.e2e",
}


def oidc_token(router: respx.MockRouter) -> None:
    """Mock the AAD oauth2 token endpoint + IMDS managed-identity probe.

    Covers any code path that defensively instantiates a credential
    (``DefaultAzureCredential`` walks the chain regardless of whether
    we end up actually issuing requests against it).
    """
    router.post(
        url__regex=re.compile(
            r"^https://login\.microsoftonline\.com/.+/oauth2/v2\.0/token$",
        ),
    ).mock(return_value=httpx.Response(200, json=_TOKEN_RESPONSE))

    # IMDS / Workload Identity probes — DefaultAzureCredential tries
    # these before falling through to env-var auth. Return 400 so the
    # chain advances quickly.
    router.get(
        url__regex=re.compile(r"^http://169\.254\.169\.254/.+"),
    ).mock(return_value=httpx.Response(400, text="not available in e2e"))


# ---------------------------------------------------------------------------
# Bundle: Sentinel ARM
# ---------------------------------------------------------------------------


_ARM_BASE = "https://management.azure.com"
# Collection-level URL: .../providers/Microsoft.SecurityInsights/<resource>?api-version=...
_ARM_COLLECTION_RE = re.compile(
    r"^https://management\.azure\.com"
    r"/subscriptions/[^/]+"
    r"/resourceGroups/[^/]+"
    r"/providers/Microsoft\.OperationalInsights"
    r"/workspaces/[^/]+"
    r"/providers/Microsoft\.SecurityInsights"
    r"/(?P<resource>[A-Za-z]+)"
    r"(?:\?.*)?$"
)
# Item-level URL: same but with /<name> appended.
_ARM_ITEM_RE = re.compile(
    r"^https://management\.azure\.com"
    r"/subscriptions/[^/]+"
    r"/resourceGroups/[^/]+"
    r"/providers/Microsoft\.OperationalInsights"
    r"/workspaces/[^/]+"
    r"/providers/Microsoft\.SecurityInsights"
    r"/(?P<resource>[A-Za-z]+)"
    r"/(?P<name>[^/?]+)"
    r"(?:\?.*)?$"
)
# LA-path items (savedSearches etc., used by hunting/parser handlers).
_LA_ITEM_RE = re.compile(
    r"^https://management\.azure\.com"
    r"/subscriptions/[^/]+"
    r"/resourceGroups/[^/]+"
    r"/providers/Microsoft\.OperationalInsights"
    r"/workspaces/[^/]+"
    r"/(?P<resource>[A-Za-z]+)"
    r"/(?P<name>[^/?]+)"
    r"(?:\?.*)?$"
)
# Resource group + workspace level (for bootstrap probes)
_RG_RE = re.compile(
    r"^https://management\.azure\.com"
    r"/subscriptions/[^/]+/resourceGroups/[^/?]+(?:\?.*)?$"
)
_WS_RE = re.compile(
    r"^https://management\.azure\.com"
    r"/subscriptions/[^/]+/resourceGroups/[^/]+"
    r"/providers/Microsoft\.OperationalInsights/workspaces/[^/?]+"
    r"(?:\?.*)?$"
)


def _arm_collection_handler(request: httpx.Request) -> httpx.Response:
    m = _ARM_COLLECTION_RE.match(str(request.url))
    if m is None:
        return httpx.Response(404, json={"error": {"code": "NotFound"}})
    resource = m.group("resource")
    return httpx.Response(200, json={"value": ARM_STORE.list(resource)})


def _arm_item_handler(request: httpx.Request) -> httpx.Response:
    m = _ARM_ITEM_RE.match(str(request.url))
    if m is None:
        return httpx.Response(404, json={"error": {"code": "NotFound"}})
    resource = m.group("resource")
    name = m.group("name")
    method = request.method.upper()
    if method == "GET":
        body = ARM_STORE.get(resource, name)
        if body is None:
            return httpx.Response(
                404,
                json={"error": {"code": "ResourceNotFound", "message": name}},
            )
        return httpx.Response(200, json=body)
    if method == "PUT":
        try:
            body = request.content and json.loads(request.content)
        except Exception:
            body = {}
        if not isinstance(body, dict):
            body = {}
        stored = ARM_STORE.put(resource, name, body)
        return httpx.Response(201, json=stored)
    if method == "DELETE":
        existed = ARM_STORE.delete(resource, name)
        return httpx.Response(204 if existed else 404)
    return httpx.Response(405, json={"error": "method not allowed"})


def arm_sentinel(router: respx.MockRouter) -> None:
    """ARM CRUD for Sentinel resources (alertRules, watchlists, etc.).

    Also covers the LA-workspace path used by bootstrap (RG +
    workspace GET/PUT) and the savedSearches path used by hunting/
    parser round-trip handlers.
    """
    # Collection list (GET on the resource collection)
    router.get(url__regex=_ARM_COLLECTION_RE).mock(side_effect=_arm_collection_handler)
    # Item CRUD (GET/PUT/DELETE on /resource/name)
    router.route(url__regex=_ARM_ITEM_RE).mock(side_effect=_arm_item_handler)
    router.route(url__regex=_LA_ITEM_RE).mock(side_effect=_arm_item_handler)
    # Workspace existence probe (bootstrap GET) — always return 200.
    router.get(url__regex=_WS_RE).mock(
        return_value=httpx.Response(200, json={
            "name": "law-e2e-itest",
            "properties": {"sku": {"name": "PerGB2018"}, "retentionInDays": 90},
        }),
    )
    # Resource group existence probe — always return 200.
    router.get(url__regex=_RG_RE).mock(
        return_value=httpx.Response(
            200, json={"name": "rg-e2e-itest", "properties": {"provisioningState": "Succeeded"}},
        ),
    )


# ---------------------------------------------------------------------------
# Bundle: Defender Graph
# ---------------------------------------------------------------------------


_GRAPH_BASE = "https://graph.microsoft.com/beta/security/rules"
_GRAPH_COLLECTION_RE = re.compile(
    rf"^{re.escape(_GRAPH_BASE)}/detectionRules(?:\?.*)?$",
)
_GRAPH_ITEM_RE = re.compile(
    rf"^{re.escape(_GRAPH_BASE)}/detectionRules/(?P<id>[^/?]+)(?:\?.*)?$",
)
# Extension probe endpoints (savedQueries, detectionTuningRules, etc.).
_GRAPH_EXT_RE = re.compile(
    r"^https://graph\.microsoft\.com/beta/security/(?P<ext>[A-Za-z]+)(?:\?.*)?$",
)


def _graph_collection_handler(request: httpx.Request) -> httpx.Response:
    if request.method.upper() == "POST":
        try:
            body = json.loads(request.content or b"{}")
        except Exception:
            body = {}
        if not isinstance(body, dict):
            body = {}
        created = GRAPH_STORE.create(body)
        return httpx.Response(201, json=created)
    return httpx.Response(200, json={"value": GRAPH_STORE.list()})


def _graph_item_handler(request: httpx.Request) -> httpx.Response:
    m = _GRAPH_ITEM_RE.match(str(request.url))
    if m is None:
        return httpx.Response(404)
    rid = m.group("id")
    method = request.method.upper()
    if method == "GET":
        body = GRAPH_STORE.get(rid)
        return httpx.Response(
            200 if body else 404, json=body or {"error": "not found"},
        )
    if method in ("PATCH", "PUT"):
        try:
            body = json.loads(request.content or b"{}")
        except Exception:
            body = {}
        if not isinstance(body, dict):
            body = {}
        updated = GRAPH_STORE.update(rid, body)
        return httpx.Response(
            200 if updated else 404, json=updated or {"error": "not found"},
        )
    if method == "DELETE":
        existed = GRAPH_STORE.delete(rid)
        return httpx.Response(204 if existed else 404)
    return httpx.Response(405)


def graph_defender(router: respx.MockRouter) -> None:
    """Defender Graph detection-rule CRUD + extension probe endpoints."""
    router.route(url__regex=_GRAPH_COLLECTION_RE).mock(
        side_effect=_graph_collection_handler,
    )
    router.route(url__regex=_GRAPH_ITEM_RE).mock(side_effect=_graph_item_handler)

    # F11 extension probe — return 404 for every extension so the
    # probe reports "no GA endpoints available" (exit code 0). The
    # capability tolerates exit 2 so a future GA wouldn't fail the
    # test either.
    router.route(url__regex=_GRAPH_EXT_RE).mock(
        return_value=httpx.Response(404, text="extension not available"),
    )


# ---------------------------------------------------------------------------
# Bundle: Log Analytics Query API
# ---------------------------------------------------------------------------


_LA_QUERY_RE = re.compile(
    r"^https://api\.loganalytics\.io/v1/workspaces/[^/]+/query(?:\?.*)?$",
)


def _empty_la_response(request: httpx.Request) -> httpx.Response:
    """One empty PrimaryResult table — shape matches the LA Query API."""
    return httpx.Response(200, json={
        "tables": [
            {
                "name": "PrimaryResult",
                "columns": [
                    {"name": "Count", "type": "long"},
                ],
                "rows": [[0]],
            },
        ],
    })


def kql_query(router: respx.MockRouter) -> None:
    """Mock the Log Analytics Query API for silent-rules / rule-test."""
    router.post(url__regex=_LA_QUERY_RE).mock(side_effect=_empty_la_response)


# ---------------------------------------------------------------------------
# Bundle registry
# ---------------------------------------------------------------------------


BUNDLES: dict[str, callable] = {
    "oidc_token": oidc_token,
    "arm_sentinel": arm_sentinel,
    "graph_defender": graph_defender,
    "kql_query": kql_query,
}


def load_bundles(router: respx.MockRouter, names: tuple[str, ...]) -> None:
    """Activate each named bundle on the shared router. Idempotent."""
    for name in names:
        bundle = BUNDLES.get(name)
        if bundle is None:
            raise KeyError(f"unknown mock bundle: {name!r}")
        bundle(router)


__all__ = [
    "ARM_STORE",
    "BUNDLES",
    "GRAPH_STORE",
    "arm_sentinel",
    "graph_defender",
    "kql_query",
    "load_bundles",
    "oidc_token",
    "reset_stores",
]
