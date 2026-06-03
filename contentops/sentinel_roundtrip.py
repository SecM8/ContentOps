# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Sentinel roundtrip-diff dispatch surface.

The diff renderer + ``FieldDiff`` / ``diff_bodies`` types live in
``contentops/utils/roundtrip_diff.py`` (shared with Defender). This
module adds Sentinel-specific dispatch: given the asset kind of a
local envelope, return the right handler's ``_strip_server_fields``
helper, ``_HASHED_FIELDS`` projection (or projection helper for
data_connector), and ARM resource collection name -- so the CLI
command in ``diagnostics.py`` stays asset-agnostic.

When ``contentops apply`` reports ``verified=False`` for a Sentinel
rule, the operator's diagnostic flow is:

  contentops sentinel-roundtrip-diff <envelope_id>

which lands here for dispatch.
"""

from __future__ import annotations

from typing import Any, Callable, NamedTuple

from contentops.core.asset import Asset


class _SentinelDispatch(NamedTuple):
    """Per-handler bits the diagnostic CLI needs.

    Keeping this typed (NamedTuple, not a dict) means asset additions
    that miss a handler trigger a clear AttributeError instead of a
    silent KeyError at diagnostic time.
    """

    resource: str
    """ARM sub-resource collection (``alertRules``, ``savedSearches``,
    ``watchlists``, ``dataConnectors``)."""

    strip_server_fields: Callable[[dict], dict]
    """Pure function returning ``remote`` with server-managed fields
    removed."""

    hashed_fields: Callable[[dict], list[str]]
    """Returns the projection used for hash compare. Takes the local
    body (or remote) so the analytic handler can dispatch on
    ``kind``."""

    use_la_path: bool = False
    """When True, the diagnostic must fetch the remote via
    ``provider.la_resource_url`` (raw Log Analytics workspace path)
    instead of ``provider.get_resource`` (which builds the
    ``Microsoft.SecurityInsights`` namespace path). Hunting and parser
    are savedSearches under the LA workspace; analytic and watchlist
    live under SecurityInsights. Without this flag the diagnostic
    404s for hunting and parser in any real tenant -- regression
    found in the PR #142 review."""


def _analytic_hashed_fields(body: dict) -> list[str]:
    from contentops.handlers.sentinel_analytic import _hashed_fields_for_kind
    kind = body.get("kind") or (body.get("properties") or {}).get("kind") or "Scheduled"
    return _hashed_fields_for_kind(kind)


def dispatch_for_asset(asset: Asset) -> _SentinelDispatch:
    """Return the dispatch bundle for ``asset``.

    Raises ``ValueError`` for non-Sentinel assets and for
    ``data_connector`` (which uses the ``_projection`` API, not the
    ``_HASHED_FIELDS`` shape; if a diagnostic is needed for it,
    extend this dispatch with a separate ``projection_fn`` field).
    """
    if asset == Asset.SENTINEL_ANALYTIC:
        from contentops.handlers.sentinel_analytic import _strip_server_fields
        return _SentinelDispatch(
            resource="alertRules",
            strip_server_fields=_strip_server_fields,
            hashed_fields=_analytic_hashed_fields,
        )
    if asset == Asset.SENTINEL_HUNTING:
        from contentops.handlers.sentinel_hunting import (
            _HASHED_FIELDS, _strip_server_fields,
        )
        return _SentinelDispatch(
            resource="savedSearches",
            strip_server_fields=_strip_server_fields,
            hashed_fields=lambda _body: list(_HASHED_FIELDS),
            use_la_path=True,
        )
    if asset == Asset.SENTINEL_PARSER:
        from contentops.handlers.sentinel_parser import (
            _HASHED_FIELDS, _strip_server_fields,
        )
        return _SentinelDispatch(
            resource="savedSearches",
            strip_server_fields=_strip_server_fields,
            hashed_fields=lambda _body: list(_HASHED_FIELDS),
            use_la_path=True,
        )
    if asset == Asset.SENTINEL_WATCHLIST:
        from contentops.handlers.sentinel_watchlist import (
            _HASHED_FIELDS, _strip_server_fields,
        )
        return _SentinelDispatch(
            resource="watchlists",
            strip_server_fields=_strip_server_fields,
            hashed_fields=lambda _body: list(_HASHED_FIELDS),
        )
    if asset == Asset.DEFENDER_CUSTOM_DETECTION:
        raise ValueError(
            "sentinel-roundtrip-diff does not handle Defender envelopes. "
            "Use `contentops defender-roundtrip-diff <envelope_id>` instead."
        )
    raise ValueError(
        f"sentinel-roundtrip-diff does not support asset kind {asset.value!r}. "
        "Supported: sentinel_analytic, sentinel_hunting, sentinel_parser, "
        "sentinel_watchlist. (sentinel_data_connector uses a _projection() "
        "helper instead of _HASHED_FIELDS; for connector mismatches read the "
        "apply summary directly.)"
    )


__all__ = ["dispatch_for_asset"]
