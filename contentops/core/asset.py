# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Asset taxonomy.

Focused single-tenant detection-engineering surface:

* ``sentinel_analytic`` and ``defender_custom_detection`` — first-class
  detection content; the strategic product targets.
* ``sentinel_hunting``, ``sentinel_watchlist``, ``sentinel_parser``,
  ``sentinel_data_connector`` — supporting assets that detection content
  depends on.

Broad-Sentinel everything-management surfaces (workbooks, automation /
playbooks, bookmarks, hunts, content packages, TI indicators, workspace
manager, source control, incidents, settings, onboarding, metadata) were
deleted in the asset-taxonomy reduction. They can be rebuilt from git
history if needed; out of scope for the focused product.
"""

from __future__ import annotations

import enum


class Asset(str, enum.Enum):
    SENTINEL_ANALYTIC = "sentinel_analytic"
    SENTINEL_HUNTING = "sentinel_hunting"
    SENTINEL_WATCHLIST = "sentinel_watchlist"
    SENTINEL_PARSER = "sentinel_parser"
    SENTINEL_DATA_CONNECTOR = "sentinel_data_connector"
    DEFENDER_CUSTOM_DETECTION = "defender_custom_detection"


# Baseline ``version`` stamped on a freshly collected / scaffolded
# envelope. The remote tenant has no semver concept for these assets, so
# collect/`to_envelope` must invent a starting version. We use 1.0.0
# (not the historical 0.1.0): these are deployed, production-grade rules,
# so a stable 1.x baseline is more honest than a pre-1.0 "unstable" tag.
# Single source of truth — every handler's ``to_envelope`` and the
# scaffold templater import this rather than hardcoding the literal.
# NB: a drift re-import never overwrites an existing file's version (see
# ``contentops.core.drift._preserve_local_version``), so changing this
# only affects assets collected/scaffolded for the first time.
COLLECT_BASELINE_VERSION = "1.0.0"


# Single source of truth for "which payload field(s) carry KQL".
# Consumed by the lint runner (KQL rules + KQLOVERRIDE rules) and by
# the snippet substitution engine. Kept here -- in the asset module --
# so additions to the taxonomy update KQL coverage in one place
# instead of two duplicated maps that historically drifted.
#
# The values are dotted payload paths so callers can support nested
# fields like Defender's ``queryCondition.queryText``.
KQL_FIELDS_BY_ASSET: dict[Asset, tuple[str, ...]] = {
    Asset.SENTINEL_ANALYTIC: ("query",),
    Asset.SENTINEL_HUNTING: ("query",),
    Asset.SENTINEL_PARSER: ("query",),
    Asset.DEFENDER_CUSTOM_DETECTION: ("queryText", "queryCondition.queryText"),
}


def kql_body_from_payload(asset: Asset, payload: dict) -> str | None:
    """Return the first non-empty KQL body for ``asset`` from ``payload``.

    Walks the dotted field paths in :data:`KQL_FIELDS_BY_ASSET` (so it
    supports nested fields like Defender's ``queryCondition.queryText``)
    and returns the first one that holds a non-blank string. Returns
    ``None`` when the asset kind carries no KQL (watchlist /
    data_connector) or the field is absent / empty.

    Single source of truth for "give me the rule's query" — shared by
    ``contentops rule-test`` and the ``live_test_pass`` promotion gate so
    the two never drift on where a kind's KQL lives.
    """
    if not isinstance(payload, dict):
        return None
    for field_path in KQL_FIELDS_BY_ASSET.get(asset, ()):
        cur: object = payload
        for part in field_path.split("."):
            if not isinstance(cur, dict) or part not in cur:
                cur = None
                break
            cur = cur[part]
        if isinstance(cur, str) and cur.strip():
            return cur
    return None
