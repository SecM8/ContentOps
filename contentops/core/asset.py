# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Asset taxonomy.

Focused single-tenant detection-engineering surface:

* ``sentinel_analytic`` and ``defender_custom_detection`` — first-class
  detection content; the strategic product targets.
* ``sentinel_hunting``, ``sentinel_watchlist``, ``sentinel_parser``,
  ``sentinel_data_connector`` — supporting assets that detection content
  depends on.
* ``sentinel_automation_rule`` and ``sentinel_playbook`` — the response
  and noise-control layer next to detections: Sentinel automation rules
  (including the "suppression" rules that auto-close noisy incidents)
  and the Logic App playbooks those rules call. Deployable and
  drift-capable; see :data:`NON_DETECTION_ASSETS` for how they differ
  from detection content in lint, coverage, and reporting.

Broad-Sentinel everything-management surfaces (workbooks, bookmarks,
hunts, content packages, TI indicators, workspace manager, source
control, incidents, settings, onboarding, metadata) were deleted in the
asset-taxonomy reduction. They can be rebuilt from git history if
needed; out of scope for the focused product.
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
    SENTINEL_AUTOMATION_RULE = "sentinel_automation_rule"
    SENTINEL_PLAYBOOK = "sentinel_playbook"


# The detection-class kinds: assets that carry a query and MITRE ATT&CK
# attribution. Single definition; coverage, report and portfolio alias it.
DETECTION_ASSETS: frozenset[Asset] = frozenset({
    Asset.SENTINEL_ANALYTIC,
    Asset.SENTINEL_HUNTING,
    Asset.DEFENDER_CUSTOM_DETECTION,
})


def payload_display_name(payload: object) -> str:
    """The rule's display name as the platform shows it (``displayName``;
    ``DisplayName`` on some collected payloads), or ``""``."""
    if not isinstance(payload, dict):
        return ""
    for key in ("displayName", "DisplayName"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


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


# Kinds that are NOT detection content. They carry no KQL, no MITRE
# mapping, are excluded from coverage maths and the detection inventory
# report, and run a reduced metadata lint set (owner / description /
# freshness, not severity / tactics / alert volume). ``parse_envelope``
# validates their ``metadata:`` block with ``SupportAssetMetadata``
# instead of ``RuleMetadata``.
#
# Code that iterates *every* envelope (coverage evidence, the Navigator
# repo axis, the metadata lint runner) checks membership here so a
# stray ``techniques:`` on a playbook can never inflate a heatmap.
NON_DETECTION_ASSETS: frozenset[Asset] = frozenset({
    Asset.SENTINEL_AUTOMATION_RULE,
    Asset.SENTINEL_PLAYBOOK,
})


# Per-kind apply ordering. ``contentops apply`` processes envelopes
# sorted by ``(APPLY_ORDER_BY_ASSET.get(kind, APPLY_ORDER_DEFAULT),
# path)``; the stable sort keeps today's path order inside each tier.
#
#   10  playbooks      — no dependencies; must exist before any
#                        automation rule that runs them.
#   50  everything else (analytics, hunting, watchlists, parsers,
#                        connectors, Defender) — unchanged order.
#   90  automation rules — an ``analytic:<id>`` scope condition needs
#                        the analytics rule to exist remotely, and a
#                        ``playbook:<id>`` action needs the Logic App.
APPLY_ORDER_DEFAULT = 50
APPLY_ORDER_BY_ASSET: dict[Asset, int] = {
    Asset.SENTINEL_PLAYBOOK: 10,
    Asset.SENTINEL_AUTOMATION_RULE: 90,
}


# Per-kind management mode defaults (see ``WorkspaceSafeguards.assetModes``
# in contentops/config.py). ``managed`` = apply writes and prune deletes;
# ``monitor`` = collect / drift / lint only, apply skips, prune refuses.
#
# The defaults live HERE, in code, not in config/tenant.yml.example:
# an existing tenant secret that pre-dates a kind carries no
# ``assetModes`` entry for it, so the code default is what a fork gets
# on upgrade. New kinds therefore default to ``monitor`` — a
# post-upgrade ``prune`` with zero local files for the kind can never
# delete the tenant's portal-created rules. Flipping a kind to
# ``managed`` is an explicit operator opt-in in tenant.yml.
AssetMode = str  # "managed" | "monitor" (Literal lives in config.py)
ASSET_MODE_MANAGED = "managed"
ASSET_MODE_MONITOR = "monitor"
DEFAULT_ASSET_MODES: dict[Asset, str] = {
    Asset.SENTINEL_ANALYTIC: ASSET_MODE_MANAGED,
    Asset.SENTINEL_HUNTING: ASSET_MODE_MANAGED,
    Asset.SENTINEL_WATCHLIST: ASSET_MODE_MANAGED,
    Asset.SENTINEL_PARSER: ASSET_MODE_MANAGED,
    Asset.SENTINEL_DATA_CONNECTOR: ASSET_MODE_MANAGED,
    Asset.DEFENDER_CUSTOM_DETECTION: ASSET_MODE_MANAGED,
    Asset.SENTINEL_AUTOMATION_RULE: ASSET_MODE_MONITOR,
    Asset.SENTINEL_PLAYBOOK: ASSET_MODE_MONITOR,
}


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
    data_connector / automation rule / playbook) or the field is
    absent / empty.

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
