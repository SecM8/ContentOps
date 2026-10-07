# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tuning impact preview — NVISO Part 8.

Compares two ``detections/drift_suppressions.yml`` blobs (typically
PR head vs. base) and identifies suppression entries that are new in
HEAD. For each new entry, resolves the corresponding envelope's
display name and telemetry keys (rule id, then display name -- see
:mod:`contentops.rule_keys`) and queries Log Analytics for the alert +
incident count over the lookback window.

The output is markdown suitable for posting as a PR comment by the
calling workflow.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from contentops.core.discovery import discover_assets, load_asset
from contentops.core.handler import LoadedAsset
from contentops.rule_keys import RuleKeys, rule_keys_for
from contentops.utils.markdown import gfm_cell


@dataclass(frozen=True)
class SuppressionKey:
    asset: str
    id: str


@dataclass(frozen=True)
class SuppressionEntry:
    asset: str
    id: str
    reason: str
    expires: str


def _parse_blob(blob: str | None) -> dict[SuppressionKey, SuppressionEntry]:
    """Parse a drift_suppressions.yml blob into {(asset,id): entry}.

    Tolerant of empty / missing / unparseable input — returns ``{}``.
    A PR that creates the file from scratch will have ``None`` for the
    base blob and that case must succeed.
    """
    if not blob:
        return {}
    try:
        raw = yaml.safe_load(blob)
    except yaml.YAMLError:
        return {}
    if not isinstance(raw, dict):
        return {}
    items = raw.get("suppressions") or []
    if not isinstance(items, list):
        return {}
    out: dict[SuppressionKey, SuppressionEntry] = {}
    for entry in items:
        if not isinstance(entry, dict):
            continue
        asset = str(entry.get("asset") or "")
        id_ = str(entry.get("id") or "")
        if not asset or not id_:
            continue
        out[SuppressionKey(asset=asset, id=id_)] = SuppressionEntry(
            asset=asset, id=id_,
            reason=str(entry.get("reason") or ""),
            expires=str(entry.get("expires") or ""),
        )
    return out


def new_suppressions(
    head_blob: str | None, base_blob: str | None,
) -> list[SuppressionEntry]:
    """Return suppression entries present in HEAD but not in BASE."""
    head = _parse_blob(head_blob)
    base = _parse_blob(base_blob)
    new_keys = sorted(head.keys() - base.keys(), key=lambda k: (k.asset, k.id))
    return [head[k] for k in new_keys]


def _find_envelope(detections_root: Path, asset: str, id_: str) -> LoadedAsset | None:
    for path in discover_assets(detections_root):
        if path.stem != id_:
            continue
        try:
            loaded = load_asset(path)
        except Exception:
            continue
        if loaded.envelope.asset.value != asset:
            continue
        return loaded
    return None


def resolve_display_name(
    detections_root: Path, asset: str, id_: str,
) -> str | None:
    """Find the envelope's display name for the (asset, id) pair.

    Shown in the report so reviewers recognise the rule.

    Returns None when the envelope can't be located — the caller renders
    that as "(envelope not found)" in the report instead of failing the
    workflow.
    """
    loaded = _find_envelope(detections_root, asset, id_)
    if loaded is None:
        return None
    return _extract_display_name(loaded.payload) or id_


def resolve_rule_keys(
    detections_root: Path, asset: str, id_: str,
) -> RuleKeys | None:
    """Telemetry keys for the (asset, id) pair, or None if not found.

    SecurityAlert / SecurityIncident name a Sentinel analytic rule by id
    (``AlertType``, ``RelatedAnalyticRuleIds``) and by display name
    (``AlertName`` / ``Title``, which ``alertDisplayNameFormat`` and
    analysts change); the impact query matches the id first.
    """
    loaded = _find_envelope(detections_root, asset, id_)
    return rule_keys_for(loaded) if loaded is not None else None


def _extract_display_name(payload: Any) -> str | None:
    """Pull a display name out of a payload, trying common shapes."""
    if not isinstance(payload, dict):
        return None
    for key in ("displayName", "name"):
        v = payload.get(key)
        if isinstance(v, str) and v.strip():
            return v
    # Defender custom detection ARM shape uses properties.displayName.
    props = payload.get("properties")
    if isinstance(props, dict):
        v = props.get("displayName")
        if isinstance(v, str) and v.strip():
            return v
    return None


def impact_by_entry(
    keys_lookup: dict[tuple[str, str], RuleKeys],
    counts_by_key: dict[str, dict[str, int]],
) -> dict[tuple[str, str], dict[str, int]]:
    """Sum :func:`~contentops.workspace_kql.suppression_impact_query` rows
    (keyed by ``match_key``) per suppression entry.

    The query attributes each alert / incident to one key, so summing an
    entry's keys never double counts.
    """
    out: dict[tuple[str, str], dict[str, int]] = {}
    for entry_key, keys in keys_lookup.items():
        totals = {"alerts_count": 0, "incidents_count": 0}
        for candidate in keys.candidates():
            row = counts_by_key.get(candidate) or {}
            for column in totals:
                totals[column] += int(row.get(column) or 0)
        out[entry_key] = totals
    return out


def render_report(
    entries: list[SuppressionEntry],
    impact_rows: dict[tuple[str, str], dict[str, int]] | None,
    *,
    name_lookup: dict[tuple[str, str], str | None],
    since_days: int,
) -> str:
    """Render the markdown body for the PR comment.

    ``impact_rows`` is keyed by ``(asset, id)`` → {alerts_count,
    incidents_count} (see :func:`impact_by_entry`). Missing keys are
    rendered as 0 / 0. When ``impact_rows`` is None (workspace query was
    skipped), the table shows '—' for both counts.
    """
    if not entries:
        return (
            "## Tuning impact preview\n\n"
            "No new suppressions in this PR. "
            "(NVISO Part 8 — only the *new* entries surface here.)\n"
        )

    lines = [
        "## Tuning impact preview",
        "",
        f"_Lookback: {since_days} days. NVISO Part 8 — blast-radius "
        f"estimate for each new entry in `detections/drift_suppressions.yml`._",
        "",
        "| Asset | Envelope id | Display name | Alerts silenced | Incidents silenced | Reason |",
        "|---|---|---|---:|---:|---|",
    ]
    totals_alerts = 0
    totals_incidents = 0
    for e in entries:
        display = name_lookup.get((e.asset, e.id))
        if display is None:
            display_cell = "_(envelope not found)_"
            alerts_cell = "—"
            incidents_cell = "—"
        else:
            display_cell = gfm_cell(display)
            if impact_rows is None:
                alerts_cell = "—"
                incidents_cell = "—"
            else:
                row = impact_rows.get((e.asset, e.id), {})
                a = int(row.get("alerts_count", 0) or 0)
                i = int(row.get("incidents_count", 0) or 0)
                totals_alerts += a
                totals_incidents += i
                alerts_cell = str(a)
                incidents_cell = str(i)
        reason = gfm_cell(e.reason or "")
        lines.append(
            f"| `{gfm_cell(e.asset)}` | `{gfm_cell(e.id)}` | {display_cell} "
            f"| {alerts_cell} | {incidents_cell} | {reason} |"
        )
    if impact_rows is not None and (totals_alerts or totals_incidents):
        lines.append("")
        lines.append(
            f"**Total impact:** {totals_alerts} alert(s), "
            f"{totals_incidents} incident(s) would have been silenced "
            f"in the last {since_days} day(s)."
        )
    lines.append("")
    return "\n".join(lines).rstrip() + "\n"


__all__ = [
    "SuppressionEntry",
    "SuppressionKey",
    "impact_by_entry",
    "new_suppressions",
    "render_report",
    "resolve_display_name",
    "resolve_rule_keys",
]
