# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""``contentops silent-rules``: every deployed repo rule with its telemetry.

The command used to print the telemetry KQL's rows, so a rule that never
fired -- no alert, no incident, hence no row -- was missing from the
list instead of at the top of it. This module starts from the repo: the
alerting rules (``sentinel_analytic``, ``defender_custom_detection``)
that are enabled and whose ``status`` the workspace role deploys
(:func:`contentops.core.env_status.allowed_statuses_for_env`, without
``deprecated``; Defender rules only for a production role, as ``apply``
does). Each rule's telemetry is the sum of its rule-key rows
(:meth:`contentops.rule_keys.TelemetryIndex.lookup`); a rule is silent
when it has no alert and no incident in the window.

Pure: the CLI loads the rules and runs the query.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping

from contentops.core.asset import Asset
from contentops.core.discovery import iter_loaded_assets
from contentops.core.env_status import _PROD_ALIASES, allowed_statuses_for_env
from contentops.core.handler import LoadedAsset
from contentops.coverage.corpus import is_detection_enabled
from contentops.rule_keys import COUNT_COLUMNS, TelemetryIndex, merge_rows, rule_keys_for

ALERTING_ASSETS = (Asset.SENTINEL_ANALYTIC, Asset.DEFENDER_CUSTOM_DETECTION)

#: Output columns, in order (``rule_keys`` is a list in JSON).
COLUMNS = (
    "silent", "source", "asset", "id", "status", "rule_name",
    *COUNT_COLUMNS, "rule_keys",
)

DEFENDER_CONNECTOR_NOTE = (
    "none of the {count} Defender custom detection(s) matched workspace "
    "telemetry; their alerts reach SecurityAlert only through the Microsoft "
    "Defender XDR connector, so without it they are listed as silent."
)


def deployed_statuses(role: str) -> tuple[str, ...]:
    """Statuses a rule deployed to ``role``'s workspace can have and
    still run (``deprecated`` rules are deployed disabled)."""
    return tuple(sorted(
        s.value for s in allowed_statuses_for_env(role) if s.value != "deprecated"
    ))


def select_rules(
    detections_path: Path,
    *,
    role: str,
    on_error: Callable[[Path, Exception], None] | None = None,
) -> list[LoadedAsset]:
    """The enabled alerting rules ``role``'s workspace runs."""
    statuses = set(deployed_statuses(role))
    defender = role.strip().lower() in _PROD_ALIASES
    rules: list[LoadedAsset] = []
    for la in iter_loaded_assets(detections_path, on_error=on_error):
        asset = la.envelope.asset
        if asset not in ALERTING_ASSETS:
            continue
        if asset is Asset.DEFENDER_CUSTOM_DETECTION and not defender:
            continue
        if la.envelope.status not in statuses or not is_detection_enabled(asset, la.payload):
            continue
        rules.append(la)
    return rules


@dataclass(frozen=True)
class SilentRulesReport:
    rows: list[dict[str, Any]]
    rule_count: int
    silent_count: int
    notes: list[str] = field(default_factory=list)


def _counts(row: Mapping[str, Any] | None) -> dict[str, int]:
    return {column: int((row or {}).get(column) or 0) for column in COUNT_COLUMNS}


def _display_name(la: LoadedAsset) -> str:
    payload = la.payload if isinstance(la.payload, Mapping) else {}
    return str(payload.get("displayName") or payload.get("DisplayName") or la.envelope.id)


def build_report(
    rules: Iterable[LoadedAsset],
    telemetry_rows: Iterable[Mapping[str, Any]],
    *,
    include_unmatched: bool = False,
) -> SilentRulesReport:
    """One row per rule, silent rules first (then fewest alerts and
    incidents). ``include_unmatched`` appends the telemetry rows no repo
    rule claimed (``source: workspace``) -- rules deployed outside the
    repo, built-in product alerts, or a repo rule whose keys didn't match."""
    telemetry_rows = list(telemetry_rows)
    index = TelemetryIndex(telemetry_rows)
    claimed: set[int] = set()
    rows: list[dict[str, Any]] = []
    defender_rules = defender_matched = 0
    for la in rules:
        matched = index.rows_for(rule_keys_for(la))
        claimed.update(id(row) for row in matched)
        merged = merge_rows(matched) if matched else None
        counts = _counts(merged)
        if la.envelope.asset is Asset.DEFENDER_CUSTOM_DETECTION:
            defender_rules += 1
            defender_matched += bool(matched)
        rows.append({
            "silent": counts["alerts_30d"] == 0 and counts["incidents_30d"] == 0,
            "source": "repo",
            "asset": la.envelope.asset.value,
            "id": la.envelope.id,
            "status": la.envelope.status,
            "rule_name": _display_name(la),
            **counts,
            "rule_keys": list((merged or {}).get("rule_keys") or []),
        })
    rule_count = len(rows)
    silent_count = sum(1 for row in rows if row["silent"])
    if include_unmatched:
        for row in telemetry_rows:
            if id(row) in claimed or not (row.get("rule_key") or row.get("rule_name")):
                continue
            counts = _counts(row)
            rows.append({
                "silent": counts["alerts_30d"] == 0 and counts["incidents_30d"] == 0,
                "source": "workspace",
                "asset": None,
                "id": None,
                "status": None,
                "rule_name": str(row.get("rule_name") or ""),
                **counts,
                "rule_keys": [str(row["rule_key"])] if row.get("rule_key") else [],
            })
    rows.sort(key=lambda r: (
        not r["silent"], r["alerts_30d"], r["incidents_30d"],
        r["source"] != "repo", r["rule_name"].lower(), r["id"] or "",
    ))
    notes = []
    if defender_rules and not defender_matched:
        notes.append(DEFENDER_CONNECTOR_NOTE.format(count=defender_rules))
    return SilentRulesReport(
        rows=rows, rule_count=rule_count, silent_count=silent_count, notes=notes,
    )


__all__ = [
    "ALERTING_ASSETS",
    "COLUMNS",
    "SilentRulesReport",
    "build_report",
    "deployed_statuses",
    "select_rules",
]
