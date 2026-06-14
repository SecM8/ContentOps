# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Merge, overlay, and enrich alerts from multiple sources.

Three-layer merge for the triple-source alert pipeline:

1. **merge_alerts** — Graph ↔ Sentinel two-pass dedup (legacy, still
   used by ``alerts collect``).
2. **overlay_arm_incidents** — Patch NormalizedAlerts in-memory with
   ARM incident lifecycle data. "ARM wins" logic for reopened incidents.
3. **apply_arm_overlay_to_daily_files** — Patch daily JSONL files with
   ARM incident lifecycle data. Zero-staleness guarantee.
4. **enrich_from_graph** — Additive MITRE/evidence enrichment from
   Graph alerts_v2. Never overwrites non-empty fields.
"""

from __future__ import annotations

import json
import logging
from collections import defaultdict
from pathlib import Path
from typing import Any

from contentops.alerts.models import (
    AlertClassification,
    AlertDetermination,
    AlertSeverity,
    AlertStatus,
    NormalizedAlert,
)

log = logging.getLogger(__name__)


def _correlation_keys(alert: NormalizedAlert) -> list[str]:
    """Candidate keys for correlating the *same* alert across Graph and Sentinel.

    A Defender alert surfaces in two places with two id schemes:

    * Graph ``alerts_v2`` — ``id`` and ``providerAlertId``
      (``provider_alert_id`` here).
    * Sentinel ``SecurityAlert`` — ``VendorOriginalId`` (mapped to
      ``provider_alert_id``) and ``SystemAlertId`` (mapped to ``id``).

    The shared value is the vendor's original alert id: Graph ``id`` /
    ``providerAlertId`` ↔ Sentinel ``VendorOriginalId``. ``SystemAlertId`` is
    Log-Analytics-internal and never matches Graph — keying on it (the old
    behaviour) produced 0 joins and double-counted every Defender alert. We
    don't assume which field the vendor populated, so we offer every non-empty
    candidate and let the lookup find the hit.
    """
    return [k for k in (alert.provider_alert_id, alert.id) if k]


def merge_alerts(
    graph_alerts: list[NormalizedAlert],
    sentinel_alerts: list[NormalizedAlert],
) -> list[NormalizedAlert]:
    """Merge alerts from Graph and Sentinel, deduplicating by alert ID
    and incident ID.

    No data is ever dropped — worst case is no joins, all kept separately.
    """
    if not graph_alerts:
        return list(sentinel_alerts)
    if not sentinel_alerts:
        return list(graph_alerts)

    result: list[NormalizedAlert] = []
    matched_graph_ids: set[str] = set()
    matched_sentinel_ids: set[str] = set()

    # Pass 1: cross-source correlation on the vendor's original alert id.
    # Index Sentinel by every candidate key (VendorOriginalId AND
    # SystemAlertId) and try each Graph candidate key against it, so the join
    # works whichever field the vendor populated. See _correlation_keys.
    sentinel_by_key: dict[str, NormalizedAlert] = {}
    for sa in sentinel_alerts:
        for key in _correlation_keys(sa):
            sentinel_by_key.setdefault(key, sa)
    for ga in graph_alerts:
        matched_sa = next(
            (sentinel_by_key[k] for k in _correlation_keys(ga) if k in sentinel_by_key),
            None,
        )
        if matched_sa is not None:
            result.append(NormalizedAlert.merge(ga, matched_sa))
            matched_graph_ids.add(ga.id)
            matched_sentinel_ids.add(matched_sa.id)

    # Pass 2: incident_id join for remaining unmatched
    graph_by_incident: dict[str, list[NormalizedAlert]] = defaultdict(list)
    for ga in graph_alerts:
        if ga.id not in matched_graph_ids and ga.incident_id:
            graph_by_incident[ga.incident_id].append(ga)

    for sa in sentinel_alerts:
        if sa.id in matched_sentinel_ids:
            continue
        if sa.incident_id and sa.incident_id in graph_by_incident:
            for ga in graph_by_incident[sa.incident_id]:
                if ga.id not in matched_graph_ids:
                    result.append(NormalizedAlert.merge(ga, sa))
                    matched_graph_ids.add(ga.id)
            matched_sentinel_ids.add(sa.id)

    # Collect remaining unmatched
    for ga in graph_alerts:
        if ga.id not in matched_graph_ids:
            result.append(ga)

    for sa in sentinel_alerts:
        if sa.id not in matched_sentinel_ids:
            result.append(sa)

    merged_count = sum(1 for a in result if a.source == "both")
    if graph_alerts and sentinel_alerts and merged_count == 0:
        # Both sources returned alerts but nothing correlated — the key is
        # likely wrong for this tenant's alert providers. Surface a sample so
        # the right field is obvious from the run log (alert ids are opaque
        # identifiers, not PII).
        gs, ss = graph_alerts[0], sentinel_alerts[0]
        log.warning(
            "Merge: 0 cross-source matches — correlation key may be wrong. "
            "sample graph id=%r provider_alert_id=%r | "
            "sample sentinel id=%r provider_alert_id=%r",
            gs.id, gs.provider_alert_id, ss.id, ss.provider_alert_id,
        )
    log.info(
        "Merge: %d Graph + %d Sentinel → %d merged, %d Graph-only, %d Sentinel-only, %d total",
        len(graph_alerts),
        len(sentinel_alerts),
        merged_count,
        sum(1 for a in result if a.source == "graph"),
        sum(1 for a in result if a.source == "sentinel"),
        len(result),
    )
    return result


# ---------------------------------------------------------------------------
# ARM overlay — in-memory (used during sync_day for re-export dates)
# ---------------------------------------------------------------------------


def _extract_alert_ids_from_incident(incident: dict[str, Any]) -> list[str]:
    """Extract SystemAlertIds from an ARM incident response."""
    props = incident.get("properties", incident)
    additional = props.get("additionalData") or {}
    alert_ids = additional.get("alertProductIds") or []
    if isinstance(alert_ids, list) and alert_ids:
        return [str(aid) for aid in alert_ids]
    return []


def overlay_arm_incidents(
    alerts: list[NormalizedAlert],
    arm_incidents: list[dict[str, Any]],
) -> list[NormalizedAlert]:
    """Overlay incident lifecycle from ARM onto NormalizedAlerts.

    Uses "ARM wins" logic: always sets status/classification/resolved
    from ARM, even if reverting (reopened incident). This ensures
    the pipeline reflects the current live state.
    """
    if not arm_incidents:
        return list(alerts)

    # Build alert_id -> incident patch map
    patch_map: dict[str, dict[str, Any]] = {}
    for inc in arm_incidents:
        props = inc.get("properties", inc)
        alert_ids = _extract_alert_ids_from_incident(inc)

        # Fallback: match by incident number if alertProductIds empty
        incident_number = props.get("incidentNumber")

        patch = {
            "status": props.get("status") or "",
            "classification": props.get("classification") or "",
            "classification_reason": props.get("classificationReason") or "",
            "closed_time_utc": props.get("closedTimeUtc"),
            "incident_number": incident_number,
            "owner": props.get("owner") or {},
        }

        for aid in alert_ids:
            patch_map[aid] = patch

        # Fallback: map by incident number for alerts already joined
        if incident_number and not alert_ids:
            for a in alerts:
                if a.incident_id == str(incident_number):
                    patch_map[a.id] = patch

    result: list[NormalizedAlert] = []
    overlaid = 0

    for alert in alerts:
        if alert.id not in patch_map:
            result.append(alert)
            continue

        patch = patch_map[alert.id]

        # ARM wins: always use ARM status/classification
        new_status = AlertStatus.from_sentinel(patch["status"]) if patch["status"] else alert.status
        new_classification = AlertClassification.from_sentinel(patch["classification"]) if patch["classification"] else alert.classification
        new_determination = AlertDetermination.from_sentinel_reason(patch["classification_reason"]) if patch["classification_reason"] else alert.determination

        new_resolved = alert.resolved
        if patch["closed_time_utc"]:
            try:
                from datetime import datetime as _dt
                new_resolved = _dt.fromisoformat(str(patch["closed_time_utc"]).replace("Z", "+00:00"))
            except (ValueError, TypeError):
                new_resolved = alert.resolved
        elif new_status != AlertStatus.resolved:
            new_resolved = None

        new_incident_id = str(patch["incident_number"]) if patch["incident_number"] is not None else alert.incident_id

        owner_data = patch["owner"]
        new_assigned_to = alert.assigned_to
        if isinstance(owner_data, dict):
            new_assigned_to = owner_data.get("assignedTo") or owner_data.get("email") or alert.assigned_to

        result.append(alert.model_copy(update={
            "status": new_status,
            "classification": new_classification,
            "determination": new_determination,
            "resolved": new_resolved,
            "incident_id": new_incident_id,
            "assigned_to": new_assigned_to,
            "source": "both" if alert.source != "both" else "both",
        }))
        overlaid += 1

    log.info("ARM overlay: %d/%d alerts updated", overlaid, len(alerts))
    return result


# ---------------------------------------------------------------------------
# ARM overlay — daily file patching (zero-staleness guarantee)
# ---------------------------------------------------------------------------


def apply_arm_overlay_to_daily_files(
    daily_dir: Path,
    arm_incidents: list[dict[str, Any]],
) -> tuple[int, int]:
    """Patch daily JSONL files with ARM incident lifecycle data.

    Returns (files_patched, entries_updated). Uses "ARM wins" logic
    so reopened incidents correctly revert classification and closed_at.
    """
    from contentops.alerts.ledger import LedgerEntry, load_ledger, write_daily_file

    if not arm_incidents or not daily_dir.is_dir():
        return 0, 0

    # Build alert_id -> patch map from ARM incidents
    patch_map: dict[str, dict[str, Any]] = {}
    incident_number_map: dict[int, dict[str, Any]] = {}

    for inc in arm_incidents:
        props = inc.get("properties", inc)
        alert_ids = _extract_alert_ids_from_incident(inc)
        incident_number = props.get("incidentNumber")

        classification_raw = props.get("classification") or ""
        classification = AlertClassification.from_sentinel(classification_raw).value if classification_raw else None

        closed_at = None
        closed_raw = props.get("closedTimeUtc")
        if closed_raw:
            try:
                from datetime import datetime as _dt
                closed_at = _dt.fromisoformat(str(closed_raw).replace("Z", "+00:00")).isoformat()
            except (ValueError, TypeError):
                pass

        status_raw = props.get("status") or ""
        is_reopened = status_raw.lower() in ("new", "active")
        if is_reopened:
            closed_at = None  # explicitly clear for reopened

        patch = {
            "classification": classification,
            "closed_at": closed_at,
            "incident_number": incident_number,
            "is_reopened": is_reopened,
        }

        for aid in alert_ids:
            patch_map[aid] = patch

        if incident_number is not None:
            incident_number_map[incident_number] = patch

    files_patched = 0
    entries_updated = 0

    for daily_file in sorted(daily_dir.glob("*.jsonl")):
        entries = load_ledger(daily_file)
        if not entries:
            continue

        updated = False
        new_entries: list[LedgerEntry] = []

        for entry in entries:
            patch = patch_map.get(entry.alert_id)
            if patch is None and entry.incident_number is not None:
                patch = incident_number_map.get(entry.incident_number)

            if patch is None:
                new_entries.append(entry)
                continue

            needs_update = False
            new_classification = entry.classification
            new_closed_at = entry.closed_at
            new_incident_number = entry.incident_number
            new_source = entry.source

            # ARM wins: always apply ARM classification
            if patch["classification"] is not None and patch["classification"] != entry.classification:
                new_classification = patch["classification"]
                needs_update = True

            # ARM wins: always apply closed_at (including None for reopened)
            if patch["is_reopened"] and entry.closed_at is not None:
                new_closed_at = None
                new_classification = patch["classification"] or "undetermined"
                needs_update = True
            elif patch["closed_at"] is not None and patch["closed_at"] != entry.closed_at:
                new_closed_at = patch["closed_at"]
                needs_update = True

            if patch["incident_number"] is not None and entry.incident_number != patch["incident_number"]:
                new_incident_number = patch["incident_number"]
                needs_update = True

            if needs_update:
                new_source = "both" if entry.source != "both" else "both"
                new_entries.append(LedgerEntry(
                    alert_id=entry.alert_id,
                    rule_display_name=entry.rule_display_name,
                    classification=new_classification,
                    closed_at=new_closed_at,
                    severity=entry.severity,
                    source=new_source,
                    created_at=entry.created_at,
                    rule_id=entry.rule_id,
                    service_source=entry.service_source,
                    detection_source=entry.detection_source,
                    incident_number=new_incident_number,
                ))
                updated = True
                entries_updated += 1
            else:
                new_entries.append(entry)

        if updated:
            write_daily_file(daily_file, new_entries)
            files_patched += 1

    log.info("ARM daily-file overlay: %d files patched, %d entries updated", files_patched, entries_updated)
    return files_patched, entries_updated


# ---------------------------------------------------------------------------
# Graph enrichment — additive MITRE/evidence
# ---------------------------------------------------------------------------


def _apply_graph_enrichment(
    alert: NormalizedAlert, ga: NormalizedAlert,
) -> tuple[NormalizedAlert, bool]:
    """Apply Graph enrichment fields to an alert. Returns (alert, changed)."""
    updates: dict[str, Any] = {}
    if not alert.mitre_techniques and ga.mitre_techniques:
        updates["mitre_techniques"] = ga.mitre_techniques
    if not alert.detection_source and ga.detection_source:
        updates["detection_source"] = ga.detection_source
    if ga.rule_id and (not alert.rule_id or alert.rule_id == alert.title):
        updates["rule_id"] = ga.rule_id
    if updates:
        return alert.model_copy(update=updates), True
    return alert, False


def enrich_from_graph(
    alerts: list[NormalizedAlert],
    graph_alerts: list[NormalizedAlert],
) -> list[NormalizedAlert]:
    """Enrich alerts with Graph-sourced MITRE techniques and evidence.

    Two-pass matching:
    1. ``provider_alert_id`` == alert ``id`` (SystemAlertId)
    2. ``incident_id`` match (catches alerts where ID schemes differ)

    Additive only — never overwrites non-empty fields.
    """
    if not graph_alerts:
        return list(alerts)

    # Pass 1 lookup: index Graph by every correlation key (see
    # _correlation_keys / merge_alerts), so a Sentinel alert matches its Graph
    # twin on the vendor's original id rather than the LA-internal SystemAlertId.
    graph_by_key: dict[str, NormalizedAlert] = {}
    for ga in graph_alerts:
        for key in _correlation_keys(ga):
            graph_by_key.setdefault(key, ga)

    # Pass 2 lookup: incident_id → list of Graph alerts
    graph_by_incident: dict[str, list[NormalizedAlert]] = defaultdict(list)
    for ga in graph_alerts:
        if ga.incident_id:
            graph_by_incident[ga.incident_id].append(ga)

    result: list[NormalizedAlert] = []
    enriched = 0

    for alert in alerts:
        # Pass 1: cross-source correlation-key match
        ga = next(
            (graph_by_key[k] for k in _correlation_keys(alert) if k in graph_by_key),
            None,
        )
        if ga is not None:
            enriched_alert, changed = _apply_graph_enrichment(alert, ga)
            result.append(enriched_alert)
            if changed:
                enriched += 1
            continue

        # Pass 2: incident_id match (pick first Graph alert with MITRE data)
        if alert.incident_id and alert.incident_id in graph_by_incident:
            matched = False
            for ga in graph_by_incident[alert.incident_id]:
                if ga.mitre_techniques or ga.detection_source:
                    enriched_alert, changed = _apply_graph_enrichment(alert, ga)
                    result.append(enriched_alert)
                    if changed:
                        enriched += 1
                    matched = True
                    break
            if matched:
                continue

        result.append(alert)

    log.info("Graph enrichment: %d/%d alerts enriched", enriched, len(alerts))
    return result
