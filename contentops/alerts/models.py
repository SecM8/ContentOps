# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Pydantic v2 models for Microsoft Graph alerts and Sentinel incidents.

The canonical shape consumed by the rollup / trend engines is
``NormalizedAlert`` -- a flat, source-agnostic struct that works equally
well with Graph ``alerts_v2`` data and Sentinel ARM incident properties.
"""

from __future__ import annotations

import enum
import json as _json
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class AlertSeverity(str, enum.Enum):
    """Severity levels for Graph alerts / Sentinel incidents."""

    informational = "informational"
    low = "low"
    medium = "medium"
    high = "high"
    unknown = "unknown"

    @classmethod
    def from_graph(cls, value: str) -> AlertSeverity:
        """Map a Graph ``severity`` string to the enum (case-insensitive)."""
        return cls(value.lower()) if value else cls.unknown

    @classmethod
    def from_sentinel(cls, value: str) -> AlertSeverity:
        """Map a Sentinel incident ``severity`` string (case-insensitive)."""
        return cls(value.lower()) if value else cls.unknown


class AlertStatus(str, enum.Enum):
    """Alert / incident lifecycle status."""

    new = "new"
    in_progress = "inProgress"
    resolved = "resolved"
    unknown = "unknown"

    @classmethod
    def from_graph(cls, value: str) -> AlertStatus:
        mapping: dict[str, AlertStatus] = {
            "new": cls.new,
            "inprogress": cls.in_progress,
            "resolved": cls.resolved,
        }
        return mapping.get(value.lower(), cls.unknown) if value else cls.unknown

    @classmethod
    def from_sentinel(cls, value: str) -> AlertStatus:
        mapping: dict[str, AlertStatus] = {
            "new": cls.new,
            "active": cls.in_progress,
            "closed": cls.resolved,
        }
        return mapping.get(value.lower(), cls.unknown) if value else cls.unknown


class AlertClassification(str, enum.Enum):
    """Classification result of an alert / incident investigation."""

    true_positive = "truePositive"
    false_positive = "falsePositive"
    benign_positive = "benignPositive"
    undetermined = "undetermined"

    @classmethod
    def from_graph(cls, value: str | None) -> AlertClassification:
        if not value:
            return cls.undetermined
        mapping: dict[str, AlertClassification] = {
            "truepositive": cls.true_positive,
            "falsepositive": cls.false_positive,
            "benignpositive": cls.benign_positive,
            "informationalexpectedactivity": cls.benign_positive,
        }
        return mapping.get(value.lower(), cls.undetermined)

    @classmethod
    def from_sentinel(cls, value: str | None) -> AlertClassification:
        if not value:
            return cls.undetermined
        mapping: dict[str, AlertClassification] = {
            "truepositive": cls.true_positive,
            "falsepositive": cls.false_positive,
            "benignpositive": cls.benign_positive,
            "undetermined": cls.undetermined,
        }
        return mapping.get(value.lower().replace(" ", "").replace("_", ""), cls.undetermined)


class AlertDetermination(str, enum.Enum):
    """Determination detail for a classified alert."""

    unknown = "unknown"
    apt = "apt"
    malware = "malware"
    phishing = "phishing"
    compromised_account = "compromisedAccount"
    security_personnel = "securityPersonnel"
    security_testing = "securityTesting"
    unwanted_software = "unwantedSoftware"
    multi_staged_attack = "multiStagedAttack"
    malicious_user_activity = "maliciousUserActivity"
    not_malicious = "notMalicious"
    not_enough_data_to_validate = "notEnoughDataToValidate"
    confirmed_activity = "confirmedActivity"
    line_of_business_application = "lineOfBusinessApplication"
    other = "other"

    @classmethod
    def from_graph(cls, value: str | None) -> AlertDetermination:
        if not value:
            return cls.unknown
        try:
            return cls(value)
        except ValueError:
            # Case-insensitive fallback
            for member in cls:
                if member.value.lower() == value.lower():
                    return member
            return cls.unknown

    @classmethod
    def from_sentinel_reason(cls, value: str | None) -> AlertDetermination:
        """Map a Sentinel ClassificationReason to the enum."""
        if not value:
            return cls.unknown
        mapping: dict[str, AlertDetermination] = {
            "suspiciousactivity": cls.malicious_user_activity,
            "suspiciousbutexpected": cls.security_testing,
            "inaccuratedata": cls.not_enough_data_to_validate,
            "incorrectalertlogic": cls.other,
            "confirmedactivity": cls.confirmed_activity,
        }
        return mapping.get(value.lower().replace(" ", "").replace("_", ""), cls.unknown)


# ---------------------------------------------------------------------------
# Graph alert model
# ---------------------------------------------------------------------------


class GraphAlert(BaseModel):
    """A single alert from the Microsoft Graph Security alerts_v2 endpoint."""

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    id: str
    title: str = ""
    severity: str = "unknown"
    status: str = "unknown"
    classification: str | None = None
    determination: str | None = None
    serviceSource: str = ""
    detectorId: str | None = None
    detectionSource: str = ""
    providerAlertId: str | None = None
    createdDateTime: datetime | None = None
    lastUpdateDateTime: datetime | None = None
    resolvedDateTime: datetime | None = None
    firstActivityDateTime: datetime | None = None
    lastActivityDateTime: datetime | None = None
    incidentId: str | None = None
    mitreTechniques: list[str] = Field(default_factory=list)
    assignedTo: str | None = None
    description: str = ""
    evidence: list[dict[str, Any]] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Sentinel incident model
# ---------------------------------------------------------------------------


class SentinelIncident(BaseModel):
    """A Sentinel incident from the ARM SecurityInsights incidents endpoint."""

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    id: str
    name: str = ""
    title: str = ""
    severity: str = "unknown"
    status: str = "unknown"
    classification: str | None = None
    classificationReason: str | None = None
    owner: dict[str, Any] = Field(default_factory=dict)
    createdTimeUtc: datetime | None = None
    lastModifiedTimeUtc: datetime | None = None
    closedTimeUtc: datetime | None = None
    firstActivityTimeUtc: datetime | None = None
    lastActivityTimeUtc: datetime | None = None
    incidentNumber: int | None = None
    additionalData: dict[str, Any] = Field(default_factory=dict)
    relatedAnalyticRuleIds: list[str] = Field(default_factory=list)
    description: str = ""


# ---------------------------------------------------------------------------
# Normalized alert (unified shape)
# ---------------------------------------------------------------------------


class NormalizedAlert(BaseModel):
    """Source-agnostic alert shape consumed by the rollup / trend engines.

    Constructed from either a Graph alert or a Sentinel incident via the
    ``from_graph()`` and ``from_sentinel()`` factory classmethods.
    """

    model_config = ConfigDict(extra="ignore")

    id: str
    title: str
    severity: AlertSeverity
    status: AlertStatus
    classification: AlertClassification
    determination: AlertDetermination
    source: str  # "graph" or "sentinel"
    service_source: str  # e.g. "microsoftDefenderForEndpoint"
    created: datetime | None = None
    resolved: datetime | None = None
    first_activity: datetime | None = None
    last_activity: datetime | None = None
    incident_id: str | None = None
    mitre_techniques: list[str] = Field(default_factory=list)
    assigned_to: str | None = None
    description: str = ""
    rule_id: str | None = None
    rule_name: str | None = None
    detection_source: str = ""
    provider_alert_id: str | None = None

    @classmethod
    def from_graph(cls, alert: GraphAlert | dict[str, Any]) -> NormalizedAlert:
        """Create a NormalizedAlert from a Graph alerts_v2 payload."""
        if isinstance(alert, dict):
            alert = GraphAlert.model_validate(alert)
        return cls(
            id=alert.id,
            title=alert.title,
            severity=AlertSeverity.from_graph(alert.severity),
            status=AlertStatus.from_graph(alert.status),
            classification=AlertClassification.from_graph(alert.classification),
            determination=AlertDetermination.from_graph(alert.determination),
            source="graph",
            service_source=alert.serviceSource or "",
            created=alert.createdDateTime,
            resolved=alert.resolvedDateTime,
            first_activity=alert.firstActivityDateTime,
            last_activity=alert.lastActivityDateTime,
            incident_id=alert.incidentId,
            mitre_techniques=alert.mitreTechniques,
            assigned_to=alert.assignedTo,
            description=alert.description,
            rule_id=alert.detectorId,
            detection_source=alert.detectionSource or "",
            provider_alert_id=alert.providerAlertId,
        )

    @classmethod
    def from_sentinel(cls, incident: SentinelIncident | dict[str, Any]) -> NormalizedAlert:
        """Create a NormalizedAlert from a Sentinel ARM incident payload."""
        if isinstance(incident, dict):
            # ARM incidents nest properties under a "properties" key
            props = incident.get("properties", incident)
            inc = SentinelIncident.model_validate({
                "id": incident.get("id", incident.get("name", "")),
                "name": incident.get("name", ""),
                **props,
            })
        else:
            inc = incident

        # Map classificationReason to determination
        determination = AlertDetermination.unknown
        if inc.classificationReason:
            determination = AlertDetermination.from_graph(inc.classificationReason)

        # Extract rule names from relatedAnalyticRuleIds
        rule_id = inc.relatedAnalyticRuleIds[0] if inc.relatedAnalyticRuleIds else None

        return cls(
            id=inc.id,
            title=inc.title,
            severity=AlertSeverity.from_sentinel(inc.severity),
            status=AlertStatus.from_sentinel(inc.status),
            classification=AlertClassification.from_sentinel(inc.classification),
            determination=determination,
            source="sentinel",
            service_source="sentinel",
            created=inc.createdTimeUtc,
            resolved=inc.closedTimeUtc,
            first_activity=inc.firstActivityTimeUtc,
            last_activity=inc.lastActivityTimeUtc,
            incident_id=str(inc.incidentNumber) if inc.incidentNumber else None,
            mitre_techniques=[],
            assigned_to=(inc.owner.get("assignedTo") or inc.owner.get("email")) if inc.owner else None,
            description=inc.description,
            rule_id=rule_id,
        )


    @classmethod
    def from_kql_row(cls, row: dict[str, Any]) -> NormalizedAlert:
        """Create a NormalizedAlert from a SecurityAlert KQL row.

        Handles both plain SecurityAlert rows and joined
        SecurityAlert+SecurityIncident rows. Joined columns
        (IncidentStatus, IncidentClassification, etc.) are used
        when present; absent columns fall back to alert-level data.
        """
        tactics_raw = row.get("Tactics") or ""
        tactics_list = [t.strip() for t in tactics_raw.split(",") if t.strip()] if tactics_raw else []

        techniques_raw = row.get("Techniques") or ""
        techniques_list = [t.strip() for t in techniques_raw.split(",") if t.strip()] if techniques_raw else []

        alert_status_map = {"new": "new", "inprogress": "inProgress", "resolved": "resolved", "dismissed": "resolved"}
        raw_alert_status = (row.get("AlertStatus") or row.get("Status") or "unknown").lower()

        # Incident lifecycle (from LEFT JOIN SecurityIncident, may be null)
        incident_status_raw = row.get("IncidentStatus") or ""
        incident_classification_raw = row.get("IncidentClassification") or ""
        incident_classification_reason = row.get("IncidentClassificationReason") or ""
        incident_number = row.get("IncidentNumber")

        # Status: prefer incident status (Closed > Active > New) when present
        if incident_status_raw:
            status = AlertStatus.from_sentinel(incident_status_raw)
        else:
            status = AlertStatus.from_graph(alert_status_map.get(raw_alert_status, raw_alert_status))

        # Classification: prefer incident classification over alert classification
        alert_classification = AlertClassification.from_sentinel(
            row.get("AlertClassification") or row.get("Classification") or ""
        )
        if incident_classification_raw:
            incident_classification = AlertClassification.from_sentinel(incident_classification_raw)
            classification = incident_classification if incident_classification != AlertClassification.undetermined else alert_classification
        else:
            classification = alert_classification

        # Determination: from incident ClassificationReason
        determination = AlertDetermination.from_sentinel_reason(incident_classification_reason)

        created = None
        if row.get("TimeGenerated"):
            try:
                created = datetime.fromisoformat(str(row["TimeGenerated"]).replace("Z", "+00:00"))
            except (ValueError, TypeError):
                pass

        # Closed time from incident ClosedTime
        resolved = None
        incident_closed = row.get("IncidentClosedTime")
        if incident_closed:
            try:
                resolved = datetime.fromisoformat(str(incident_closed).replace("Z", "+00:00"))
            except (ValueError, TypeError):
                pass

        # Incident ID
        incident_id = str(incident_number) if incident_number is not None else None

        # Owner from incident (dynamic JSON column)
        assigned_to = None
        owner_raw = row.get("IncidentOwner")
        if isinstance(owner_raw, dict):
            assigned_to = owner_raw.get("assignedTo") or owner_raw.get("email")
        elif isinstance(owner_raw, str) and owner_raw:
            try:
                owner_parsed = _json.loads(owner_raw)
                if isinstance(owner_parsed, dict):
                    assigned_to = owner_parsed.get("assignedTo") or owner_parsed.get("email")
            except (ValueError, TypeError):
                pass

        # Rule ID: prefer RelatedAnalyticRuleIds (ARM resource ID) over AlertType
        rule_ids_raw = row.get("RelatedAnalyticRuleIds")
        rule_id = row.get("AlertType") or ""
        if isinstance(rule_ids_raw, list) and rule_ids_raw:
            rule_id = str(rule_ids_raw[0])
        elif isinstance(rule_ids_raw, str) and rule_ids_raw:
            try:
                parsed = _json.loads(rule_ids_raw)
                if isinstance(parsed, list) and parsed:
                    rule_id = str(parsed[0])
            except (ValueError, TypeError):
                pass

        return cls(
            id=row.get("SystemAlertId") or "",
            title=row.get("AlertName") or "",
            severity=AlertSeverity.from_sentinel(row.get("AlertSeverity") or "unknown"),
            status=status,
            classification=classification,
            determination=determination,
            source="sentinel",
            service_source=row.get("ProductName") or row.get("ProviderName") or "sentinel",
            created=created,
            resolved=resolved,
            mitre_techniques=techniques_list,
            description=row.get("Description") or "",
            rule_id=rule_id,
            detection_source=row.get("ProviderName") or "",
            incident_id=incident_id,
            assigned_to=assigned_to,
            # The vendor's original alert id (e.g. the Defender alert id).
            # This is what correlates a Sentinel SecurityAlert row to the
            # same alert in Graph alerts_v2 — SystemAlertId is LA-internal and
            # never matches Graph. See merge.py:_correlation_keys.
            provider_alert_id=row.get("VendorOriginalId") or None,
        )

    @classmethod
    def merge(cls, graph: NormalizedAlert, sentinel: NormalizedAlert) -> NormalizedAlert:
        """Merge a Graph alert and a Sentinel incident for the same event.

        Prefers Graph for evidence-rich fields (MITRE, detection_source,
        service_source) and Sentinel for rule correlation
        (relatedAnalyticRuleIds → rule_id). Classification uses whichever
        is not undetermined.
        """
        classification = graph.classification
        if classification == AlertClassification.undetermined and sentinel.classification != AlertClassification.undetermined:
            classification = sentinel.classification

        determination = graph.determination
        if determination == AlertDetermination.unknown and sentinel.determination != AlertDetermination.unknown:
            determination = sentinel.determination

        return cls(
            id=graph.id,
            title=graph.title or sentinel.title,
            severity=graph.severity if graph.severity != AlertSeverity.unknown else sentinel.severity,
            status=graph.status if graph.status != AlertStatus.unknown else sentinel.status,
            classification=classification,
            determination=determination,
            source="both",
            service_source=graph.service_source or sentinel.service_source,
            created=graph.created or sentinel.created,
            resolved=graph.resolved or sentinel.resolved,
            first_activity=graph.first_activity or sentinel.first_activity,
            last_activity=graph.last_activity or sentinel.last_activity,
            incident_id=graph.incident_id or sentinel.incident_id,
            mitre_techniques=graph.mitre_techniques or sentinel.mitre_techniques,
            assigned_to=graph.assigned_to or sentinel.assigned_to,
            description=graph.description or sentinel.description,
            rule_id=sentinel.rule_id or graph.rule_id,
            rule_name=graph.rule_name or sentinel.rule_name,
            detection_source=graph.detection_source or sentinel.detection_source,
            # Keep the correlation key so a merged alert still matches in a
            # later enrich pass.
            provider_alert_id=graph.provider_alert_id or sentinel.provider_alert_id,
        )


__all__ = [
    "AlertClassification",
    "AlertDetermination",
    "AlertSeverity",
    "AlertStatus",
    "GraphAlert",
    "NormalizedAlert",
    "SentinelIncident",
]
