# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Pydantic models for detection rule validation."""

from __future__ import annotations

import enum
import re
from datetime import timedelta
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class Platform(str, enum.Enum):
    SENTINEL = "sentinel"
    DEFENDER = "defender"


class Status(str, enum.Enum):
    EXPERIMENTAL = "experimental"
    TEST = "test"
    PRODUCTION = "production"
    DEPRECATED = "deprecated"


class SentinelKind(str, enum.Enum):
    SCHEDULED = "Scheduled"
    NRT = "NRT"
    MICROSOFT_SECURITY_INCIDENT_CREATION = "MicrosoftSecurityIncidentCreation"
    FUSION = "Fusion"
    ML_BEHAVIOR_ANALYTICS = "MLBehaviorAnalytics"
    THREAT_INTELLIGENCE = "ThreatIntelligence"


class MicrosoftSecurityProductName(str, enum.Enum):
    """Source product the MicrosoftSecurityIncidentCreation rule listens to.

    The ARM ``productFilter`` enum is locked to the legacy product
    names — ARM still validates against pre-rebrand strings even at
    api-version ``2025-09-01``. Submitting "Microsoft Defender for
    Cloud" (the post-rebrand display name) yields HTTP 400. Use the
    legacy name in YAML; the rule still surfaces the rebranded product
    in the portal because Sentinel translates internally.
    """

    AZURE_AD_IDENTITY_PROTECTION = "Azure Active Directory Identity Protection"
    AZURE_ADVANCED_THREAT_PROTECTION = "Azure Advanced Threat Protection"
    AZURE_SECURITY_CENTER = "Azure Security Center"
    AZURE_SECURITY_CENTER_FOR_IOT = "Azure Security Center for IoT"
    MICROSOFT_CLOUD_APP_SECURITY = "Microsoft Cloud App Security"
    # Added 2026-05-18 after an adopter's collect surfaced two
    # production-deployed MicrosoftSecurityIncidentCreation rules using
    # these legacy product names. ARM accepted them, our enum didn't.
    OFFICE_365_ADVANCED_THREAT_PROTECTION = "Office 365 Advanced Threat Protection"
    MICROSOFT_DEFENDER_ADVANCED_THREAT_PROTECTION = "Microsoft Defender Advanced Threat Protection"


class FusionSubTypeStatus(str, enum.Enum):
    ENABLED = "Enabled"
    DISABLED = "Disabled"


class Severity(str, enum.Enum):
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFORMATIONAL = "Informational"


class TriggerOperator(str, enum.Enum):
    GREATER_THAN = "GreaterThan"
    LESS_THAN = "LessThan"
    EQUAL = "Equal"
    NOT_EQUAL = "NotEqual"


class AttackTactic(str, enum.Enum):
    RECONNAISSANCE = "Reconnaissance"
    RESOURCE_DEVELOPMENT = "ResourceDevelopment"
    INITIAL_ACCESS = "InitialAccess"
    EXECUTION = "Execution"
    PERSISTENCE = "Persistence"
    PRIVILEGE_ESCALATION = "PrivilegeEscalation"
    DEFENSE_EVASION = "DefenseEvasion"
    CREDENTIAL_ACCESS = "CredentialAccess"
    DISCOVERY = "Discovery"
    LATERAL_MOVEMENT = "LateralMovement"
    COLLECTION = "Collection"
    COMMAND_AND_CONTROL = "CommandAndControl"
    EXFILTRATION = "Exfiltration"
    IMPACT = "Impact"
    PRE_ATTACK = "PreAttack"
    IMPAIR_PROCESS_CONTROL = "ImpairProcessControl"
    INHIBIT_RESPONSE_FUNCTION = "InhibitResponseFunction"


class EntityType(str, enum.Enum):
    ACCOUNT = "Account"
    HOST = "Host"
    IP = "IP"
    FILE = "File"
    FILE_HASH = "FileHash"
    PROCESS = "Process"
    URL = "URL"
    DNS = "DNS"
    AZURE_RESOURCE = "AzureResource"
    CLOUD_APPLICATION = "CloudApplication"
    MAILBOX = "Mailbox"
    MAIL_CLUSTER = "MailCluster"
    MAIL_MESSAGE = "MailMessage"
    SUBMISSION_MAIL = "SubmissionMail"
    SECURITY_GROUP = "SecurityGroup"
    MALWARE = "Malware"
    REGISTRY_KEY = "RegistryKey"
    REGISTRY_VALUE = "RegistryValue"


class MatchingMethod(str, enum.Enum):
    ALL_ENTITIES = "AllEntities"
    ANY_ALERT = "AnyAlert"
    SELECTED = "Selected"


class AggregationKind(str, enum.Enum):
    SINGLE_ALERT = "SingleAlert"
    ALERT_PER_RESULT = "AlertPerResult"


class AlertProperty(str, enum.Enum):
    ALERT_LINK = "AlertLink"
    CONFIDENCE_LEVEL = "ConfidenceLevel"
    CONFIDENCE_SCORE = "ConfidenceScore"
    EXTENDED_LINKS = "ExtendedLinks"
    PRODUCT_NAME = "ProductName"
    PROVIDER_NAME = "ProviderName"
    PRODUCT_COMPONENT_NAME = "ProductComponentName"
    REMEDIATION_STEPS = "RemediationSteps"
    TECHNIQUES = "Techniques"
    SUB_TECHNIQUES = "SubTechniques"


# ---------------------------------------------------------------------------
# Sentinel sub-models
# ---------------------------------------------------------------------------


class FieldMapping(BaseModel):
    identifier: str
    columnName: str


class EntityMapping(BaseModel):
    entityType: EntityType
    fieldMappings: list[FieldMapping] = Field(max_length=3)


class SentinelEntitiesMapping(BaseModel):
    columnName: str


class AlertDynamicProperty(BaseModel):
    alertProperty: AlertProperty
    value: str


class AlertDetailsOverride(BaseModel):
    alertDisplayNameFormat: str | None = None
    alertDescriptionFormat: str | None = None
    alertSeverityColumnName: str | None = None
    alertTacticsColumnName: str | None = None
    alertDynamicProperties: list[AlertDynamicProperty] | None = None


class EventGroupingSettings(BaseModel):
    aggregationKind: AggregationKind


class GroupingConfiguration(BaseModel):
    enabled: bool = False
    reopenClosedIncident: bool = False
    lookbackDuration: str = "PT5H"
    matchingMethod: MatchingMethod = MatchingMethod.ALL_ENTITIES
    groupByEntities: list[EntityType] | None = None
    groupByAlertDetails: list[str] | None = None
    groupByCustomDetails: list[str] | None = None


class IncidentConfiguration(BaseModel):
    createIncident: bool = True
    groupingConfiguration: GroupingConfiguration | None = None


# ---------------------------------------------------------------------------
# Sentinel payload models
# ---------------------------------------------------------------------------


SCHEDULED_ONLY_FIELDS = frozenset(
    {"queryFrequency", "queryPeriod", "triggerOperator", "triggerThreshold"}
)


class SentinelScheduledPayload(BaseModel):
    """Sentinel Scheduled alert rule payload."""

    kind: Literal["Scheduled"]
    displayName: str
    description: str | None = None
    enabled: bool = True
    severity: Severity
    # No upper bound: the ARM API accepts and runs queries longer than the
    # 10,000 characters Microsoft documents for analytics rules (rules
    # collected back from live tenants exceed it). Lint rule KQL009 warns
    # above that figure instead of failing validation here.
    query: str = Field(min_length=1)
    queryFrequency: str
    queryPeriod: str
    triggerOperator: TriggerOperator
    triggerThreshold: int = Field(ge=0)
    suppressionEnabled: bool | None = None
    suppressionDuration: str | None = None
    tactics: list[AttackTactic] | None = None
    techniques: list[str] | None = None
    subTechniques: list[str] | None = None
    # Microsoft Sentinel's ARM contract for alertRules accepts up to 10
    # entityMappings per rule. The previous cap of 5 here was from a
    # 2022-era doc page; the 2025-07-01-preview API surface explicitly
    # allows more. Confirmed empirically 2026-05-18 by an adopter whose
    # 6-mapping production rule (collected from a working tenant)
    # tripped the old cap and CI rejected it. See task #39 in the
    # adopter-friction notes.
    entityMappings: list[EntityMapping] | None = Field(default=None, max_length=10)
    sentinelEntitiesMappings: list[SentinelEntitiesMapping] | None = None
    customDetails: dict[str, str] | None = None
    alertDetailsOverride: AlertDetailsOverride | None = None
    eventGroupingSettings: EventGroupingSettings | None = None
    incidentConfiguration: IncidentConfiguration | None = None
    alertRuleTemplateName: str | None = None
    templateVersion: str | None = None

    @model_validator(mode="after")
    def validate_matching_method(self) -> SentinelScheduledPayload:
        """Selected matching method requires at least one groupBy array."""
        if self.incidentConfiguration and self.incidentConfiguration.groupingConfiguration:
            gc = self.incidentConfiguration.groupingConfiguration
            if gc.matchingMethod == MatchingMethod.SELECTED:
                has_entities = bool(gc.groupByEntities)
                has_details = bool(gc.groupByAlertDetails)
                has_custom = bool(gc.groupByCustomDetails)
                if not (has_entities or has_details or has_custom):
                    raise ValueError(
                        "matchingMethod 'Selected' requires at least one "
                        "non-empty groupBy array"
                    )
        return self


class SentinelNRTPayload(BaseModel):
    """Sentinel NRT alert rule payload."""

    kind: Literal["NRT"]
    displayName: str
    description: str | None = None
    enabled: bool = True
    severity: Severity
    # No upper bound: the ARM API accepts and runs queries longer than the
    # 10,000 characters Microsoft documents for analytics rules (rules
    # collected back from live tenants exceed it). Lint rule KQL009 warns
    # above that figure instead of failing validation here.
    query: str = Field(min_length=1)
    suppressionEnabled: bool | None = None
    suppressionDuration: str | None = None
    tactics: list[AttackTactic] | None = None
    techniques: list[str] | None = None
    subTechniques: list[str] | None = None
    # Microsoft Sentinel's ARM contract for alertRules accepts up to 10
    # entityMappings per rule. The previous cap of 5 here was from a
    # 2022-era doc page; the 2025-07-01-preview API surface explicitly
    # allows more. Confirmed empirically 2026-05-18 by an adopter whose
    # 6-mapping production rule (collected from a working tenant)
    # tripped the old cap and CI rejected it. See task #39 in the
    # adopter-friction notes.
    entityMappings: list[EntityMapping] | None = Field(default=None, max_length=10)
    sentinelEntitiesMappings: list[SentinelEntitiesMapping] | None = None
    customDetails: dict[str, str] | None = None
    alertDetailsOverride: AlertDetailsOverride | None = None
    eventGroupingSettings: EventGroupingSettings | None = None
    incidentConfiguration: IncidentConfiguration | None = None
    alertRuleTemplateName: str | None = None
    templateVersion: str | None = None

    @model_validator(mode="before")
    @classmethod
    def reject_scheduled_fields(cls, data: dict) -> dict:
        """NRT rules must not have Scheduled-only fields."""
        for field in SCHEDULED_ONLY_FIELDS:
            if field in data and data[field] is not None:
                raise ValueError(
                    f"NRT rules must not have '{field}' — "
                    f"that field is Scheduled-only"
                )
        return data


# ---------------------------------------------------------------------------
# Sentinel — additional alert rule kinds (MSI, Fusion, MLBA, TI)
# ---------------------------------------------------------------------------


class SentinelMicrosoftSecurityIncidentCreationPayload(BaseModel):
    """``MicrosoftSecurityIncidentCreation`` alert rule.

    ARM kind that promotes alerts from a connected Microsoft security
    product into Sentinel incidents. Optional whitelist / blacklist
    filters constrain which alerts trigger creation.
    """

    kind: Literal["MicrosoftSecurityIncidentCreation"]
    displayName: str
    description: str | None = None
    enabled: bool = True
    productFilter: MicrosoftSecurityProductName
    severitiesFilter: list[Severity] | None = None
    displayNamesFilter: list[str] | None = None
    displayNamesExcludeFilter: list[str] | None = None
    alertRuleTemplateName: str | None = None
    templateVersion: str | None = None

    @model_validator(mode="after")
    def reject_filter_overlap(self) -> "SentinelMicrosoftSecurityIncidentCreationPayload":
        if self.displayNamesFilter and self.displayNamesExcludeFilter:
            overlap = set(self.displayNamesFilter) & set(self.displayNamesExcludeFilter)
            if overlap:
                raise ValueError(
                    "displayNamesFilter and displayNamesExcludeFilter overlap on: "
                    + ", ".join(sorted(overlap))
                )
        return self


class FusionSourceSubType(BaseModel):
    """One sub-type within a Fusion source.

    Fusion source settings are nested: each top-level *source* (e.g.
    "Anomaly", "Microsoft Defender for Identity") may itself contain
    sub-types whose enabled state is independently togglable.
    """

    sourceSubTypeName: str
    enabled: bool
    severityFilters: dict | None = None


class FusionSourceSetting(BaseModel):
    sourceName: str
    enabled: bool
    sourceSubTypes: list[FusionSourceSubType] | None = None


class SentinelFusionPayload(BaseModel):
    """``Fusion`` alert rule.

    Fusion content is templated by Microsoft and not authored by users:
    we manage only the toggle (``enabled``) and the ``sourceSettings``
    overlay. ``alertRuleTemplateName`` is required to identify the
    Microsoft-shipped fusion model.
    """

    kind: Literal["Fusion"]
    enabled: bool = True
    alertRuleTemplateName: str
    sourceSettings: list[FusionSourceSetting] | None = None


class SentinelMLBehaviorAnalyticsPayload(BaseModel):
    """``MLBehaviorAnalytics`` alert rule.

    Microsoft-shipped behaviour analytics content. Toggle-only — the
    detection logic itself is not customer-modifiable.
    """

    kind: Literal["MLBehaviorAnalytics"]
    enabled: bool = True
    alertRuleTemplateName: str


class SentinelThreatIntelligencePayload(BaseModel):
    """``ThreatIntelligence`` alert rule.

    Toggle-only Microsoft-shipped threat-intel correlation rule.
    """

    kind: Literal["ThreatIntelligence"]
    enabled: bool = True
    alertRuleTemplateName: str


# ---------------------------------------------------------------------------
# Defender sub-models
# ---------------------------------------------------------------------------


# ``schedule.period`` is the legacy Graph beta field. Graph deprecates it
# in favour of ``frequency`` and the v1.0 ``ruleSchedule`` type has no
# ``period`` at all.
_DEFENDER_LEGACY_PERIODS = frozenset({"0", "1H", "3H", "12H", "24H"})

# Limits the service applies to a rule's schedule (the "Frequency" and
# "Lookback" fields of the Defender portal's rule wizard). A frequency of
# zero (``PT0S``) is a continuous (NRT) rule and takes no lookback.
_DEFENDER_MIN_FREQUENCY = timedelta(minutes=5)
_DEFENDER_MAX_FREQUENCY = timedelta(days=14)
# Maximum lookback by frequency: below 1 hour it must stay under 48
# hours; below 1 day it may reach 14 days; from 1 day on, 30 days.
_DEFENDER_SUB_HOURLY_LOOKBACK_LIMIT = timedelta(hours=48)  # exclusive
_DEFENDER_SUB_DAILY_MAX_LOOKBACK = timedelta(days=14)
_DEFENDER_MAX_LOOKBACK = timedelta(days=30)

_ISO_8601_DURATION_RE = re.compile(
    r"^P(?:(\d+)W)?(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?$"
)


def _parse_schedule_duration(value: str, *, field: str) -> timedelta:
    """Parse an ISO 8601 duration as Graph writes it for a rule schedule.

    Weeks, days, hours, minutes and whole seconds are accepted (``PT0S``,
    ``PT15M``, ``PT1H``, ``P1D``, ``P2W``). Months and years have no fixed
    length and are not schedule values.
    """
    match = _ISO_8601_DURATION_RE.match(value)
    if match is None or all(part is None for part in match.groups()):
        raise ValueError(
            f"schedule.{field} must be an ISO 8601 duration such as PT1H or P1D, got {value!r}"
        )
    weeks, days, hours, minutes, seconds = (int(part or 0) for part in match.groups())
    return timedelta(weeks=weeks, days=days, hours=hours, minutes=minutes, seconds=seconds)


def _has_entity_mapping(entity_mappings: dict[str, Any] | None) -> bool:
    """True when at least one entity mapping names a query column.

    The service returns every entity collection, unused ones as empty
    lists and unused columns as empty strings, so emptiness is decided
    per column.
    """
    for mappings in (entity_mappings or {}).values():
        if not isinstance(mappings, list):
            continue
        for mapping in mappings:
            if isinstance(mapping, dict) and any(
                isinstance(column, str) and column.strip() for column in mapping.values()
            ):
                return True
    return False


class DefenderSchedule(BaseModel):
    """Run schedule of a custom detection rule.

    ``frequency`` (ISO 8601 duration) decides when it is present and is
    checked, together with ``lookback``, against the service limits.
    ``period`` is its deprecated predecessor: it is required, and
    checked, only when ``frequency`` is absent.
    """

    period: str | None = None
    frequency: str | None = None
    lookback: str | None = None

    @model_validator(mode="after")
    def validate_schedule(self) -> DefenderSchedule:
        frequency_text = (self.frequency or "").strip()
        if not frequency_text:
            if self.period is None:
                raise ValueError("schedule requires frequency (or the legacy period)")
            if self.period not in _DEFENDER_LEGACY_PERIODS:
                raise ValueError(
                    "schedule.period must be one of 0, 1H, 3H, 12H, 24H when frequency is not set"
                )
            return self

        frequency = _parse_schedule_duration(frequency_text, field="frequency")
        lookback_text = (self.lookback or "").strip()
        if frequency == timedelta(0):
            if lookback_text:
                raise ValueError("schedule.lookback is not supported for continuous (NRT) rules")
            return self
        if not _DEFENDER_MIN_FREQUENCY <= frequency <= _DEFENDER_MAX_FREQUENCY:
            raise ValueError(
                "schedule.frequency must be between 5 minutes and 14 days (or PT0S for continuous)"
            )
        if not lookback_text:
            # The service derives the lookback from the frequency.
            return self

        lookback = _parse_schedule_duration(lookback_text, field="lookback")
        if lookback < frequency:
            raise ValueError("schedule.lookback must be at least the frequency")
        if frequency < timedelta(hours=1):
            if lookback >= _DEFENDER_SUB_HOURLY_LOOKBACK_LIMIT:
                raise ValueError(
                    "schedule.lookback must be less than 48 hours when frequency is below 1 hour"
                )
        elif frequency < timedelta(days=1):
            if lookback > _DEFENDER_SUB_DAILY_MAX_LOOKBACK:
                raise ValueError(
                    "schedule.lookback must be at most 14 days when frequency is below 1 day"
                )
        elif lookback > _DEFENDER_MAX_LOOKBACK:
            raise ValueError("schedule.lookback must be at most 30 days")
        return self


class DefenderImpactedAsset(BaseModel):
    odata_type: str = Field(alias="@odata.type")
    identifier: str

    model_config = {"populate_by_name": True}


class DefenderAlertTemplate(BaseModel):
    title: str
    description: str | None = None
    severity: Literal["informational", "low", "medium", "high"]
    category: str | None = None
    recommendedActions: str | None = None
    mitreTechniques: list[str] | None = None
    # Graph deprecates ``impactedAssets`` in favour of ``entityMappings``;
    # a rule built with entity mapping carries an empty list here. Either
    # property has to identify at least one entity.
    impactedAssets: list[DefenderImpactedAsset] = Field(default_factory=list)
    entityMappings: dict[str, Any] | None = None

    @model_validator(mode="after")
    def require_an_entity(self) -> DefenderAlertTemplate:
        if not self.impactedAssets and not _has_entity_mapping(self.entityMappings):
            raise ValueError(
                "At least one of impactedAssets or entityMappings must be provided."
            )
        return self


class DefenderResponseAction(BaseModel):
    odata_type: str = Field(alias="@odata.type")
    identifier: str

    model_config = {"populate_by_name": True}


class DefenderOrganizationalScope(BaseModel):
    scopeType: str | None = None
    scopeNames: list[str] | None = None


class DefenderDetectionAction(BaseModel):
    alertTemplate: DefenderAlertTemplate
    organizationalScope: DefenderOrganizationalScope | None = None
    responseActions: list[DefenderResponseAction] | None = None


class DefenderQueryCondition(BaseModel):
    # Unknown properties are ignored, not rejected: Graph adds properties
    # without notice, and one unknown property on one rule would otherwise
    # fail validation for the whole repository.
    model_config = ConfigDict(extra="ignore")
    # No upper bound (see SentinelScheduledPayload.query); KQL009 is
    # advisory for Defender, which documents no query-length limit.
    queryText: str


class DefenderPayload(BaseModel):
    """Defender XDR custom detection rule payload."""

    # Unknown properties are ignored for the same reason as on
    # ``DefenderQueryCondition``. Required properties stay required.
    model_config = ConfigDict(extra="ignore")
    displayName: str
    description: str | None = None
    # ``status`` replaced ``isEnabled`` in Graph beta (isEnabled removed
    # 2026-10-01). Both are accepted; ``status`` wins when both are set.
    # See contentops/defender/rule_status.py.
    status: Literal["enabled", "disabled", "autoDisabled"] | None = None
    isEnabled: bool | None = None
    queryCondition: DefenderQueryCondition
    schedule: DefenderSchedule
    detectionAction: DefenderDetectionAction


# ---------------------------------------------------------------------------
# Pipeline envelope
# ---------------------------------------------------------------------------


class RuleEnvelope(BaseModel):
    """Top-level pipeline fields wrapping any rule."""

    id: str = Field(pattern=r"^[a-z0-9][a-z0-9\-]*[a-z0-9]$")
    version: str
    platform: Platform
    status: Status


SentinelAlertRulePayload = (
    SentinelScheduledPayload
    | SentinelNRTPayload
    | SentinelMicrosoftSecurityIncidentCreationPayload
    | SentinelFusionPayload
    | SentinelMLBehaviorAnalyticsPayload
    | SentinelThreatIntelligencePayload
)


_SENTINEL_KIND_TO_MODEL: dict[str, type[BaseModel]] = {
    "Scheduled": SentinelScheduledPayload,
    "NRT": SentinelNRTPayload,
    "MicrosoftSecurityIncidentCreation": SentinelMicrosoftSecurityIncidentCreationPayload,
    "Fusion": SentinelFusionPayload,
    "MLBehaviorAnalytics": SentinelMLBehaviorAnalyticsPayload,
    "ThreatIntelligence": SentinelThreatIntelligencePayload,
}


def validate_sentinel_payload(payload: dict) -> "SentinelAlertRulePayload":
    """Validate a Sentinel alert rule payload, dispatching by ``kind``."""
    kind = payload.get("kind")
    model = _SENTINEL_KIND_TO_MODEL.get(kind)
    if model is None:
        valid = ", ".join(sorted(_SENTINEL_KIND_TO_MODEL))
        raise ValueError(
            f"Unknown Sentinel kind: {kind!r} (expected one of: {valid})"
        )
    return model(**payload)  # type: ignore[return-value]


def validate_defender_payload(payload: dict) -> DefenderPayload:
    """Validate a Defender payload."""
    return DefenderPayload(**payload)
