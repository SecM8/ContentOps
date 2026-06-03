# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Workspace KQL helper — shared infra for F4 / F20 (and future F2).

Wraps the Log Analytics Query API:
    POST https://api.loganalytics.io/v1/workspaces/<workspace_id>/query

Returns parsed rows (list of dicts keyed by column name). Used by:

* F4 `contentops silent-rules` — counts SecurityAlert / SecurityIncident
  per rule.
* F20 `pipeline portfolio --with-telemetry` — populates fire-rate /
  FP-rate / cost columns.

Pure: takes an HTTP-runner callable so tests can mock without
httpx. The CLI passes a real httpx-backed runner.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable

import httpx


LA_QUERY_BASE = "https://api.loganalytics.io"
LA_SCOPE = "https://api.loganalytics.io/.default"


class WorkspaceKqlError(RuntimeError):
    """Raised when the LA Query API request fails or returns malformed data."""


@dataclass
class QueryResult:
    """One LA Query API response, parsed."""
    rows: list[dict[str, Any]] = field(default_factory=list)
    column_names: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Core
# ---------------------------------------------------------------------------


def parse_response(body: dict[str, Any]) -> QueryResult:
    """Transform the LA Query API JSON into a list[dict] keyed by column.

    LA shape:
        { "tables": [ { "name": "PrimaryResult", "columns": [...], "rows": [...] } ] }
    Columns: [{name, type}], rows: list[list[value]]. We zip them.
    """
    tables = body.get("tables") or []
    if not tables:
        return QueryResult()
    primary = tables[0]
    cols = [str(c.get("name") or "") for c in (primary.get("columns") or [])]
    rows: list[dict[str, Any]] = []
    for raw_row in primary.get("rows") or []:
        if not isinstance(raw_row, list):
            continue
        rows.append({
            col: raw_row[i] if i < len(raw_row) else None
            for i, col in enumerate(cols)
        })
    return QueryResult(rows=rows, column_names=cols)


def query(
    kql: str,
    *,
    workspace_id: str,
    token: str,
    timeout: float | httpx.Timeout = httpx.Timeout(
        # Read=30s matches the historical scalar. Connect/pool=10s so
        # an unreachable LA endpoint fails fast rather than burning the
        # full read budget on each retry attempt.
        connect=10.0, read=30.0, write=30.0, pool=10.0,
    ),
    transport: httpx.BaseTransport | None = None,
) -> QueryResult:
    """Run ``kql`` against the LA workspace and return a QueryResult.

    ``transport`` is an httpx.BaseTransport that tests can pass to
    intercept the HTTP call without real network. The CLI passes
    None and uses the default.
    """
    if not workspace_id:
        raise WorkspaceKqlError("workspace_id is required")
    url = f"/v1/workspaces/{workspace_id}/query"
    client = httpx.Client(
        base_url=LA_QUERY_BASE,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        timeout=timeout,
        transport=transport,
    )
    try:
        from contentops.utils.http_retry import request_with_retry

        try:
            response = request_with_retry(
                lambda: client.post(url, json={"query": kql}),
                label=f"LA Query POST {url}",
            )
        except (httpx.HTTPError, OSError) as exc:
            raise WorkspaceKqlError(f"LA Query request failed: {exc}") from exc
        if response.status_code >= 400:
            raise WorkspaceKqlError(
                f"LA Query returned {response.status_code}: "
                f"{response.text[:200]}"
            )
        try:
            body = response.json()
        except Exception as exc:
            raise WorkspaceKqlError(f"LA Query response not JSON: {exc}") from exc
        return parse_response(body)
    finally:
        client.close()


# ---------------------------------------------------------------------------
# F4 silent-rules — count alerts/incidents per rule
# ---------------------------------------------------------------------------


def silent_rules_query(*, since_days: int = 30) -> str:
    """Return the canonical KQL that powers `contentops silent-rules`.

    For every rule's displayName, count SecurityAlert + SecurityIncident
    rows in the window. Rules with zero rows are "silent".
    """
    return f"""
let window = {since_days}d;
let alerts = SecurityAlert
| where TimeGenerated > ago(window)
| summarize alerts_30d = count() by AlertName;
let incidents = SecurityIncident
| where TimeGenerated > ago(window)
| summarize incidents_30d = count(),
            closed_fp_30d = countif(Classification == "FalsePositive")
            by Title;
alerts
| join kind=fullouter (incidents) on $left.AlertName == $right.Title
| project rule_name = coalesce(AlertName, Title),
          alerts_30d = coalesce(alerts_30d, 0),
          incidents_30d = coalesce(incidents_30d, 0),
          closed_fp_30d = coalesce(closed_fp_30d, 0)
| order by alerts_30d asc, rule_name asc
""".strip()


# ---------------------------------------------------------------------------
# F20 telemetry — same KQL, returns same rows
# ---------------------------------------------------------------------------


def telemetry_query(*, since_days: int = 30) -> str:
    """Same KQL as silent_rules_query — both features need the same data."""
    return silent_rules_query(since_days=since_days)


# ---------------------------------------------------------------------------
# Tuning impact preview — NVISO Part 8
# ---------------------------------------------------------------------------


def suppression_impact_query(*, rule_names: list[str], since_days: int = 30) -> str:
    """KQL that counts alerts + incidents that would be silenced by
    suppressing the given rule displayNames over the lookback window.

    NVISO Part 8 ("21 incidents, 309 alerts" example) — gives reviewers
    a concrete blast-radius estimate before approving a new drift
    suppression. The list is matched verbatim against SecurityAlert
    .AlertName and SecurityIncident.Title (Sentinel's own rule-name
    fields), so the caller must resolve each suppression's envelope
    id → displayName before invoking this.

    Returns one row per rule_name with two count columns. Rules that
    fired zero times will not appear (left as a gap that the renderer
    fills with 0 / 0).
    """
    if not rule_names:
        # Avoid emitting a bare `in ()` which LA rejects.
        return "print rule_name=''| where false"
    # Render the names as KQL string literals with full escape coverage.
    def _kql_string_literal(name: str) -> str:
        return (
            '"'
            + name
            .replace('\\', '\\\\')
            .replace('"', '\\"')
            .replace('\n', '\\n')
            .replace('\r', '\\r')
            .replace('\t', '\\t')
            .replace('\0', '')
            + '"'
        )

    names_kql = ", ".join(_kql_string_literal(n) for n in rule_names)
    return f"""
let window = {since_days}d;
let names = dynamic([{names_kql}]);
let alerts = SecurityAlert
| where TimeGenerated > ago(window)
| where AlertName in (names)
| summarize alerts_count = count() by rule_name = AlertName;
let incidents = SecurityIncident
| where TimeGenerated > ago(window)
| where Title in (names)
| summarize incidents_count = count() by rule_name = Title;
alerts
| join kind=fullouter (incidents) on rule_name
| project rule_name = coalesce(rule_name, rule_name1),
          alerts_count = coalesce(alerts_count, 0),
          incidents_count = coalesce(incidents_count, 0)
| order by incidents_count desc, alerts_count desc, rule_name asc
""".strip()


# ---------------------------------------------------------------------------
# Auto-disabled rule detection — NVISO Part 7
# ---------------------------------------------------------------------------


def auto_disabled_query(*, since_days: int = 7) -> str:
    """Return KQL that surfaces rules the Sentinel platform itself has
    disabled, plus rules with recent query failures that may be on track
    to be auto-disabled.

    Two complementary signals:

      * ``SentinelHealth`` table — emits one row per analytic rule
        lifecycle event (enabled / disabled / updated / failure). A
        ``Status == "Disabled"`` row that was not driven by repo apply
        means the platform stepped in (e.g. consecutive query failures,
        ingest schema break, deprecated table reference).

      * ``LAQueryLogs`` table — query-execution telemetry. Rules with
        repeated ``QueryStatus != "Succeeded"`` runs are heading toward
        auto-disable even before SentinelHealth flags them.

    Prerequisite: ``SentinelHealth`` is an OPT-IN diagnostic data
    collection on the workspace (opt-in since approximately 2022). If
    it's not turned on, this query returns zero rows for the SentinelHealth
    branch — silently. Operators should verify the diagnostic is
    enabled before relying on this signal; see
    https://learn.microsoft.com/en-us/azure/sentinel/health-audit.

    Both branches are unioned so the absence of one source still surfaces
    findings from the other.
    """
    return f"""
let window = {since_days}d;
let auto_disabled =
    SentinelHealth
    | where TimeGenerated > ago(window)
    | where SentinelResourceKind == "Alert Rule"
    | where Status in ("Disabled", "Failure")
    | summarize last_event = max(TimeGenerated),
                event_count = count()
              by rule_name = tostring(SentinelResourceName),
                 signal = tostring(Status)
    | project rule_name, signal, last_event, event_count,
              source = "SentinelHealth";
let failing_queries =
    LAQueryLogs
    | where TimeGenerated > ago(window)
    | where tostring(RequestContext) has "Microsoft.SecurityInsights"
    | where ResponseCode >= 400
    | summarize last_event = max(TimeGenerated),
                event_count = count()
              by rule_name = hash_sha256(tostring(QueryText)), signal = "QueryFailure"
    | project rule_name, signal, last_event, event_count,
              source = "LAQueryLogs";
union auto_disabled, failing_queries
| order by last_event desc, rule_name asc
""".strip()


def security_alerts_query(*, since_days: int = 30) -> str:
    """Return KQL that fetches deduplicated alerts from SecurityAlert table.

    The SecurityAlert table writes a new row on each status change, so
    a single alert may appear 2-4 times. ``arg_max(TimeGenerated, *)``
    keeps only the latest row per ``SystemAlertId``.
    """
    return _security_alerts_base(f"TimeGenerated > ago({since_days}d)")


_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def security_alerts_for_date_query(*, target_date: str) -> str:
    """Return KQL for a single day's alerts, deduplicated.

    ``target_date`` is ``YYYY-MM-DD``. Returns all alerts whose
    ``TimeGenerated`` falls within ``[date, date+1d)``.
    """
    if not _DATE_RE.fullmatch(target_date):
        raise ValueError(f"target_date must be YYYY-MM-DD, got {target_date!r}")
    return _security_alerts_base(
        f"TimeGenerated >= datetime({target_date}) "
        f"and TimeGenerated < datetime({target_date}) + 1d"
    )


def _security_alerts_base(where_clause: str) -> str:
    return f"""
SecurityAlert
| where {where_clause}
| summarize arg_max(TimeGenerated, *) by SystemAlertId
| project SystemAlertId,
          AlertName,
          AlertSeverity,
          Status,
          Classification = tostring(parse_json(ExtendedProperties).Classification),
          ProviderName,
          ProductName,
          Tactics,
          Techniques,
          TimeGenerated,
          StartTime,
          EndTime,
          Description,
          AlertType
| order by TimeGenerated desc
""".strip()


def security_alerts_joined_query(*, since_days: int = 30) -> str:
    """KQL that joins SecurityAlert with SecurityIncident for incident lifecycle.

    Returns alerts enriched with incident status, classification, closure
    time, and owner. Alerts without a parent incident are kept via LEFT
    OUTER join with NULL incident columns.
    """
    return _security_alerts_joined_base(f"TimeGenerated > ago({since_days}d)")


def security_alerts_joined_for_date_query(*, target_date: str) -> str:
    """Joined SecurityAlert+SecurityIncident for a single day.

    Uses ``TimeGenerated`` boundaries — captures alerts created on
    that calendar day. NOT ingestion_time(), which would pull in
    re-ingested historical rows and inflate counts.
    """
    if not _DATE_RE.fullmatch(target_date):
        raise ValueError(f"target_date must be YYYY-MM-DD, got {target_date!r}")
    return _security_alerts_joined_base(
        f"TimeGenerated >= datetime({target_date}) "
        f"and TimeGenerated < datetime({target_date}) + 1d"
    )


def _security_alerts_joined_base(where_clause: str) -> str:
    return f"""
let alerts = SecurityAlert
| where {where_clause}
| summarize arg_max(TimeGenerated, *) by SystemAlertId
| project SystemAlertId, AlertName, AlertSeverity,
          AlertStatus = Status,
          AlertClassification = tostring(parse_json(ExtendedProperties).Classification),
          ProviderName, ProductName, Tactics, Techniques,
          TimeGenerated, StartTime, EndTime, Description, AlertType;
let incident_per_alert = SecurityIncident
| where TimeGenerated > ago(90d)
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| mv-expand AlertIds
| extend AlertId = tostring(AlertIds)
| summarize arg_max(IncidentNumber, Classification, ClassificationReason,
                    Status, ClosedTime, Owner, CreatedTime,
                    RelatedAnalyticRuleIds) by AlertId
| project AlertId, IncidentNumber,
          IncidentStatus = Status,
          IncidentClassification = Classification,
          IncidentClassificationReason = ClassificationReason,
          IncidentOwner = Owner, IncidentClosedTime = ClosedTime,
          IncidentCreatedTime = CreatedTime,
          RelatedAnalyticRuleIds;
alerts
| join kind=leftouter (incident_per_alert) on $left.SystemAlertId == $right.AlertId
| project-away AlertId
| order by TimeGenerated desc
""".strip()


def reconciliation_query() -> str:
    """KQL that returns the current incident state for all closed incidents.

    Used by the reconciliation check to verify ledger accuracy.
    """
    return """
SecurityIncident
| where TimeGenerated > ago(90d)
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| mv-expand AlertIds
| extend AlertId = tostring(AlertIds)
| project AlertId, IncidentNumber,
          CurrentStatus = Status,
          CurrentClassification = Classification,
          ClosedTime
""".strip()


__all_extra = [
    "auto_disabled_query",
    "security_alerts_query", "security_alerts_for_date_query",
    "security_alerts_joined_query", "security_alerts_joined_for_date_query",
    "reconciliation_query",
]


# ---------------------------------------------------------------------------
# Workspace-ID auto-derive (PR-J)
# ---------------------------------------------------------------------------


ARM_API_VERSION = "2023-09-01"


def resolve_workspace_id(
    *,
    role: str = "prod",
    workspace_name: str | None = None,
    credential: Any | None = None,
    timeout: float = 30.0,
    transport: httpx.BaseTransport | None = None,
    tenant_config_path: Any | None = None,
) -> str:
    """Auto-derive the LA workspace ID (``customerId`` GUID) from tenant.yml.

    The LA Query API hits ``/v1/workspaces/<id>/...`` where ``<id>``
    must be the workspace **GUID** (``properties.customerId``) — not
    the ARM resource name. Before this helper, operators had to set
    a separate ``PIPELINE_WORKSPACE_ID`` env var alongside the
    tenant.yml entries; now the GUID is derived on-demand.

    Resolution rules:

      * ``workspace_name`` (an exact match on ``workspaceName``) wins
        when provided — used by ``--workspace`` flag callers.
      * Otherwise pick the first ``sentinelWorkspaces`` entry whose
        ``role`` matches.
      * If no role matches and there is exactly one workspace, use it.
      * If no role matches and there is more than one candidate, RAISE
        — never silently guess a workspace (ambiguity protection).

    Looks up the GUID via ARM ``GET /subscriptions/{sub}/resourceGroups/
    {rg}/providers/Microsoft.OperationalInsights/workspaces/{name}``
    and returns ``properties.customerId``.

    Raises ``WorkspaceKqlError`` when:
      * tenant.yml has no Sentinel workspaces.
      * neither ``role`` nor ``workspace_name`` matches.
      * no ``role`` matches and more than one workspace is configured
        (the choice is ambiguous; we refuse to guess).
      * the ARM call returns 4xx / 5xx OR the response lacks
        ``properties.customerId``.
    """
    from contentops.config import load_tenant_config
    from contentops.utils.auth import get_arm_access_token, get_credential

    try:
        cfg = load_tenant_config(path=tenant_config_path) if tenant_config_path \
            else load_tenant_config()
    except FileNotFoundError as exc:
        # Wrap so callers catching WorkspaceKqlError get a uniform error
        # type. The original message (with the cp template hint) is
        # preserved in the chained __cause__.
        raise WorkspaceKqlError(
            f"can't auto-derive workspace ID: {exc}"
        ) from exc
    workspaces = list(cfg.sentinelWorkspaces or [])
    if not workspaces:
        raise WorkspaceKqlError(
            "tenant.yml has no Sentinel workspaces; can't auto-derive "
            "workspace ID. Add a `sentinelWorkspaces` entry or pass "
            "`--workspace-id` explicitly."
        )

    chosen = None
    if workspace_name:
        for w in workspaces:
            if w.workspaceName == workspace_name:
                chosen = w
                break
        if chosen is None:
            available = ", ".join(w.workspaceName for w in workspaces)
            raise WorkspaceKqlError(
                f"workspace name {workspace_name!r} not in tenant.yml "
                f"(available: {available})."
            )
    else:
        for w in workspaces:
            if w.role == role:
                chosen = w
                break
        if chosen is None:
            if len(workspaces) == 1:
                # Unambiguous single-workspace tenant — safe to use it.
                chosen = workspaces[0]
            else:
                available = ", ".join(
                    f"{w.workspaceName} (role={w.role!r})" for w in workspaces
                )
                raise WorkspaceKqlError(
                    f"no Sentinel workspace matches role {role!r} and the "
                    f"tenant has {len(workspaces)} candidates — refusing to "
                    f"guess. Pass `--workspace` to choose explicitly, or set "
                    f"the matching `role` in tenant.yml (available: "
                    f"{available})."
                )

    if credential is None:
        credential = get_credential()
    arm_token = get_arm_access_token(credential).token

    arm_path = (
        f"/subscriptions/{chosen.subscriptionId}"
        f"/resourceGroups/{chosen.resourceGroup}"
        f"/providers/Microsoft.OperationalInsights"
        f"/workspaces/{chosen.workspaceName}"
        f"?api-version={ARM_API_VERSION}"
    )

    with httpx.Client(
        base_url="https://management.azure.com",
        headers={"Authorization": f"Bearer {arm_token}"},
        timeout=timeout,
        transport=transport,
    ) as client:
        from contentops.utils.http_retry import request_with_retry
        response = request_with_retry(
            lambda: client.get(arm_path),
            label=f"ARM workspace GET {chosen.workspaceName!r}",
        )
    if response.status_code >= 400:
        raise WorkspaceKqlError(
            f"ARM workspace lookup returned {response.status_code} "
            f"for {chosen.workspaceName!r}: {response.text[:200]}"
        )
    try:
        body = response.json()
    except Exception as exc:
        raise WorkspaceKqlError(
            f"ARM workspace response for {chosen.workspaceName!r} "
            f"not JSON: {exc}"
        ) from exc
    properties = body.get("properties") or {}
    workspace_id = properties.get("customerId")
    if not workspace_id:
        raise WorkspaceKqlError(
            f"ARM workspace response for {chosen.workspaceName!r} "
            "lacks properties.customerId."
        )
    return str(workspace_id)


__all__ = [
    "ARM_API_VERSION",
    "LA_QUERY_BASE", "LA_SCOPE",
    "WorkspaceKqlError", "QueryResult",
    "parse_response", "query",
    "resolve_workspace_id",
    "silent_rules_query", "telemetry_query",
    "auto_disabled_query",
    "security_alerts_for_date_query",
    "security_alerts_joined_query",
    "security_alerts_joined_for_date_query",
    "reconciliation_query",
    "suppression_impact_query",
]
