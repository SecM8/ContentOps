# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Workspace KQL helper — shared infra for F4 / F20 (and future F2).

Wraps the Log Analytics Query API:
    POST https://api.loganalytics.io/v1/workspaces/<workspace_id>/query

Returns parsed rows (list of dicts keyed by column name). Used by:

* F4 `contentops silent-rules` — counts SecurityAlert / SecurityIncident
  per rule.
* F20 `contentops portfolio --with-telemetry` — populates fire-rate /
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


# Rule identity in telemetry (see contentops/rule_keys.py, which normalises
# repo-side keys the same way). Incidents list the analytic rules their alerts
# came from in RelatedAnalyticRuleIds (possibly full ARM ids -> last path
# segment). A Sentinel alert takes its rule from the incident it belongs to
# when that incident has exactly one related rule (Microsoft documents that
# field); otherwise from AlertType, which Microsoft documents only as "taken
# from the rule ID" and is seen as "<workspace-guid>_<rule name>".
_SENTINEL_PRODUCTS = '("Azure Sentinel", "Microsoft Sentinel")'
_WS_PREFIXED_RULE = (
    r'@"^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-'
    r'[0-9A-Fa-f]{12}_(.+)$"'
)


def _alert_rule_id_expr() -> str:
    """KQL: lower-cased rule name of a Sentinel analytic alert, else "".

    Needs ``linked_rule_id`` from :func:`_alert_rule_link_lets`. Only
    Sentinel alerts get a rule id: a Defender alert in an incident that
    also holds one Sentinel rule's alert must not be credited to that rule.
    """
    from_alert_type = f"tolower(coalesce(extract({_WS_PREFIXED_RULE}, 1, AlertType), AlertType))"
    return (
        f"iff(ProductName in {_SENTINEL_PRODUCTS}, "
        f"coalesce(linked_rule_id, {from_alert_type}), "
        f'"")'
    )


def _incident_rule_id_expr(ref: str) -> str:
    """KQL: lower-cased rule name from one RelatedAnalyticRuleIds entry."""
    last = f'extract(@"([^/]+)$", 1, {ref})'
    return f"tolower(coalesce(extract({_WS_PREFIXED_RULE}, 1, {last}), {last}))"


def _name_key_expr(column: str) -> str:
    return f'strcat("name:", tolower(trim(@"\\s+", {column})))'


def _alert_rule_link_lets() -> str:
    """KQL ``let`` statements shared by the telemetry queries.

    ``incident_latest``: one row per incident, its latest state
    (SecurityIncident logs a row per update). ``alert_rule_link``: for
    every alert in an incident with exactly one related analytic rule, that
    rule's id (``AlertIds`` holds ``SystemAlertId`` values, as in
    :func:`_security_alerts_joined_base`).
    """
    return f"""let incident_latest = materialize(SecurityIncident
| where TimeGenerated > ago(window)
| summarize arg_max(TimeGenerated, *) by IncidentNumber);
let alert_rule_link = incident_latest
| where array_length(RelatedAnalyticRuleIds) == 1
| extend linked_rule_id = {_incident_rule_id_expr("tostring(RelatedAnalyticRuleIds[0])")}
| mv-expand AlertId = AlertIds to typeof(string)
| where isnotempty(AlertId) and isnotempty(linked_rule_id)
| summarize linked_rule_id = take_any(linked_rule_id) by AlertId;"""


def _latest_alerts() -> str:
    """KQL: one row per alert (latest state) with its ``linked_rule_id``."""
    return """SecurityAlert
| where TimeGenerated > ago(window)
| summarize arg_max(TimeGenerated, AlertName, AlertType, ProductName) by SystemAlertId
| join kind=leftouter (alert_rule_link) on $left.SystemAlertId == $right.AlertId"""


def silent_rules_query(*, since_days: int = 30) -> str:
    """Return the canonical KQL that powers `contentops silent-rules`.

    One row per **rule key** with SecurityAlert and SecurityIncident
    counts in the window. A rule key is ``id:<rule name>`` when the alert /
    incident identifies its Sentinel analytic rule and ``name:<display
    name>`` otherwise -- joining by display name alone missed every rule
    using ``alertDisplayNameFormat`` and every renamed incident, which then
    looked silent. A Sentinel alert's rule is the single related rule of
    its incident when there is one, else the rule id in ``AlertType``;
    incidents use ``RelatedAnalyticRuleIds`` (one row per related rule).
    Every alert therefore lands in exactly one row and every incident in at
    most one row per rule, so ``contentops.rule_keys.TelemetryIndex`` can
    sum a rule's rows (ids and names) without double counting.

    De-duplication:

    * SecurityAlert writes a new row on each status change, so alerts are
      first reduced to their latest row per ``SystemAlertId``.
    * SecurityIncident logs one row per incident UPDATE (assign, comment,
      close), so incidents are reduced to their latest row per
      ``IncidentNumber`` -- the same ``arg_max`` pattern as
      ``_security_alerts_joined_base``. Counting raw rows inflated
      ``incidents_30d`` and let ``closed_fp_30d`` reflect intermediate
      states.

    ``closed_tp_30d`` / ``closed_fp_30d`` / ``closed_bp_30d`` count
    incidents whose latest row is ``Status == "Closed"`` with
    classification TruePositive / FalsePositive / BenignPositive. The
    status check matters: ``Classification`` is the value given when the
    incident was last closed and survives a reopen, so a reopened incident
    still carries it. Open, reopened and Undetermined incidents are in
    ``incidents_30d`` only.
    """
    return f"""
let window = {since_days}d;
{_alert_rule_link_lets()}
let alerts = {_latest_alerts()}
| extend rule_id = {_alert_rule_id_expr()}
| extend rule_key = iff(isnotempty(rule_id), strcat("id:", rule_id), {_name_key_expr("AlertName")})
| summarize alerts_30d = count(), alert_name = take_any(AlertName) by rule_key;
let incidents = incident_latest
| extend rule_refs = iff(array_length(RelatedAnalyticRuleIds) > 0, RelatedAnalyticRuleIds, dynamic([""]))
| mv-expand rule_ref = rule_refs to typeof(string)
| extend rule_id = {_incident_rule_id_expr("rule_ref")}
| extend rule_key = iff(isnotempty(rule_id), strcat("id:", rule_id), {_name_key_expr("Title")})
| distinct IncidentNumber, rule_key, Title, Classification, Status
| summarize incidents_30d = count(),
            closed_tp_30d = countif(Status == "Closed" and Classification == "TruePositive"),
            closed_fp_30d = countif(Status == "Closed" and Classification == "FalsePositive"),
            closed_bp_30d = countif(Status == "Closed" and Classification == "BenignPositive"),
            incident_title = take_any(Title)
            by rule_key;
alerts
| join kind=fullouter (incidents) on rule_key
| project rule_key = coalesce(rule_key, rule_key1),
          rule_name = coalesce(alert_name, incident_title),
          alerts_30d = coalesce(alerts_30d, 0),
          incidents_30d = coalesce(incidents_30d, 0),
          closed_tp_30d = coalesce(closed_tp_30d, 0),
          closed_fp_30d = coalesce(closed_fp_30d, 0),
          closed_bp_30d = coalesce(closed_bp_30d, 0)
| order by alerts_30d asc, rule_name asc
""".strip()


# ---------------------------------------------------------------------------
# F20 telemetry — same KQL, returns same rows
# ---------------------------------------------------------------------------


def telemetry_query(*, since_days: int = 30) -> str:
    """Same KQL as silent_rules_query — both features need the same data."""
    return silent_rules_query(since_days=since_days)


def closed_fp_rate(row: Any) -> float | None:
    """A rule's false-positive rate from one (merged) telemetry row.

    ``closed_fp_30d / (closed_tp_30d + closed_fp_30d + closed_bp_30d)``:
    the FalsePositive share of the incidents closed with a verdict. Open
    incidents and incidents closed as Undetermined carry none, so they
    are left out of both sides. ``None`` when no incident was closed as
    TP, FP or BP. The one definition behind the ``lifecycle promote``
    gate, the report and ``portfolio --with-telemetry``.
    """
    tp, fp, bp = (
        int(row.get(column) or 0)
        for column in ("closed_tp_30d", "closed_fp_30d", "closed_bp_30d")
    )
    closed = tp + fp + bp
    return fp / closed if closed else None


# ---------------------------------------------------------------------------
# Tuning impact preview — NVISO Part 8
# ---------------------------------------------------------------------------


def _kql_string_literal(value: str) -> str:
    """Render a value as a KQL string literal with full escape coverage."""
    return (
        '"'
        + value
        .replace('\\', '\\\\')
        .replace('"', '\\"')
        .replace('\n', '\\n')
        .replace('\r', '\\r')
        .replace('\t', '\\t')
        .replace('\0', '')
        + '"'
    )


def suppression_impact_query(
    *,
    rule_names: list[str] | None = None,
    rule_keys: list[str] | None = None,
    since_days: int = 30,
) -> str:
    """KQL that counts alerts + incidents that would be silenced by
    suppressing the given rules over the lookback window.

    NVISO Part 8 ("21 incidents, 309 alerts" example) — gives reviewers
    a concrete blast-radius estimate before approving a new drift
    suppression.

    Rules are given as rule keys (``id:<rule name>`` / ``name:<display
    name>``, see ``contentops.rule_keys``); plain ``rule_names`` become
    ``name:`` keys. Each alert / incident is attributed to the first key
    it matches -- its rule id when that is one of the keys, else its
    display name -- so the caller can sum a rule's keys without double
    counting. Alerts are de-duplicated per ``SystemAlertId`` and
    incidents per ``IncidentNumber`` first (both tables log a row per
    update), and a Sentinel alert takes its rule id as in
    :func:`silent_rules_query`.

    Returns one row per matched key (``match_key``) with
    ``alerts_count`` / ``incidents_count``; keys that matched nothing
    don't appear (the renderer fills 0 / 0).
    """
    from contentops.rule_keys import NAME_PREFIX, normalise_rule_name

    keys: list[str] = list(rule_keys or [])
    for name in rule_names or []:
        normalised = normalise_rule_name(name)
        if normalised:
            keys.append(NAME_PREFIX + normalised)
    keys = list(dict.fromkeys(k for k in keys if k))
    if not keys:
        # Avoid emitting a bare `in ()` which LA rejects.
        return "print match_key=''| where false"

    keys_kql = ", ".join(_kql_string_literal(k) for k in keys)
    return f"""
let window = {since_days}d;
let keys = dynamic([{keys_kql}]);
{_alert_rule_link_lets()}
let alerts = {_latest_alerts()}
| extend rule_id = {_alert_rule_id_expr()}
| extend id_key = iff(isnotempty(rule_id), strcat("id:", rule_id), ""),
         name_key = {_name_key_expr("AlertName")}
| extend match_key = iff(id_key in (keys), id_key, iff(name_key in (keys), name_key, ""))
| where isnotempty(match_key)
| summarize alerts_count = count() by match_key;
let incidents = incident_latest
| extend rule_refs = iff(array_length(RelatedAnalyticRuleIds) > 0, RelatedAnalyticRuleIds, dynamic([""]))
| mv-expand rule_ref = rule_refs to typeof(string)
| extend rule_id = {_incident_rule_id_expr("rule_ref")}
| extend id_key = iff(isnotempty(rule_id), strcat("id:", rule_id), ""),
         name_key = {_name_key_expr("Title")}
| extend match_key = iff(id_key in (keys), id_key, iff(name_key in (keys), name_key, ""))
| where isnotempty(match_key)
| distinct IncidentNumber, match_key
| summarize incidents_count = count() by match_key;
alerts
| join kind=fullouter (incidents) on match_key
| project match_key = coalesce(match_key, match_key1),
          alerts_count = coalesce(alerts_count, 0),
          incidents_count = coalesce(incidents_count, 0)
| order by incidents_count desc, alerts_count desc, match_key asc
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
          VendorOriginalId,
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
| project SystemAlertId, VendorOriginalId, AlertName, AlertSeverity,
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
    "silent_rules_query", "telemetry_query", "closed_fp_rate",
    "auto_disabled_query",
    "security_alerts_for_date_query",
    "security_alerts_joined_query",
    "security_alerts_joined_for_date_query",
    "reconciliation_query",
    "suppression_impact_query",
]
