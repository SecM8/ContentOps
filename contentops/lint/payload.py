# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Payload-level lint rules.

These rules look at the *envelope payload* (the YAML body the API
receives), not the KQL query inside it. Distinct from
``contentops.lint.kql`` which is query-content focused.

Each rule emits ``LintFinding`` objects compatible with the KQL
runner so the existing reporting / severity machinery just works.
"""

from __future__ import annotations

import re
from typing import Any

from contentops.core.asset import Asset
from contentops.lint.kql import LintFinding
from contentops.utils.slug import _SLUG_MAX_LEN

# Asset kinds whose canonical envelope id is derived from
# ``payload.displayName`` via ``displayname_slug()`` — these are the
# kinds where the 80-char cap can silently change the canonical id
# at collect time and cause downstream reference drift (e.g.
# compliance/mappings/*.yml).
_SLUG_DRIVEN_ASSETS: frozenset[Asset] = frozenset({
    Asset.SENTINEL_ANALYTIC,
    Asset.SENTINEL_HUNTING,
    Asset.DEFENDER_CUSTOM_DETECTION,
})

# Mirror the production slug rules from contentops.utils.slug — kept in
# sync by the test ``test_slug_truncation_helper_mirrors_production``.
_NON_SLUG = re.compile(r"[^a-z0-9]+")


def _check_template_version_coupling(
    payload: dict[str, Any],
) -> list[LintFinding]:
    """ARM rejects ``templateVersion`` without ``alertRuleTemplateName``.

    The 2025-07-01-preview API surface returns

      Invalid Properties for alert rule: 'templateVersion' can only
      be used if 'alertRuleTemplateName' is not empty.

    on PUT, *after* the deploy reaches the wire. We catch it at PR
    time so analysts see the problem before merge.
    """
    if not isinstance(payload, dict):
        return []
    has_tv = bool(payload.get("templateVersion"))
    has_tn = bool(payload.get("alertRuleTemplateName"))
    if has_tv and not has_tn:
        return [LintFinding(
            "PAYLOAD001", "error",
            "templateVersion is set but alertRuleTemplateName is empty/missing — "
            "ARM rejects the PUT with HTTP 400. Either add the "
            "alertRuleTemplateName from the source Marketplace template, "
            "or remove the templateVersion line.",
        )]
    return []


def _check_displayname_slug_truncation(
    payload: dict[str, Any],
) -> list[LintFinding]:
    """PAYLOAD002 — displayName produces a slug that hits the 80-char cap.

    Collected envelopes derive their canonical id from
    ``displayname_slug(displayName)`` (see ``contentops.utils.slug``).
    That helper caps the slug at 80 characters; a longer displayName
    is silently truncated, so the canonical id no longer reads as
    "slugify the displayName" — every downstream reference keyed on
    the full slug silently diverges from what the displayName
    would suggest.
    """
    if not isinstance(payload, dict):
        return []
    display_name = payload.get("displayName")
    if not isinstance(display_name, str) or not display_name:
        return []

    # Build the un-capped slug so we can measure what the production
    # helper would truncate. Mirrors ``displayname_slug`` minus the cap.
    full_slug = _NON_SLUG.sub("-", display_name.strip().lower()).strip("-")
    if len(full_slug) <= _SLUG_MAX_LEN:
        return []

    return [LintFinding(
        "PAYLOAD002", "warning",
        f"displayName produces a slug of {len(full_slug)} characters "
        f"which exceeds the {_SLUG_MAX_LEN}-char canonical-id cap; "
        f"`contentops.utils.slug.displayname_slug` would silently "
        f"truncate it. Hand-authored cross-references quoting the "
        f"un-truncated form would diverge. Either shorten the "
        f"displayName so its slug is <= {_SLUG_MAX_LEN} chars, or "
        f"accept the truncation by keeping the explicit `id:` already "
        f"in the envelope.",
    )]


_SENTINEL_MITRE_ASSETS: frozenset[Asset] = frozenset({
    Asset.SENTINEL_ANALYTIC,
    Asset.SENTINEL_HUNTING,
})


def _check_empty_mitre(
    payload: dict[str, Any], *, asset: Asset,
) -> list[LintFinding]:
    """PAYLOAD003 — warn when MITRE tactics/techniques are empty.

    Sentinel kinds carry ``payload.tactics`` and ``payload.techniques``.
    Defender custom detections carry
    ``payload.detectionAction.alertTemplate.mitreTechniques``. Either
    being empty is a warning (the linter is loud at commit time but
    won't block CI), since a tenant may legitimately ship a rule that
    isn't ATT&CK-mapped yet.
    """
    if not isinstance(payload, dict):
        return []
    findings: list[LintFinding] = []

    if asset in _SENTINEL_MITRE_ASSETS:
        tactics = payload.get("tactics")
        techniques = payload.get("techniques")
        if not tactics:
            findings.append(LintFinding(
                "PAYLOAD003", "warning",
                "payload.tactics is empty; map this rule to at least one "
                "MITRE ATT&CK tactic so Sentinel can correlate incidents "
                "and analysts can filter by tactic.",
            ))
        if not techniques:
            findings.append(LintFinding(
                "PAYLOAD003", "warning",
                "payload.techniques is empty; map this rule to at least "
                "one MITRE ATT&CK technique ID (e.g. T1098) so the rule "
                "shows up under the ATT&CK heatmap.",
            ))
    elif asset is Asset.DEFENDER_CUSTOM_DETECTION:
        alert_template = (
            payload.get("detectionAction", {}) or {}
        ).get("alertTemplate", {}) or {}
        mitre = alert_template.get("mitreTechniques")
        if not mitre:
            findings.append(LintFinding(
                "PAYLOAD003", "warning",
                "payload.detectionAction.alertTemplate.mitreTechniques is "
                "empty; map this rule to at least one MITRE ATT&CK "
                "technique ID so the Defender portal can show it under "
                "the ATT&CK heatmap.",
            ))

    return findings


def _check_null_recommended_actions(
    payload: dict[str, Any], *, asset: Asset,
) -> list[LintFinding]:
    """PAYLOAD004 — warn when Defender ``recommendedActions`` is null.

    SOC analysts see a null ``recommendedActions`` as "no triage
    guidance" in the Defender portal. Warning (not error) because some
    rules genuinely don't need actions beyond the default playbook;
    the lint message nudges authors to fill it in or document why.
    """
    if asset is not Asset.DEFENDER_CUSTOM_DETECTION:
        return []
    if not isinstance(payload, dict):
        return []
    alert_template = (
        payload.get("detectionAction", {}) or {}
    ).get("alertTemplate", {}) or {}
    if "recommendedActions" not in alert_template:
        return []
    value = alert_template["recommendedActions"]
    if value is None or (isinstance(value, str) and not value.strip()):
        return [LintFinding(
            "PAYLOAD004", "warning",
            "payload.detectionAction.alertTemplate.recommendedActions is "
            "null; fill in a short SOC playbook hint (a sentence is "
            "fine) so analysts have triage guidance in the Defender "
            "portal. If genuinely no action is needed, set it to a "
            "non-empty string explaining that.",
        )]
    return []


# Defender ``FileProfile()`` output columns. The beta detectionRules
# save-validator has no schema for FileProfile output, so referencing one
# of these downstream of the ``invoke`` without redeclaring it via
# ``column_ifexists`` 400s the save — even though the query runs fine in
# Advanced Hunting. See docs/operations/defender-fileprofile-detections.md.
_FILEPROFILE_OUTPUT_COLUMNS: tuple[str, ...] = (
    "GlobalPrevalence", "GlobalFirstSeen", "GlobalLastSeen",
    "SignatureState", "IsCertificateValid", "IsRootSignerMicrosoft",
    "Signer", "Issuer",
)
_FILEPROFILE_INVOKE_RE = re.compile(r"invoke\s+FileProfile\s*\(", re.IGNORECASE)
# Entity-mapping identifier -> expected query column. Defender identifiers
# are camelCase; the query column is the PascalCase form for every
# identifier in the corpus (deviceId -> DeviceId). Overrides cover the
# acronym columns where naive PascalCasing would be wrong.
_IDENTIFIER_COLUMN_OVERRIDES: dict[str, str] = {
    "sha1": "SHA1", "sha256": "SHA256", "md5": "MD5",
    "ipAddress": "IPAddress", "url": "Url",
}


def _identifier_to_column(identifier: str) -> str:
    if identifier in _IDENTIFIER_COLUMN_OVERRIDES:
        return _IDENTIFIER_COLUMN_OVERRIDES[identifier]
    return identifier[:1].upper() + identifier[1:]


def _defender_query_text(payload: dict[str, Any]) -> str | None:
    qc = payload.get("queryCondition")
    if isinstance(qc, dict):
        q = qc.get("queryText")
        if isinstance(q, str) and q.strip():
            return q
    return None


def _check_fileprofile_output_filter(
    payload: dict[str, Any], *, asset: Asset,
) -> list[LintFinding]:
    """PAYLOAD005 — FileProfile output column referenced without column_ifexists.

    Heuristic for the documented Defender save-validator 400 (the common
    failure mode). It fires only when the query invokes ``FileProfile`` and
    references one of its output columns WITHOUT a defensive
    ``column_ifexists("Col", ...)`` redeclaration anywhere. Warning, not
    error: ``contentops defender-patch-probe --replicate`` is the
    authoritative check; this just catches the common case at PR time.
    """
    if asset is not Asset.DEFENDER_CUSTOM_DETECTION or not isinstance(payload, dict):
        return []
    query = _defender_query_text(payload)
    if query is None or not _FILEPROFILE_INVOKE_RE.search(query):
        return []
    findings: list[LintFinding] = []
    for col in _FILEPROFILE_OUTPUT_COLUMNS:
        if not re.search(rf"\b{col}\b", query):
            continue
        if re.search(rf"""column_ifexists\(\s*["']{col}["']""", query):
            continue  # redeclared defensively — the validator can see it
        findings.append(LintFinding(
            "PAYLOAD005", "warning",
            f"query invokes FileProfile() and references its output column "
            f"`{col}` without redeclaring it via "
            f'`column_ifexists("{col}", <typed default>)`. The Defender beta '
            f"save-validator has no schema for FileProfile output, so the "
            f"deploy 400s even though the query runs in Advanced Hunting. "
            f"See docs/operations/defender-fileprofile-detections.md.",
        ))
    return findings


def _check_unprojected_entity_columns(
    payload: dict[str, Any], *, asset: Asset,
) -> list[LintFinding]:
    """PAYLOAD006 — entity mapping references a column lost across FileProfile.

    Defender's save-validator 400s ("Entity mappings reference the
    following column(s) which are not projected by the query output")
    specifically when an ``impactedAssets`` identifier's column passes
    through the **schema-less ``FileProfile()`` boundary** and isn't
    re-projected after the ``invoke``. For non-FileProfile queries the
    validator has the table schema and sees columns that flow through
    joins/project-reorder, so this rule is scoped to FileProfile queries
    and only checks the segment AFTER the ``invoke`` (where the parser
    loses visibility). Warning/heuristic — defender-patch-probe is
    authoritative.
    """
    if asset is not Asset.DEFENDER_CUSTOM_DETECTION or not isinstance(payload, dict):
        return []
    query = _defender_query_text(payload)
    if query is None:
        return []
    invoke = _FILEPROFILE_INVOKE_RE.search(query)
    if invoke is None:
        return []
    # Only the segment after the invoke matters: that's where the
    # validator loses schema visibility, so the entity column must be
    # (re)projected there to survive the save.
    after_invoke = query[invoke.end():]
    detection_action = payload.get("detectionAction")
    alert = detection_action.get("alertTemplate") if isinstance(detection_action, dict) else None
    impacted = alert.get("impactedAssets") if isinstance(alert, dict) else None
    if not isinstance(impacted, list):
        return []
    findings: list[LintFinding] = []
    seen: set[str] = set()
    for entry in impacted:
        if not isinstance(entry, dict):
            continue
        ident = entry.get("identifier")
        if not isinstance(ident, str) or not ident.strip():
            continue
        col = _identifier_to_column(ident.strip())
        if col in seen:
            continue
        seen.add(col)
        if not re.search(rf"\b{re.escape(col)}\b", after_invoke):
            findings.append(LintFinding(
                "PAYLOAD006", "warning",
                f"entity mapping identifier `{ident}` expects a `{col}` "
                f"column, but it is not re-projected after `invoke "
                f"FileProfile(...)` — the validator loses schema visibility "
                f"across FileProfile, so the save 400s with "
                f'"Entity mappings reference ... not projected". Re-project it '
                f'after the invoke (e.g. `column_ifexists("{col}", ...)`). '
                f"See docs/operations/defender-fileprofile-detections.md.",
            ))
    return findings


def lint_payload(
    payload: dict[str, Any], *, asset: Asset,
) -> list[LintFinding]:
    """Run every payload-level rule that applies to ``asset``."""
    findings: list[LintFinding] = []
    if asset is Asset.SENTINEL_ANALYTIC:
        findings.extend(_check_template_version_coupling(payload))
    if asset in _SLUG_DRIVEN_ASSETS:
        findings.extend(_check_displayname_slug_truncation(payload))
    findings.extend(_check_empty_mitre(payload, asset=asset))
    findings.extend(_check_null_recommended_actions(payload, asset=asset))
    findings.extend(_check_fileprofile_output_filter(payload, asset=asset))
    findings.extend(_check_unprojected_entity_columns(payload, asset=asset))
    return findings


__all__ = ["lint_payload"]
