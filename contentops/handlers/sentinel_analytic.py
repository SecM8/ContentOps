# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Sentinel analytic rule handler (Scheduled + NRT + MSI + templated).

Performs ETag-protected PUTs against the ARM ``alertRules`` collection
via :class:`contentops.providers.sentinel_arm.SentinelArmProvider`: GET
first to capture the remote etag, PUT with ``If-Match``, then GET
again and compare a stable content hash to detect tampering or
partial writes. A 412 Precondition Failed is surfaced as a per-asset
failure ("rerun contentops plan and resolve drift"), never a stack
trace.
"""

from __future__ import annotations

import logging
from typing import Callable

import click

from contentops.core.asset import Asset, COLLECT_BASELINE_VERSION
from contentops.core.handler import LoadedAsset
from contentops.core.result import ActionResult, PlanAction
from contentops.handlers._verify import (
    ETAG_CONFLICT_MESSAGE,
    compute_content_hash,
    extract_etag,
    hash_mismatch_error,
)
from contentops.models import validate_sentinel_payload
from contentops.providers.sentinel_arm import SentinelArmProvider
from contentops.utils.yaml_io import to_sentinel_body

logger = logging.getLogger(__name__)

# Fields that materially define each alert ``kind``. Server-set fields
# like ``lastModifiedUtc`` are intentionally excluded — they would always
# force a "drift". Each list is the projection used for both pre-PUT and
# post-PUT hash compare.
_SCHEDULED_HASHED_FIELDS = [
    "properties.displayName",
    "properties.query",
    "properties.severity",
    "properties.tactics",
    "properties.queryFrequency",
    "properties.queryPeriod",
    "properties.triggerOperator",
    "properties.triggerThreshold",
    "properties.enabled",
]
_NRT_HASHED_FIELDS = [
    "properties.displayName",
    "properties.query",
    "properties.severity",
    "properties.tactics",
    "properties.enabled",
]
_MSI_HASHED_FIELDS = [
    "properties.displayName",
    "properties.productFilter",
    "properties.severitiesFilter",
    "properties.displayNamesFilter",
    "properties.displayNamesExcludeFilter",
    "properties.enabled",
]
# Fusion / MLBA / ThreatIntelligence: enable-only, identified by template.
_TEMPLATED_HASHED_FIELDS = [
    "properties.alertRuleTemplateName",
    "properties.enabled",
]

# Per-kind PUT body allowlists for the rule kinds where ARM rejects most
# of the body as "Read-only" because the content is server-managed by the
# template. Discovered empirically during the 2026-05-15 prod -> SIT
# mirror — ARM peels back read-only fields one at a time (first
# displayName, then description, etc.), so the safe shape is to keep
# only fields the operator can actually change.
#
# Fusion is the broadest customisation surface: sourceSettings and
# scenarioExclusionPatterns are the per-tenant tuning knobs.
_FUSION_BODY_ALLOWLIST = (
    "alertRuleTemplateName",
    "enabled",
    "sourceSettings",
    "scenarioExclusionPatterns",
)
# MLBehaviorAnalytics has no operator-tunable fields beyond enable/disable.
_MLBA_BODY_ALLOWLIST = (
    "alertRuleTemplateName",
    "enabled",
)
# ThreatIntelligence is NOT in this list: ARM *requires* displayName for
# TI rules ("Required property 'displayName' not found"), so the apply
# path leaves TI bodies as collected. Same goes for Scheduled / NRT /
# MicrosoftSecurityIncidentCreation bound to a template — they only
# need displayName stripped (template owns it), and the existing
# alertRuleTemplateName-driven branch handles that.


# Server-managed fields stripped before round-trip diff so the
# diagnostic shows the same canonical view ``apply`` would hash. The
# existing ``_HASHED_FIELDS`` projection already excludes these by
# omission; the constants exist for the new
# ``sentinel-roundtrip-diff`` CLI command and for future
# defence-in-depth in the apply-verify path. Mirrors Defender's
# ``_SERVER_FIELDS`` / ``_SERVER_NESTED_FIELDS`` shape.
_SERVER_FIELDS = ("etag", "type", "systemData")
_SERVER_PROPERTY_FIELDS: dict[str, frozenset[str]] = {
    # ``provisioningState`` mirrors the watchlist strip set. It's a
    # standard ARM lifecycle field that the preview API surfaces on
    # several Sentinel resources; future-proof the strip so a future
    # ARM update doesn't show a spurious [DIFF] for it.
    "properties": frozenset({"lastModifiedUtc", "provisioningState"}),
}


def _strip_server_fields(remote: dict) -> dict:
    """Return ``remote`` with top-level + nested server-managed fields removed.

    Pure (defensive copy); never mutates the input. Used by the
    ``sentinel-roundtrip-diff`` diagnostic so its ``[OK]`` rows mean
    the apply verify would also report ``verified=True``.
    """
    cleaned = {k: v for k, v in remote.items() if k not in _SERVER_FIELDS}
    for parent, nested in _SERVER_PROPERTY_FIELDS.items():
        block = cleaned.get(parent)
        if isinstance(block, dict):
            cleaned[parent] = {k: v for k, v in block.items() if k not in nested}
    return cleaned


def _hashed_fields_for_kind(kind: str) -> list[str]:
    if kind == "Scheduled":
        return _SCHEDULED_HASHED_FIELDS
    if kind == "NRT":
        return _NRT_HASHED_FIELDS
    if kind == "MicrosoftSecurityIncidentCreation":
        return _MSI_HASHED_FIELDS
    if kind in ("Fusion", "MLBehaviorAnalytics", "ThreatIntelligence"):
        return _TEMPLATED_HASHED_FIELDS
    # Default to the strictest (Scheduled) projection — a future kind we
    # haven't taught the handler about will hash deterministically as long
    # as the same projection runs both pre- and post-PUT, even if some of
    # those fields read as None.
    return _SCHEDULED_HASHED_FIELDS


class SentinelAnalyticHandler:
    asset = Asset.SENTINEL_ANALYTIC

    # Single canonical name for the ARM sub-resource collection this
    # handler manages — keeps the per-call resource string from sprawling.
    _RESOURCE = "alertRules"

    def __init__(
        self,
        provider_factory: Callable[[], SentinelArmProvider | None],
    ) -> None:
        """`provider_factory` returns a SentinelArmProvider or None for dry-run.

        The factory is invoked lazily on the first apply / list / delete
        call so importing the handler doesn't trigger an auth / network
        side-effect.
        """
        self._provider_factory = provider_factory
        self._provider: SentinelArmProvider | None = None

    def _provider_or_create(self) -> SentinelArmProvider | None:
        if self._provider is None:
            self._provider = self._provider_factory()
        return self._provider

    def validate(self, loaded: LoadedAsset) -> None:
        validate_sentinel_payload(loaded.payload)
        # ARM rejects PUT with HTTP 400 if `templateVersion` is set
        # without `alertRuleTemplateName`. Catch it at plan time so
        # `contentops plan` shows a clear error rather than waiting for
        # the apply to fail with a noisy ARM response. Mirrors the
        # PAYLOAD001 lint rule.
        payload = loaded.payload or {}
        if payload.get("templateVersion") and not payload.get("alertRuleTemplateName"):
            raise ValueError(
                f"sentinel_analytic {loaded.envelope.id!r} payload has "
                "templateVersion set but no alertRuleTemplateName — ARM "
                "would reject the PUT. Either add alertRuleTemplateName "
                "from the source Marketplace template, or remove "
                "templateVersion. (See lint rule PAYLOAD001.)"
            )

    def plan(self, loaded: LoadedAsset) -> ActionResult:
        if loaded.envelope.status == "experimental":
            return ActionResult(
                asset_id=loaded.envelope.id,
                asset_kind=self.asset.value,
                action=PlanAction.SKIP,
                status="planned",
                detail="experimental status — skipped by deploy",
            )
        action = PlanAction.DISABLE if loaded.envelope.status == "deprecated" else PlanAction.UPDATE
        return ActionResult(
            asset_id=loaded.envelope.id,
            asset_kind=self.asset.value,
            action=action,
            status="planned",
        )

    def apply(self, loaded: LoadedAsset, *, dry_run: bool = False) -> ActionResult:
        if loaded.envelope.status == "experimental":
            return ActionResult(
                asset_id=loaded.envelope.id,
                asset_kind=self.asset.value,
                action=PlanAction.SKIP,
                status="skipped",
                detail="experimental",
            )

        if dry_run:
            click.echo(f"  [DRY-RUN] Would PUT sentinel rule: {loaded.envelope.id}")
            return ActionResult(
                asset_id=loaded.envelope.id,
                asset_kind=self.asset.value,
                action=PlanAction.UPDATE,
                status="dry-run",
            )

        provider = self._provider_or_create()
        if provider is None:
            # ``_provider_or_create`` only returns None if the factory
            # itself returns None — which the legacy v1 dry-run path
            # used to do. Live apply must have a real provider; raise
            # rather than asserting so `python -O` (which strips asserts)
            # still catches the misconfiguration loudly.
            raise RuntimeError(
                f"sentinel_analytic {loaded.envelope.id!r}: "
                "SentinelArmProvider factory returned None during a "
                "non-dry-run apply. Check auth / tenant config — this is "
                "a misconfiguration, not a per-rule error."
            )

        body = to_sentinel_body(loaded.payload)
        # Defence-in-depth scrub: if templateVersion is set but
        # alertRuleTemplateName is empty/missing, ARM returns HTTP 400
        # "Invalid Properties for alert rule: 'templateVersion' can only
        # be used if 'alertRuleTemplateName' is not empty.". Plan-time
        # validate() already catches this (and the PAYLOAD001 lint rule
        # blocks it at PR time), but if either gate is bypassed (legacy
        # apply path, retry-failed without re-validation) we drop the
        # field here so the PUT succeeds.
        properties = body.get("properties") or {}
        if properties.get("templateVersion") and not properties.get("alertRuleTemplateName"):
            logger.warning(
                "sentinel_analytic %s: stripping templateVersion before PUT — "
                "alertRuleTemplateName is empty (would have caused ARM 400). "
                "Update the YAML to add the template name OR remove "
                "templateVersion.",
                loaded.envelope.id,
            )
            properties.pop("templateVersion", None)
            body["properties"] = properties

        # Per-kind body sanitisation. ARM treats different rule kinds
        # differently — see ``_FUSION_BODY_ALLOWLIST`` etc. above for the
        # empirically-derived contract. The hash projection for templated
        # kinds (``_TEMPLATED_HASHED_FIELDS``) already omits the
        # server-managed fields, so post-apply verify stays correct.
        #
        # History: O.1 v1 (PR #160) stripped only ``displayName`` for any
        # templated kind. The 2026-05-15 prod -> SIT mirror peeled back
        # more issues: Fusion also rejects ``description`` (and likely
        # other fields), while ThreatIntelligence *requires* displayName
        # — so v1's strip regressed TI. This v2 (PR #163) replaces the
        # one-field strip with per-kind allowlists.
        kind_marker = body.get("kind") or "Scheduled"
        if kind_marker == "Fusion":
            properties = {
                k: v for k, v in properties.items()
                if k in _FUSION_BODY_ALLOWLIST
            }
            body["properties"] = properties
        elif kind_marker == "MLBehaviorAnalytics":
            properties = {
                k: v for k, v in properties.items()
                if k in _MLBA_BODY_ALLOWLIST
            }
            body["properties"] = properties
        elif kind_marker == "ThreatIntelligence":
            # ARM REQUIRES displayName for TI rules. Leave the body intact.
            pass
        elif properties.get("alertRuleTemplateName") and "displayName" in properties:
            # Template-bound Scheduled / NRT / MSI — template owns
            # displayName, but the rest of the body stays.
            properties.pop("displayName", None)
            body["properties"] = properties

        if loaded.envelope.status == "deprecated":
            body["properties"]["enabled"] = False

        # Resolve the ARM resource name to PUT against. Collected
        # envelopes carry the original GUID under ``metadata.arm_name``
        # because the envelope id is now the slugified displayName.
        # Legacy envelopes that pre-date metadata.arm_name fall back
        # to using the envelope id directly (matches v1 deploy).
        remote_id = loaded.envelope.arm_name or loaded.envelope.id

        # GET first to grab the etag; absent on first-create which is fine.
        # ``extract_etag`` is the shared helper that handles both
        # top-level and properties-nested placements; see _verify.py.
        existing = provider.get_resource(self._RESOURCE, remote_id)
        etag: str | None = extract_etag(existing)

        kind = body.get("kind") or "Scheduled"
        hashed_fields = _hashed_fields_for_kind(kind)
        sent_hash = compute_content_hash(body, hashed_fields)
        response = provider.put_resource(self._RESOURCE, remote_id, body, etag=etag)

        if response.status_code == 412:
            click.echo(
                f"  etag-conflict: {loaded.envelope.id}", err=True,
            )
            return ActionResult(
                asset_id=loaded.envelope.id,
                asset_kind=self.asset.value,
                action=PlanAction.UPDATE,
                status="error-412",
                detail=ETAG_CONFLICT_MESSAGE,
                verified=False,
                error=ETAG_CONFLICT_MESSAGE,
            )

        if response.status_code not in (200, 201):
            logger.error(
                "Failed to deploy sentinel rule %s: %s %s",
                loaded.envelope.id, response.status_code, response.text,
            )
            return ActionResult(
                asset_id=loaded.envelope.id,
                asset_kind=self.asset.value,
                action=PlanAction.UPDATE,
                status=f"error-{response.status_code}",
                detail=response.text[:200],
                verified=False,
                error=response.text[:200],
            )

        action = PlanAction.UPDATE
        if response.status_code == 201:
            action = PlanAction.CREATE
        if loaded.envelope.status == "deprecated":
            action = PlanAction.DISABLE
        click.echo(f"  {action.value}: {loaded.envelope.id}")

        # Verify by reading back and comparing the stable content hash.
        remote = provider.get_resource(self._RESOURCE, remote_id)
        if remote is None:
            err = "post-apply GET returned 404"
            return ActionResult(
                asset_id=loaded.envelope.id,
                asset_kind=self.asset.value,
                action=action,
                status="success",
                detail=err,
                verified=False,
                error=err,
            )
        got_hash = compute_content_hash(remote, hashed_fields)
        if got_hash != sent_hash:
            err = hash_mismatch_error(sent_hash, got_hash)
            return ActionResult(
                asset_id=loaded.envelope.id,
                asset_kind=self.asset.value,
                action=action,
                status="success",
                detail=err,
                verified=False,
                error=err,
            )

        return ActionResult(
            asset_id=loaded.envelope.id,
            asset_kind=self.asset.value,
            action=action,
            status="success",
            verified=True,
        )

    def close(self) -> None:
        if self._provider is not None:
            self._provider.close()
            self._provider = None

    def delete(self, remote_id: str) -> ActionResult:
        """Destructive — DELETE one alertRule by ARM resource name.

        Returns an ActionResult; status is ``success`` for 200/204 or
        ``error-<code>`` otherwise. 404 is treated as success (resource
        already gone — idempotent prune).
        """
        from contentops.core.result import NotSupportedError
        from contentops.handlers._delete import (
            delete_result_from_exception, delete_result_from_response,
        )
        provider = self._provider_or_create()
        if provider is None:
            raise NotSupportedError(
                "sentinel_analytic delete requires a SentinelArmProvider — "
                "called in dry-run / no-credential context"
            )
        try:
            response = provider.delete_resource(self._RESOURCE, remote_id)
        except Exception as exc:  # pragma: no cover — defensive
            return delete_result_from_exception(remote_id, self.asset, exc)
        return delete_result_from_response(remote_id, self.asset, response)

    # --- Drift support -------------------------------------------------
    # Implements the DriftCapable protocol so `contentops drift` can
    # round-trip remote alert rules into git-managed YAML.

    def list_remote(self) -> list[dict]:
        provider = self._provider_or_create()
        if provider is None:
            return []
        return provider.list_resource(self._RESOURCE)

    def to_envelope(self, remote: dict) -> dict | None:
        """Convert an ARM alertRule into a v2 envelope dict.

        Round-trips every alert ``kind`` we manage. For Microsoft-shipped
        kinds (Fusion / MLBehaviorAnalytics / ThreatIntelligence) the
        ``alertRuleTemplateName`` is the *required* identifier and is
        preserved; for Scheduled / NRT it's a server-side audit field
        and is dropped so the payload compares cleanly.
        """
        from contentops.utils.slug import displayname_slug

        rule_id = remote.get("name")
        if not rule_id:
            return None
        properties: dict = dict(remote.get("properties") or {})
        kind = remote.get("kind") or properties.get("kind") or "Scheduled"

        # Snapshot the template info BEFORE the per-kind strip below
        # might drop it. The envelope's ``version`` field reflects the
        # Sentinel template version regardless of whether the payload
        # itself ends up carrying ``alertRuleTemplateName`` (Fusion / MLBA
        # / TI keep it; Scheduled / NRT / MSI strip it for clean diffs,
        # but the *rule* is still template-derived).
        _template_name_original = properties.get("alertRuleTemplateName")
        _template_version_original = properties.get("templateVersion")

        # Server-set, non-deterministic fields that always drift if kept.
        for k in ("lastModifiedUtc",):
            properties.pop(k, None)

        # Scheduled / NRT customers usually don't pin templateVersion in YAML,
        # so dropping these prevents spurious "changed" reports. For Fusion,
        # MLBA, and ThreatIntelligence the template name *is* the identifier
        # and must stay.
        if kind in ("Scheduled", "NRT", "MicrosoftSecurityIncidentCreation"):
            for k in ("alertRuleTemplateName", "templateVersion"):
                properties.pop(k, None)

        properties["kind"] = kind
        enabled = properties.get("enabled", True)
        status = "production" if enabled else "deprecated"

        display_name = properties.get("displayName") or ""
        envelope_id = displayname_slug(display_name, fallback_id=rule_id)
        if not envelope_id:
            return None

        # For template-bound rules (Fusion / MLBA / TI / template-bound
        # Scheduled etc.) the envelope's ``version`` field surfaces the
        # real Sentinel-side template version when ARM provides it — a
        # genuine upstream version, not a synthetic baseline. When ARM
        # omits it (e.g. auto-versioned Fusion), and for non-templated
        # hand-authored rules, we fall back to the shared collect
        # baseline. Discovered 2026-05-15 from a collected envelope of
        # `advanced-multistage-attack-detection` — the envelope had a
        # synthetic version even though the rule is a Microsoft-shipped
        # Fusion template.
        #
        # We read from the pre-strip snapshot so this works even for
        # Scheduled / NRT / MSI rules where the strip above drops the
        # template identity from the payload itself.
        if _template_name_original:
            envelope_version = _template_version_original or COLLECT_BASELINE_VERSION
        else:
            envelope_version = COLLECT_BASELINE_VERSION

        return {
            "id": envelope_id,
            "version": envelope_version,
            "asset": Asset.SENTINEL_ANALYTIC.value,
            "status": status,
            # Collected envelopes carry the minimum metadata block
            # ({arm_name: ...}) required to round-trip through
            # parse_envelope. Authoring-quality fields (owner,
            # severity, tactics, fpHandling) are enforced by
            # ``contentops lint --strict``, not here.
            "metadata": {"arm_name": rule_id},
            "payload": properties,
        }
