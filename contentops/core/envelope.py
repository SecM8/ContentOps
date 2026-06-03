# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Canonical detection envelope.

Layout (the only shape ContentOps accepts):

    id: ...
    version: ...
    asset: sentinel_analytic | defender_custom_detection | sentinel_watchlist | ...
    status: ...
    metadata:               # optional at parse time; lint --strict enforces richness
      arm_name: ...         # collected envelopes carry this minimum
      owner: ...            # full authoring metadata is required by lint --strict
      severity: ...
      tactics: [ ... ]
      ...
    payload: { ... }

Parse permissive, lint strict: a missing or minimal metadata block parses
cleanly so collected envelopes round-trip without inventing author-time
fields. The strict authoring schema is enforced by ``contentops lint
--strict``, not at parse time.
"""

from __future__ import annotations

import logging
from typing import Any

from pydantic import BaseModel, Field, ValidationError

logger = logging.getLogger(__name__)

from contentops.core.asset import Asset
from contentops.core.lifecycle_stage import LifecycleStage
from contentops.core.metadata import RuleMetadata


# CLI telemetry: ids of envelopes that fell back to loose metadata parse
# during this process (the `else`-branch strict-parse failure in
# ``parse_envelope`` — typically a collected/grandfathered rule missing
# strict authoring fields like ``runbookUrl``). Each fallback still logs a
# per-rule WARNING (suppressed at the default CLI verbosity via
# ``_VERBOSE_ONLY_LOGGERS``; visible with ``-v``). The CLI resets this at
# the start of each invocation and prints ONE aggregated summary line on
# close, so a 150-rule operator repo gets a single "N detections need
# metadata" note instead of 150 stack-trace-shaped warnings.
_loose_parse_fallback_ids: set[str] = set()


def _record_loose_parse_fallback(rule_id: str | None) -> None:
    """Tally one loose-parse fallback (deduped by rule id)."""
    if rule_id:
        _loose_parse_fallback_ids.add(rule_id)


def loose_parse_fallback_ids() -> frozenset[str]:
    """Return the ids of envelopes that fell back to loose metadata parse."""
    return frozenset(_loose_parse_fallback_ids)


def reset_loose_parse_fallbacks() -> None:
    """Clear the loose-parse tally. The CLI calls this once per invocation."""
    _loose_parse_fallback_ids.clear()


class EnvelopeV2(BaseModel):
    id: str = Field(pattern=r"^[a-z0-9][a-z0-9\-]*[a-z0-9]$")
    version: str
    asset: Asset
    status: str
    metadata: RuleMetadata | None = None
    # Mirrors metadata.arm_name in-memory so apply / prune can resolve
    # the original ARM resource name without re-parsing metadata.
    arm_name: str | None = None

    # Authoring-workflow stage (concept / research / engineering /
    # delivery / optimization / feedback). Orthogonal to ``status``
    # (which drives runtime deploy behaviour). None on collected
    # envelopes and on envelopes that pre-date the field. Never gates
    # any apply / prune / drift logic — pure metadata for dashboards
    # and SOC team-lead planning. See contentops/core/lifecycle_stage.py.
    lifecycleStage: LifecycleStage | None = None

    model_config = {"frozen": True}


def parse_envelope(raw: dict[str, Any]) -> tuple[EnvelopeV2, dict[str, Any]]:
    """Parse a raw YAML dict into ``(envelope, payload)``.

    Detection envelopes may carry either:
      * a full :class:`RuleMetadata` block (authored content), or
      * a minimal ``{arm_name: ...}`` (collected content), or
      * no ``metadata:`` key at all.

    The strict-authoring requirements (owner / severity / tactics /
    fpHandling / runbookUrl / expectedAlertsPerDay) are enforced by
    ``contentops lint --strict``, not here. This keeps the parse path
    permissive enough that ``contentops collect`` can always round-trip
    its output back through ``parse_envelope`` without inventing
    placeholder author-time fields.
    """
    if "asset" not in raw:
        raise ValueError("Envelope must contain 'asset'")

    asset = Asset(raw["asset"])
    payload = raw.get("payload", {})

    metadata: RuleMetadata | None = None
    arm_name: str | None = None

    metadata_raw = raw.get("metadata")
    if isinstance(metadata_raw, dict) and metadata_raw:
        recognised_loose = {"arm_name"}
        full_keys = {
            "owner", "runbookUrl", "severity", "tactics", "techniques",
            "expectedAlertsPerDay", "fpHandling",
        }
        if full_keys.issubset(metadata_raw.keys()):
            metadata = RuleMetadata(**metadata_raw)
            arm_name = metadata.arm_name
        elif set(metadata_raw.keys()).issubset(recognised_loose):
            arm_name = metadata_raw.get("arm_name")
        else:
            # Either a partially-authored envelope or a collected one
            # carrying a couple of extra fields. Try strict construction
            # first; fall through to loose acceptance if it fails so a
            # missing optional field doesn't block parse. Narrow the
            # exception to validation/typing errors (so a programmer
            # bug doesn't silently fall through) and log the cause —
            # a typo in `tactics` or `severity` used to silently drop
            # the entire metadata block to arm_name only, hiding the
            # mistake from both lint and drift.
            try:
                metadata = RuleMetadata(**metadata_raw)
                arm_name = metadata.arm_name
            except (ValidationError, TypeError, ValueError) as exc:
                _record_loose_parse_fallback(raw.get("id"))
                logger.warning(
                    "envelope %s: metadata fell back to loose parse — %s",
                    raw.get("id"), exc,
                )
                arm_name = metadata_raw.get("arm_name")

    envelope = EnvelopeV2(
        id=raw["id"],
        version=raw["version"],
        asset=asset,
        status=raw["status"],
        metadata=metadata,
        arm_name=arm_name,
        # T.2 authoring lifecycle stage. Permissive: missing is None;
        # unknown values raise via the Literal validator and surface
        # the typo at parse time rather than silently dropping.
        lifecycleStage=raw.get("lifecycleStage"),
    )
    return envelope, payload
