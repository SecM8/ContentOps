# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Lint runner — walks discovered assets and dispatches KQL bodies to rules."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from contentops.core.asset import KQL_FIELDS_BY_ASSET, Asset
from contentops.core.discovery import iter_loaded_assets
from contentops.core.handler import LoadedAsset
from contentops.core.metadata import RuleMetadata
from contentops.lint.kql import LintFinding, lint_kql
from contentops.lint.metadata_rules import lint_metadata
from contentops.lint.payload import lint_payload
from contentops.lint.snippets import (
    lint_kql_placeholders,
    lint_overrides_directory,
)


def _is_placeholder(value: str) -> bool:
    """Return True if a string is a scaffold-style TODO placeholder.

    Single source of truth: delegates to
    ``metadata_rules._is_template_placeholder`` so the runner and the
    per-field META008 check agree on what counts as a placeholder.
    Without this, the runner's permissive ``s.startswith("todo")``
    treated legitimate prose like ``"todo: implement alerting"`` as
    empty, then escalated strict mode unnecessarily.
    """
    from contentops.lint.metadata_rules import _is_template_placeholder
    return _is_template_placeholder(value)


def _has_partial_authoring(metadata: RuleMetadata | None) -> bool:
    """Return True iff the envelope carries SOME but not all T.3 fields.

    The graduated ``scaffoldStrict`` policy (Phase 2.2b) says: once the
    operator has started authoring T.3 fields (description /
    attackDescription / references / falsePositives), the lint runner
    escalates META002-005 severity to error so the four fields are
    filled together. Collected envelopes carrying no T.3 content stay
    lenient until the tenant flips ``scaffoldStrict`` globally — this
    is the back-pressure that keeps the G24 backlog drainable without
    every PR going red.

    Scaffold TODO placeholders (``TODO (METAxxx): ...``) are treated
    as empty so a freshly-scaffolded envelope doesn't immediately
    fail lint — the operator gets the same gentle warnings as a
    collected envelope until they start replacing placeholders with
    real content.

    Returns False for:
      * metadata is None (collected envelope, no authoring at all);
      * all four T.3 fields empty / placeholder (lenient: still
        waiting for the operator to start authoring);
      * all four T.3 fields populated (envelope is fully authored;
        no findings to escalate).

    Returns True only in the partial-authoring middle ground: at
    least one T.3 field has real content AND at least one is missing
    or still a placeholder.
    """
    if metadata is None:
        return False

    def _str_filled(s: str | None) -> bool:
        return bool(s and s.strip() and not _is_placeholder(s))

    populated = sum(
        1 for present in (
            _str_filled(metadata.description),
            _str_filled(metadata.attackDescription),
            bool(metadata.references),
            bool(metadata.falsePositives),
        ) if present
    )
    return 0 < populated < 4


# Backwards-compatible alias so any external importer of the old name
# keeps working. The single source of truth lives in
# ``contentops.core.asset.KQL_FIELDS_BY_ASSET`` (consolidated as part of
# the cross-phase review follow-ups).
_KQL_FIELD_BY_ASSET = KQL_FIELDS_BY_ASSET


@dataclass
class LintedFile:
    path: Path
    # ``None`` for snippet-file findings (KQLOVERRIDE004) under
    # ``overrides/`` -- those files don't have an Asset kind. Verified
    # no consumer dispatches on ``asset``; only ``findings`` is read.
    asset: Asset | None
    findings: list[LintFinding] = field(default_factory=list)


def _extract_query(payload: dict[str, Any], dotted: str) -> str | None:
    cur: Any = payload
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur if isinstance(cur, str) else None


def _query_for(loaded: LoadedAsset) -> str | None:
    fields = _KQL_FIELD_BY_ASSET.get(loaded.envelope.asset)
    if not fields:
        return None
    for f in fields:
        q = _extract_query(loaded.payload, f)
        if q is not None:
            return q
    return None


def lint_assets(
    detections_path: Path,
    *,
    asset_filter: Asset | None = None,
    strict_policy: bool = False,
) -> list[LintedFile]:
    """Lint every asset under ``detections_path``.

    ``strict_policy`` is the resolved tenant.policy.scaffoldStrict
    value. When True, META002-005 are emitted at error severity
    (CI-blocking); when False they stay as warnings. The default of
    False here exists so call sites that don't load tenant.yml (e.g.
    unit tests, the snippets-only path) stay lenient — the lint CLI
    flips it via ``cfg.is_scaffold_strict()``.
    """
    results: list[LintedFile] = []
    for loaded in iter_loaded_assets(detections_path):
        if asset_filter is not None and loaded.envelope.asset != asset_filter:
            continue

        kind = loaded.envelope.asset.value
        findings: list[LintFinding] = []

        findings.extend(lint_payload(
            loaded.payload, asset=loaded.envelope.asset,
        ))

        # META001-007 — envelope-metadata rules. META002-005 escalate
        # to error severity when strict_policy is on; META001/006/007
        # stay at their inherent severity regardless. See
        # contentops/lint/metadata_rules.py for the per-rule logic.
        #
        # Phase 2.2b — graduated scaffoldStrict: when the envelope is in
        # the partial-authoring middle ground (at least one T.3 field
        # populated, at least one missing), escalate to strict even when
        # the tenant policy is lenient. Forces partially-authored rules
        # to finish; leaves collected envelopes alone.
        effective_strict = strict_policy or _has_partial_authoring(loaded.envelope.metadata)
        findings.extend(lint_metadata(loaded, strict_policy=effective_strict))

        query = _query_for(loaded)
        if query is not None:
            findings.extend(lint_kql(query, kind=kind))
            findings.extend(lint_kql_placeholders(query))
            # L-2: KQL101 (``| take`` / ``| limit`` forbidden) used to
            # only fire under ``--strict``, so a status:production rule
            # with ``| take 100`` shipped through ``contentops lint``
            # clean. Run the strict rules unconditionally on production
            # envelopes (error severity) and as warnings on non-prod
            # envelopes so the same rule surfaces at PR time. Strict
            # mode still triggers the full strict pipeline including
            # the Kusto.Language wrapper.
            from contentops.lint.strict_rules import run_python_rules
            for finding in run_python_rules(query):
                if loaded.envelope.status != "production":
                    finding = LintFinding(
                        rule_id=finding.rule_id,
                        severity="warning",
                        message=finding.message,
                        line=finding.line,
                    )
                findings.append(finding)

        # Emit a LintedFile for files that produced findings or for
        # KQL-bearing assets (so the "0 findings" line still reports
        # them as inspected).
        if findings or _query_for(loaded) is not None:
            results.append(LintedFile(
                path=loaded.path, asset=loaded.envelope.asset, findings=findings,
            ))

    # KQLOVERRIDE004 - validate snippet files in overrides/. Snippet
    # files have no Asset kind, so ``LintedFile.asset`` is ``None``
    # for these entries (verified no consumer dispatches on .asset).
    overrides_root = detections_path.parent / "overrides"
    if overrides_root.exists():
        for path, finding in lint_overrides_directory(overrides_root):
            results.append(LintedFile(
                path=path, asset=None,
                findings=[finding],
            ))

    return results


__all__ = ["LintedFile", "lint_assets"]
