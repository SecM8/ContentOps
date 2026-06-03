# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Envelope-metadata lint rules.

These rules look at ``loaded.envelope.metadata`` — the validation /
ownership / compliance fields — rather than at the KQL query body
(``contentops.lint.kql``) or the ARM payload shape
(``contentops.lint.payload``). They surface staleness in the
authoring-quality fields the promotion gates rely on.

Findings are emitted as ``LintFinding`` objects compatible with the
KQL runner so the existing severity / reporting machinery works
without changes.

Currently implemented:

* **META001** — ``metadata.lastValidatedAt`` is missing,
  unparseable, or older than the configured threshold (default 180
  days / 6 months, escalated to 90 days for ``status: production``).
  Closes gap-assessment G19 — the field was declared but never
  enforced at lint time; promotion already enforced it via
  ``contentops.lifecycle.gate_recent_validation``, but operators
  only saw the failure at promote-time instead of at PR-review time.

* **META002 / META003 / META004 / META005** — Section T authoring
  fields (``owner``, ``severity``, ``tactics``, ``fpHandling``).
  Emitted at ``warning`` by default (lenient migration mode);
  escalated to ``error`` when ``policy.scaffoldStrict=true`` in
  ``config/tenant.yml`` so CI blocks. See ``_STRICT_ESCALATABLE``.

* **META006 / META007** — ``blindSpots`` and ``responseActions``.
  Always emitted at ``info`` severity. Best-effort content that
  shouldn't gate CI even in strict mode.

The strict-policy escalation flag is wired from ``tenant.yml`` in
``contentops/cli/commands/lint.py`` via ``policy.scaffoldStrict``.
"""

from __future__ import annotations

from datetime import date
from typing import Iterable

from contentops.core.handler import LoadedAsset
from contentops.lifecycle import _parse_iso_date
from contentops.lint.kql import LintFinding


# Six months. Balances rigour vs analyst toil — a rule that hasn't
# been re-eyeballed in over half a year deserves a fresh look. Match
# the ``--max-validation-age-days`` default on the lifecycle promote
# gate so the two signals stay aligned.
DEFAULT_MAX_AGE_DAYS = 180

# Stricter freshness bar for ``status: production`` — production rules
# fire alerts; an unreviewed three-month-old rule has a higher
# operational cost than an experimental rule of the same age. Under
# strict mode, staleness past this threshold escalates META001 to
# error (CI-blocking) for production envelopes only; non-production
# envelopes use the looser DEFAULT_MAX_AGE_DAYS.
PRODUCTION_MAX_AGE_DAYS = 90


# Rules whose severity is escalated to "error" when the tenant has
# ``policy.scaffoldStrict=true``. Lenient is the default (a missing
# policy block or unset scaffoldStrict resolves to False); strict is
# operator opt-in once the authoring backlog has drained. The strict
# mode turns the Section T "authoring metadata" rules into a CI gate;
# lenient mode leaves them as warnings. META006-META007 are NOT in
# this set — they stay info severity in both modes because "blind
# spots / response actions" is genuinely best-effort content and
# shouldn't gate CI even on strict.
_STRICT_ESCALATABLE: frozenset[str] = frozenset({
    "META002", "META003", "META004", "META005",
})


def lint_metadata(
    loaded: LoadedAsset,
    *,
    max_age_days: int = DEFAULT_MAX_AGE_DAYS,
    production_max_age_days: int = PRODUCTION_MAX_AGE_DAYS,
    today: date | None = None,
    strict_policy: bool = False,
) -> Iterable[LintFinding]:
    """Yield ``LintFinding``s for envelope-metadata issues.

    Implements META001 (lastValidatedAt freshness) and META002-META007
    (Section T authoring fields). When ``strict_policy=True``,
    META002-META005 are emitted at ``error`` severity so CI blocks;
    when False (the lenient default), they're emitted at ``warning``
    severity (backlog meter, non-blocking).

    META001 (lastValidatedAt staleness) uses a per-status threshold:
    ``production_max_age_days`` (default 90) for ``status:
    production`` envelopes, ``max_age_days`` (default 180) for any
    other status. Under ``strict_policy=True`` a stale field escalates
    from warning to error so the gate fires at PR time, not at
    promote time. Closes G19.

    Severity for META002-005 is driven solely by ``strict_policy``.
    An earlier revision escalated META002-005 unconditionally for
    ``status: production`` envelopes; that override was removed so the
    tenant can drain a content-enrichment backlog without every PR
    going red. See ``CHANGELOG.md`` for the rationale and
    ``docs/reference/gap-assessment.md`` for the tracked backlog
    (production rules without authoring metadata).
    """
    today = today or date.today()
    metadata = loaded.envelope.metadata
    effective_strict = strict_policy
    # META001 freshness threshold is status-dependent. Production
    # rules carry alert-volume and triage cost; experimental / test
    # rules do not.
    effective_max_age = (
        production_max_age_days if loaded.envelope.status == "production"
        else max_age_days
    )

    # `metadata is None` on collected envelopes that only carry
    # `arm_name` (see contentops.core.envelope.parse_envelope). Treat
    # that the same as "lastValidatedAt is not set" PLUS every other
    # Section T field also being absent — yield one finding per
    # missing field so operators see the full picture.
    if metadata is None:
        # META001 — lastValidatedAt
        yield LintFinding(
            rule_id="META001",
            severity="warning",
            message=(
                "metadata.lastValidatedAt is not set (envelope has no "
                "authoring metadata block yet); set it once the rule "
                "is reviewed so promotion gates and compliance auditors "
                "can see the rule was eyeballed."
            ),
        )
        # META002-005 (escalatable) and META006-007 (info) — emit each
        # as "not set" because there's no metadata block to read from.
        yield from _missing_field_findings(
            present_metadata=False, strict_policy=effective_strict,
        )
        return

    raw = metadata.lastValidatedAt
    if not raw:
        yield LintFinding(
            rule_id="META001",
            severity="warning",
            message=(
                "metadata.lastValidatedAt is not set; set it (ISO 8601 "
                "date) after each validation round so promotion gates "
                "and compliance auditors can see the rule was reviewed."
            ),
        )
    else:
        parsed = _parse_iso_date(raw)
        if parsed is None:
            yield LintFinding(
                rule_id="META001",
                severity="error",
                message=(
                    f"metadata.lastValidatedAt={raw!r} is not ISO 8601 "
                    "(expected YYYY-MM-DD or a full ISO timestamp)."
                ),
            )
        else:
            age_days = (today - parsed).days
            if age_days > effective_max_age:
                # Under strict mode, staleness escalates to error so
                # CI blocks at PR time; lenient mode keeps it as a
                # warning (backlog meter).
                stale_severity = "error" if strict_policy else "warning"
                yield LintFinding(
                    rule_id="META001",
                    severity=stale_severity,
                    message=(
                        f"metadata.lastValidatedAt={parsed.isoformat()} is "
                        f"{age_days}d old (threshold {effective_max_age}d for "
                        f"status={loaded.envelope.status!r}). "
                        "Re-validate the rule and bump the field."
                    ),
                )

    # META002 — description
    if not (metadata.description and metadata.description.strip()):
        yield LintFinding(
            rule_id="META002",
            severity=_strict("META002", effective_strict),
            message=(
                "metadata.description is not set; add a single-paragraph "
                "summary of what this rule detects. Distinct from "
                "payload.description which is server-managed for "
                "Fusion / MLBA / ThreatIntelligence kinds."
            ),
        )

    # META003 — attackDescription
    if not (metadata.attackDescription and metadata.attackDescription.strip()):
        yield LintFinding(
            rule_id="META003",
            severity=_strict("META003", effective_strict),
            message=(
                "metadata.attackDescription is not set; describe what "
                "attackers actually do (the threat context). This is the "
                "first thing SOC analysts read on triage."
            ),
        )

    # META004 — references
    if not metadata.references:
        yield LintFinding(
            rule_id="META004",
            severity=_strict("META004", effective_strict),
            message=(
                "metadata.references is empty; cite at least one source "
                "(CVE, MITRE ATT&CK technique page, vendor advisory, "
                "threat-intel blog). Empty references makes the rule "
                "look ungrounded under audit."
            ),
        )

    # META005 — falsePositives
    if not metadata.falsePositives:
        yield LintFinding(
            rule_id="META005",
            severity=_strict("META005", effective_strict),
            message=(
                "metadata.falsePositives is empty; enumerate at least "
                "one known FP scenario so the triage workflow has a "
                "head start. Free-text fpHandling still applies as a "
                "fallback; this is the structured complement."
            ),
        )

    # META006 — blindSpots (always info; never escalated)
    if not metadata.blindSpots:
        yield LintFinding(
            rule_id="META006",
            severity="info",
            message=(
                "metadata.blindSpots is empty; consider documenting "
                "known evasion vectors or detection gaps for honesty. "
                "Empty is acceptable when there genuinely aren't known "
                "blind spots."
            ),
        )

    # META007 — responseActions (always info; runbookUrl carries it)
    if not metadata.responseActions:
        yield LintFinding(
            rule_id="META007",
            severity="info",
            message=(
                "metadata.responseActions is empty; consider adding "
                "3-7 concise inline steps for the impatient case. "
                "runbookUrl can still carry the full playbook."
            ),
        )

    # META009 — severity / fp-rate mismatch. A "high" severity rule
    # paired with a self-declared "high" weekly FP rate is the
    # classic noise-generator: it spends analyst attention budget on
    # alerts the author already knows are likely wrong. Info-only
    # (we're not blocking anything), but the lint message points
    # operators at the rule before it gets promoted into a triage
    # backlog.
    if (
        metadata.severity == "high"
        and metadata.fpExpectedPerWeek == "high"
    ):
        yield LintFinding(
            rule_id="META009",
            severity="info",
            message=(
                "severity='high' paired with fpExpectedPerWeek='high' — "
                "the rule will burn analyst attention budget on alerts "
                "the author already expects to be FPs. Either tune the "
                "query (preferred) or lower severity to 'medium' so "
                "the noise doesn't crowd out higher-fidelity signals."
            ),
        )

    # META008 — template-TODO placeholders surviving past experimental.
    # ``contentops new`` writes ``TODO (METAxxx): ...`` lines so the
    # operator sees the prompt inline; fine while the rule is being
    # authored (``status: experimental``). Once the rule is promoted
    # to ``test`` or further (production / deprecated), a TODO in a
    # T.3 field means an author forgot to fill it in. The existing
    # graduated _has_partial_authoring check treats placeholders as
    # empty (lenient warning); META008 catches the specific "still a
    # template stub but status moved past experimental" case so
    # production rules never ship with the literal "TODO (METAxxx)"
    # prompt visible to analysts.
    if loaded.envelope.status != "experimental":
        for field_name, value in (
            ("description", metadata.description),
            ("attackDescription", metadata.attackDescription),
        ):
            if isinstance(value, str) and _is_template_placeholder(value):
                yield LintFinding(
                    rule_id="META008",
                    severity="error",
                    message=(
                        f"metadata.{field_name} is still the scaffold "
                        f"placeholder ({value.strip()[:60]!r}) but "
                        f"status={loaded.envelope.status!r} is past "
                        "'experimental'. Fill in the real content "
                        "before promoting, or move status back to "
                        "'experimental' while you author."
                    ),
                )


def _is_template_placeholder(value: str) -> bool:
    """Return True if ``value`` looks like a ``contentops new`` scaffold prompt.

    Templates emit ``TODO (METAxxx): ...`` lines as inline prompts;
    real authored content does not start with ``todo`` (or its
    variants like ``todo:`` / ``todo (``). Kept narrow so an analyst
    writing a sentence containing the word ``todo`` mid-text doesn't
    trip the check — the prefix match avoids that.
    """
    if not value:
        return False
    s = value.strip().lower()
    return s.startswith("todo") and (
        s.startswith("todo (") or s.startswith("todo:") or s == "todo"
        or s.startswith("todo ")
    )


def _strict(rule_id: str, strict_policy: bool) -> str:
    """Resolve the effective severity for an escalatable rule."""
    if strict_policy and rule_id in _STRICT_ESCALATABLE:
        return "error"
    return "warning"


def _missing_field_findings(
    *, present_metadata: bool, strict_policy: bool,
) -> Iterable[LintFinding]:
    """Yield META002-META007 findings when the envelope has no
    metadata block at all. Same messaging as the per-field branches
    but consolidated into a single generator so the no-metadata
    case stays maintainable. ``strict_policy`` here is the already-
    resolved effective severity (caller passes its ``effective_strict``).
    """
    suffix = " (envelope has no authoring metadata block)" if not present_metadata else ""
    yield LintFinding(
        rule_id="META002",
        severity=_strict("META002", strict_policy),
        message=f"metadata.description is not set{suffix}.",
    )
    yield LintFinding(
        rule_id="META003",
        severity=_strict("META003", strict_policy),
        message=f"metadata.attackDescription is not set{suffix}.",
    )
    yield LintFinding(
        rule_id="META004",
        severity=_strict("META004", strict_policy),
        message=f"metadata.references is empty{suffix}.",
    )
    yield LintFinding(
        rule_id="META005",
        severity=_strict("META005", strict_policy),
        message=f"metadata.falsePositives is empty{suffix}.",
    )
    yield LintFinding(
        rule_id="META006",
        severity="info",
        message=f"metadata.blindSpots is empty{suffix}.",
    )
    yield LintFinding(
        rule_id="META007",
        severity="info",
        message=f"metadata.responseActions is empty{suffix}.",
    )
