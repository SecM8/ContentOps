# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Mandatory rule metadata for v2 detection envelopes (M1)."""

from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, Field, field_validator

# Tactics use Literal rather than Enum: YAML files store the raw string and a
# Literal gives Pydantic a clean discriminator without needing custom coercion
# from str -> enum on every parse.
Tactic = Literal[
    "Reconnaissance",
    "ResourceDevelopment",
    "InitialAccess",
    "Execution",
    "Persistence",
    "PrivilegeEscalation",
    "DefenseEvasion",
    "CredentialAccess",
    "Discovery",
    "LateralMovement",
    "Collection",
    "CommandAndControl",
    "Exfiltration",
    "Impact",
]

Severity = Literal["informational", "low", "medium", "high"]

_TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
# D3FEND technique id format: D3-XXX (capital letters / digits after the
# hyphen). Examples: D3-NTA (Network Traffic Analysis),
# D3-PSA (Process Spawn Analysis), D3-FCA (File Creation Analysis).
# Matches the canonical labels used at https://d3fend.mitre.org/.
_D3FEND_RE = re.compile(r"^D3-[A-Z0-9]+$")


class RuleMetadata(BaseModel):
    owner: str = Field(min_length=1)
    runbookUrl: str = Field(min_length=1)
    severity: Severity
    tactics: list[Tactic] = Field(min_length=1)
    techniques: list[str] = Field(default_factory=list)
    expectedAlertsPerDay: int = Field(ge=0)
    fpHandling: str = Field(min_length=1)
    cohort: str | None = None
    lastValidatedAt: str | None = None
    # Set by `contentops collect` — preserves the original ARM resource
    # name when the envelope id is a slugified displayName so apply
    # and prune can still address the right remote resource.
    arm_name: str | None = None

    # ----------------------------------------------------------------
    # Section T — authoring/triage metadata for Fortune 500 readiness.
    # All optional; lint rules META002-META007 surface gaps. Pattern
    # modelled on FalconForce's FalconFriday detection markdown shape
    # (see docs/reference/envelope-schema.md).
    # ----------------------------------------------------------------

    # What this rule detects (envelope-level, single paragraph). Distinct
    # from `payload.description` which is server-managed for Fusion /
    # MLBA / ThreatIntelligence kinds and not always operator-controlled.
    description: str | None = None

    # What attackers actually do — the threat context. The "why this
    # matters" surface that SOC analysts read first when triaging.
    attackDescription: str | None = None

    # Citation URLs: CVE / MITRE ATT&CK / vendor advisory / threat-intel
    # blog post. Each entry validated as http(s)://. Empty list is the
    # default; META004 lint warns when nothing's listed.
    references: list[str] = Field(default_factory=list)

    # Enumerated false-positive scenarios. Complements the existing
    # free-text fpHandling — analysts gradually migrate prose into
    # discrete cases the triage workflow can pattern-match against.
    falsePositives: list[str] = Field(default_factory=list)

    # Known evasion vectors / detection gaps. Honest documentation;
    # what NOT to rely on this rule for. Empty list is honest if
    # there genuinely aren't known blind spots; META006 stays info.
    blindSpots: list[str] = Field(default_factory=list)

    # Concise inline response steps. Complements runbookUrl for the
    # impatient case (3-7 bullets). Full playbooks live behind the URL.
    responseActions: list[str] = Field(default_factory=list)

    # Structured complement to free-text fpHandling: the author's
    # expectation of how often this rule fires false positives. Low /
    # medium / high. Used by META009 to surface the mismatch case
    # (severity=high paired with fpExpectedPerWeek=high suggests the
    # rule needs tuning before it spends analyst attention budget).
    # Optional; no migration burden on existing envelopes.
    fpExpectedPerWeek: Literal["low", "medium", "high"] | None = None

    # MITRE D3FEND defensive techniques this detection implements
    # (e.g. ["D3-NTA", "D3-PSA"]). Pairs with `techniques` (which names
    # the *attacker* behaviour) so the coverage report can answer
    # "which defensive surfaces do we have content for?" from the
    # defender axis, not just the attacker axis. Optional; empty list
    # is the default. Validated against the canonical D3-XXX format;
    # the bundled list at contentops/coverage/data/d3fend_techniques.json
    # carries names + descriptions for ~30 high-value techniques.
    defensiveTechniques: list[str] = Field(default_factory=list)

    model_config = {"frozen": True, "extra": "forbid"}

    @field_validator("owner")
    @classmethod
    def _owner_email_ish(cls, v: str) -> str:
        if not _EMAIL_RE.match(v):
            raise ValueError(f"owner must look like an email address, got {v!r}")
        return v

    @field_validator("runbookUrl")
    @classmethod
    def _runbook_http(cls, v: str) -> str:
        if not (v.startswith("http://") or v.startswith("https://")):
            raise ValueError(f"runbookUrl must start with http:// or https://, got {v!r}")
        return v

    @field_validator("techniques")
    @classmethod
    def _techniques_format(cls, v: list[str]) -> list[str]:
        for t in v:
            if not _TECHNIQUE_RE.match(t):
                raise ValueError(
                    f"technique {t!r} must match T#### or T####.### (e.g. T1059 or T1059.001)"
                )
        return v

    @field_validator("fpHandling")
    @classmethod
    def _fp_nonempty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("fpHandling must be non-empty guidance")
        return v

    @field_validator("references")
    @classmethod
    def _references_are_urls(cls, v: list[str]) -> list[str]:
        """Each entry must be http(s):// so the link is clickable in
        review tools (GitHub, IDE, runbook viewers) and so a typo'd
        scheme surfaces at parse time. Mirrors `_runbook_http`."""
        for ref in v:
            if not (ref.startswith("http://") or ref.startswith("https://")):
                raise ValueError(
                    f"references entry must start with http:// or https://, "
                    f"got {ref!r}"
                )
        return v

    @field_validator("defensiveTechniques")
    @classmethod
    def _d3fend_format(cls, v: list[str]) -> list[str]:
        """Each entry must match D3-XXX (canonical D3FEND id)."""
        for tech in v:
            if not _D3FEND_RE.match(tech):
                raise ValueError(
                    f"defensiveTechniques entry {tech!r} must match D3-XXX "
                    "(e.g. D3-NTA, D3-PSA, D3-FCA)"
                )
        return v
