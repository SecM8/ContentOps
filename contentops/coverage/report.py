# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Compute and render MITRE ATT&CK coverage from detection envelopes.

Both the per-tactic heatmap (:func:`compute_coverage`) and the three-level
summary behind every published percentage (:func:`coverage_summary`) are
computed from one corpus walk (:func:`contentops.coverage.corpus.load_corpus`)
with one scope, so the heatmap, gaps report, badge, Navigator layer and
inventory report always describe the same set of detections.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path

from contentops.core.asset import DETECTION_ASSETS
from contentops.coverage.corpus import (
    EXCLUDED_DISABLED,
    EXCLUDED_HUNTING,
    EXCLUDED_NON_PRODUCTION,
    Corpus,
    CorpusDiagnostics,
    CoverageScope,
    load_corpus,
)
from contentops.coverage.extract import ExtractedCoverage
from contentops.coverage.matrix import ALL_TACTICS, load_matrix

logger = logging.getLogger(__name__)

SEVERITIES: tuple[str, ...] = ("informational", "low", "medium", "high")


@dataclass
class TacticCoverage:
    tactic: str
    detection_count: int = 0
    techniques: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    # In-scope detections for this tactic whose envelope is status:
    # production. Equal to detection_count under the default (production)
    # scope; differs only with --include-non-production. The discriminator
    # is envelope.status, NOT the [DEV] displayName prefix (an intentional
    # tuning marker on real production rules).
    production_detection_count: int = 0


@dataclass
class CoverageReport:
    tactics: list[TacticCoverage]
    total_detections: int
    total_with_mitre_data: int
    # Well-formed technique ids that are not in the current ATT&CK matrix
    # (unknown or deprecated) -- they map to no tactic.
    techniques_without_tactic: tuple[str, ...] = ()
    # In-scope detections with status: production.
    total_production_detections: int = 0
    scope_label: str = ""
    production_only: bool = True
    # Detections left out of the numbers, by reason
    # (disabled / hunting / non_production).
    excluded: dict[str, int] = field(default_factory=dict)
    # Everything the in-scope detections cover, independent of tactic
    # buckets: parent ids (sub-techniques roll up) + sub-technique ids. The
    # gaps report matches against this, so a technique on a tactic-less rule
    # is covered there too (it is in the badge).
    covered_techniques: frozenset[str] | None = None
    diagnostics: CorpusDiagnostics = field(default_factory=CorpusDiagnostics)
    attack_version: str = ""


def _empty_tactics() -> dict[str, TacticCoverage]:
    return {
        t: TacticCoverage(
            tactic=t,
            detection_count=0,
            techniques={},
            by_severity={s: 0 for s in SEVERITIES},
            production_detection_count=0,
        )
        for t in ALL_TACTICS
    }


def compute_coverage(
    root: Path,
    *,
    scope: CoverageScope | None = None,
    corpus: Corpus | None = None,
) -> CoverageReport:
    """Bucket the in-scope detections under *root* by tactic.

    A detection counts under each tactic it claims (Defender: its alert
    category; rules that claim none get tactics from their techniques).
    Under a tactic, only the techniques the ATT&CK matrix files under that
    tactic are listed -- a rule tagged Execution + CredentialAccess with
    T1059 + T1110 lists T1059 under Execution and T1110 under
    CredentialAccess, never the other way round.
    """
    corpus = corpus or load_corpus(root, scope=scope)
    buckets = _empty_tactics()
    in_scope = corpus.in_scope()
    total_with_mitre_data = 0
    for entry in in_scope:
        mitre = entry.mitre
        if mitre.tactics or mitre.techniques:
            total_with_mitre_data += 1
        for tactic in mitre.tactics:
            bucket = buckets.get(tactic)
            if bucket is None:
                continue
            bucket.detection_count += 1
            if entry.is_production:
                bucket.production_detection_count += 1
            bucket.by_severity[mitre.severity] = bucket.by_severity.get(mitre.severity, 0) + 1
            for tech in mitre.techniques_for(tactic):
                bucket.techniques[tech] = bucket.techniques.get(tech, 0) + 1

    diagnostics = corpus.diagnostics()
    return CoverageReport(
        tactics=[buckets[t] for t in ALL_TACTICS],
        total_detections=len(in_scope),
        total_with_mitre_data=total_with_mitre_data,
        techniques_without_tactic=tuple(
            sorted(set(diagnostics.unknown_ids) | set(diagnostics.deprecated_ids))
        ),
        total_production_detections=sum(1 for e in in_scope if e.is_production),
        scope_label=corpus.scope.label,
        production_only=corpus.scope.production_only,
        excluded=corpus.excluded_counts(),
        covered_techniques=corpus.covered().ids,
        diagnostics=diagnostics,
        attack_version=corpus.matrix.attack_version,
    )


def _heat_emoji(n: int) -> str:
    if n == 0:
        return "🟥"
    if n <= 2:
        return "🟧"
    if n <= 5:
        return "🟨"
    return "🟩"


def _severity_mix(by_sev: dict[str, int]) -> str:
    return (
        f"{by_sev.get('high', 0)}/"
        f"{by_sev.get('medium', 0)}/"
        f"{by_sev.get('low', 0)}/"
        f"{by_sev.get('informational', 0)}"
    )


def _top_techniques(techniques: dict[str, int], limit: int = 3) -> str:
    if not techniques:
        return "—"
    items = sorted(techniques.items(), key=lambda kv: (-kv[1], kv[0]))
    return ", ".join(f"{t}×{c}" for t, c in items[:limit])


def _md_literal(value: str, limit: int = 40) -> str:
    """Render untrusted text (a malformed technique value from YAML) as an
    inert Markdown code span: no backticks, pipes or line breaks survive."""
    cleaned = "".join(ch if ch.isprintable() else " " for ch in value)
    cleaned = cleaned.replace("`", "'").replace("|", "/").strip()
    if len(cleaned) > limit:
        cleaned = cleaned[: limit - 1] + "…"
    return f"`{cleaned}`"


def _excluded_phrase(excluded: dict[str, int]) -> str:
    parts = []
    labels = (
        (EXCLUDED_DISABLED, "disabled/deprecated"),
        (EXCLUDED_HUNTING, "hunting"),
        (EXCLUDED_NON_PRODUCTION, "non-production"),
    )
    for key, label in labels:
        if excluded.get(key):
            parts.append(f"{excluded[key]} {label}")
    return ", ".join(parts)


def render_diagnostics_markdown(diag: CorpusDiagnostics) -> list[str]:
    """Bullet lines describing ATT&CK data-quality findings (shared by the
    heatmap and the gaps report)."""
    lines: list[str] = []
    if diag.remapped_ids:
        pairs = ", ".join(f"{old}→{new}" for old, new in diag.remapped_ids)
        lines.append(
            f"- **Revoked ids remapped** ({len(diag.remapped_ids)}): {pairs}. "
            "MITRE replaced these techniques; update the rules' tags."
        )
    if diag.deprecated_ids:
        lines.append(
            f"- **Deprecated ids, not counted** ({len(diag.deprecated_ids)}): "
            f"{', '.join(diag.deprecated_ids)}."
        )
    if diag.unknown_ids:
        lines.append(
            f"- **Unknown ids, not counted** ({len(diag.unknown_ids)}): "
            f"{', '.join(diag.unknown_ids)} — not in the bundled ATT&CK matrix "
            "(typo, or run `python scripts/refresh_attack_matrix.py`)."
        )
    if diag.invalid_ids:
        shown = ", ".join(
            f"{_md_literal(value)} on `{rule}`" for rule, value in diag.invalid_ids[:10]
        )
        more = "" if len(diag.invalid_ids) <= 10 else f" (+{len(diag.invalid_ids) - 10} more)"
        lines.append(
            f"- **Malformed technique values ignored** ({len(diag.invalid_ids)}): "
            f"{shown}{more}. Expected `T####` or `T####.###`."
        )
    if diag.outside_tactics:
        lines.append(
            f"- **Outside the rule's tactics** ({len(diag.outside_tactics)}): "
            f"{', '.join(diag.outside_tactics)} — counted for technique "
            "coverage, but listed under no tactic because none of the rule's "
            "tactics is one ATT&CK files them under."
        )
    if diag.metadata_errors:
        shown = ", ".join(f"`{rule}`" for rule, _ in diag.metadata_errors[:10])
        more = "" if len(diag.metadata_errors) <= 10 else f" (+{len(diag.metadata_errors) - 10} more)"
        lines.append(
            f"- **Metadata failed strict validation** ({len(diag.metadata_errors)}): "
            f"{shown}{more} — ATT&CK tags were read from the raw block; run "
            "`contentops lint --strict` for the details."
        )
    return lines


def rule_attack_notes(cov: ExtractedCoverage, *, attack_version: str = "") -> list[str]:
    """One rule's ATT&CK data-quality notes as inert Markdown -- the
    per-rule counterpart of :func:`render_diagnostics_markdown`, shown by
    ``explain`` and the detection docs. Ids are normalised by the
    extractor; a malformed value goes through :func:`_md_literal`."""
    release = f"ATT&CK v{attack_version}" if attack_version else "the bundled ATT&CK matrix"
    notes = [
        f"`{old}` was revoked by MITRE; counted as `{new}`. Update the tag."
        for old, new in cov.remapped_ids
    ]
    notes += [f"`{tid}` is deprecated in {release}; not counted." for tid in cov.deprecated_ids]
    notes += [f"`{tid}` is not in {release}; not counted." for tid in cov.unknown_ids]
    notes += [
        f"{_md_literal(value)} is not a technique id (expected `T####` or "
        "`T####.###`); ignored."
        for value in cov.invalid_ids
    ]
    if cov.tactics_inferred:
        notes.append("No tactic tagged; tactics are the techniques' ATT&CK tactics.")
    return notes


def render_markdown(report: CoverageReport) -> str:
    show_production = not report.production_only
    lines: list[str] = []
    lines.append("# MITRE ATT&CK Coverage")
    lines.append("")
    if report.scope_label:
        excluded = _excluded_phrase(report.excluded)
        version = f" · ATT&CK v{report.attack_version}" if report.attack_version else ""
        lines.append(
            f"_Scope: {report.scope_label}{version}"
            + (f" · excluded: {excluded}" if excluded else "")
            + "._"
        )
        lines.append("")
    if show_production:
        lines.append(
            "|  | Tactic | # Detections | # Production | Severity Mix (H/M/L/I) "
            "| Top Techniques |"
        )
        lines.append("|---|---|---:|---:|---|---|")
    else:
        lines.append("|  | Tactic | # Detections | Severity Mix (H/M/L/I) | Top Techniques |")
        lines.append("|---|---|---:|---|---|")
    for tc in report.tactics:
        cells = [_heat_emoji(tc.detection_count), tc.tactic, str(tc.detection_count)]
        if show_production:
            # Flag tactics "covered" only by non-production rules.
            prod = tc.production_detection_count
            cells.append(f"⚠️ {prod}" if (tc.detection_count > 0 and prod == 0) else str(prod))
        cells += [_severity_mix(tc.by_severity), _top_techniques(tc.techniques)]
        lines.append("| " + " | ".join(cells) + " |")
    lines.append("")
    if show_production:
        lines.append(
            f"**Totals:** {report.total_detections} detection(s) in scope — "
            f"{report.total_production_detections} production, "
            f"{report.total_with_mitre_data} with MITRE data."
        )
        lines.append("")
        lines.append(
            "_The **# Production** column counts only `status: production` "
            "detections (the [DEV]-prefix tuning marker still counts as "
            "production). A ⚠️ marks a tactic with detections but none in "
            "production — coverage there is experimental/draft, not yet "
            "production-grade._"
        )
    else:
        lines.append(
            f"**Totals:** {report.total_detections} detection(s) in scope, "
            f"{report.total_with_mitre_data} with MITRE data."
        )
    diag_lines = render_diagnostics_markdown(report.diagnostics)
    if diag_lines:
        lines.append("")
        lines.append("**ATT&CK data quality:**")
        lines.append("")
        lines.extend(diag_lines)
    lines.append("")
    return "\n".join(lines)


@dataclass(frozen=True)
class CoverageLevel:
    """Per-level coverage stats (used for tactics / techniques / sub-techniques)."""
    covered: int
    total: int

    @property
    def pct(self) -> int:
        if self.total <= 0:
            return 0
        return round(100 * self.covered / self.total)


@dataclass(frozen=True)
class CoverageSummary:
    """Three-level MITRE coverage summary against the full ATT&CK
    Enterprise matrix.

    * ``tactics`` — coverage at the 14-tactic level (which kill-chain
      stages have ANY detection).
    * ``techniques`` — parent-technique coverage (~222 in MITRE
      Enterprise). Sub-technique hits roll UP to the parent.
    * ``sub_techniques`` — sub-technique coverage (~475 in MITRE
      Enterprise). Parent-only hits do NOT roll DOWN (you can't claim
      coverage for every sub-technique just because the parent is
      covered).

    The README badge uses ``techniques.pct`` — the number every SOC
    lead reads as "% of MITRE technique coverage". Backwards-compat
    aliases (``covered`` / ``total`` / ``pct`` / ``matrix_label``)
    forward to the technique level so existing consumers (portfolio
    footer, generated catalog) keep working. ``scope_label`` says which
    detections were counted; ``detections_in_scope`` how many.
    """
    tactics: CoverageLevel
    techniques: CoverageLevel
    sub_techniques: CoverageLevel
    matrix_label: str = "MITRE ATT&CK Enterprise (full)"
    attack_version: str = ""
    scope_label: str = ""
    detections_in_scope: int = 0

    # Backwards-compat: pre-polish callers used .covered / .total / .pct
    # for the single (then-curated) technique number. Forward those to
    # the technique level so PR #253 portfolio footer + PR #255 report
    # badge + the catalog renderer keep working unchanged.
    @property
    def covered(self) -> int:
        return self.techniques.covered

    @property
    def total(self) -> int:
        return self.techniques.total

    @property
    def pct(self) -> int:
        return self.techniques.pct


def _full_matrix() -> dict[str, frozenset[str]]:
    """Return ``{'tactics': set, 'techniques': set, 'sub_techniques': set}``
    from the bundled full ATT&CK Enterprise matrix (one shared loader:
    :func:`contentops.coverage.matrix.load_matrix`)."""
    matrix = load_matrix()
    return {
        "tactics": matrix.tactics,
        "techniques": matrix.techniques,
        "sub_techniques": matrix.sub_techniques,
    }


def summary_from_corpus(corpus: Corpus) -> CoverageSummary:
    """Three-level summary of what ``corpus``'s in-scope detections cover."""
    covered = corpus.covered()
    matrix = corpus.matrix
    return CoverageSummary(
        tactics=CoverageLevel(covered=len(covered.tactics), total=len(matrix.tactics)),
        techniques=CoverageLevel(covered=len(covered.techniques), total=len(matrix.techniques)),
        sub_techniques=CoverageLevel(
            covered=len(covered.sub_techniques), total=len(matrix.sub_techniques),
        ),
        attack_version=matrix.attack_version,
        scope_label=corpus.scope.label,
        detections_in_scope=len(corpus.in_scope()),
    )


def coverage_summary(
    root: Path,
    *,
    scope: CoverageScope | None = None,
    corpus: Corpus | None = None,
    cohort: str | None = None,
) -> CoverageSummary:
    """Compute three-level MITRE coverage from repo envelopes.

    Deterministic; no external state. Counts the in-scope detections
    (default: enabled production rules, hunting excluded) under ``root``,
    optionally only those tagged ``cohort``, against the bundled full
    Enterprise matrix.

    Roll-up semantics:

    * A detection with ``T1059.001`` contributes to BOTH the parent
      ``T1059`` (technique level) AND ``T1059.001`` (sub-technique
      level) — sub-technique hits propagate UP, never DOWN.
    * A detection with only ``T1059`` contributes ONLY to the parent
      level. Parent-only coverage does NOT claim every sub-technique
      under that parent.
    """
    corpus = corpus or load_corpus(root, scope=scope)
    if cohort is not None:
        corpus = corpus.filter(lambda e: e.cohort == cohort)
    return summary_from_corpus(corpus)


def render_badge(summary: CoverageSummary) -> str:
    """Render a shields.io-endpoint JSON for the README badge.

    Message: ``"<technique_pct>% techniques · <sub_technique_pct>%
    sub-techniques"`` — the headline number is technique-level coverage
    (matches what every other ATT&CK coverage tool reports) and the
    second number shows the sub-technique depth.

    Colour bands track the technique level: 0-19% red, 20-39% orange,
    40-59% yellow, 60-79% yellowgreen, 80+% brightgreen. Anchored to
    the full ATT&CK Enterprise matrix (~222 parent techniques) so
    the % is the canonical industry number.
    """
    tech_pct = summary.techniques.pct
    sub_pct = summary.sub_techniques.pct
    if tech_pct < 20:
        color = "red"
    elif tech_pct < 40:
        color = "orange"
    elif tech_pct < 60:
        color = "yellow"
    elif tech_pct < 80:
        color = "yellowgreen"
    else:
        color = "brightgreen"
    payload = {
        "schemaVersion": 1,
        "label": "ATT&CK coverage",
        "message": f"{tech_pct}% techniques · {sub_pct}% sub-techniques",
        "color": color,
    }
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def render_json(report: CoverageReport) -> str:
    diag = report.diagnostics
    payload = {
        "tactics": [
            {
                "tactic": tc.tactic,
                "detection_count": tc.detection_count,
                "production_detection_count": tc.production_detection_count,
                "techniques": dict(sorted(tc.techniques.items())),
                "by_severity": {s: tc.by_severity.get(s, 0) for s in SEVERITIES},
            }
            for tc in report.tactics
        ],
        "total_detections": report.total_detections,
        "total_production_detections": report.total_production_detections,
        "total_with_mitre_data": report.total_with_mitre_data,
        "techniques_without_tactic": list(report.techniques_without_tactic),
        "scope": report.scope_label,
        "attack_version": report.attack_version,
        "excluded": dict(sorted(report.excluded.items())),
        "covered_techniques": sorted(report.covered_techniques or ()),
        "diagnostics": {
            "remapped_ids": [list(p) for p in diag.remapped_ids],
            "deprecated_ids": list(diag.deprecated_ids),
            "unknown_ids": list(diag.unknown_ids),
            "invalid_ids": [{"detection": r, "value": v} for r, v in diag.invalid_ids],
            "outside_tactics": list(diag.outside_tactics),
            "metadata_errors": [{"detection": r, "error": e} for r, e in diag.metadata_errors],
        },
    }
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


__all__ = [
    "ALL_TACTICS",
    "DETECTION_ASSETS",
    "SEVERITIES",
    "CoverageLevel",
    "CoverageReport",
    "CoverageSummary",
    "TacticCoverage",
    "compute_coverage",
    "coverage_summary",
    "render_badge",
    "render_diagnostics_markdown",
    "render_json",
    "render_markdown",
    "rule_attack_notes",
    "summary_from_corpus",
]
