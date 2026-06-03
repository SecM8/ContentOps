# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Compute and render MITRE ATT&CK coverage from detection envelopes."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

import yaml

from contentops.core.asset import Asset
from contentops.core.discovery import is_skipped_path
from contentops.core.envelope import parse_envelope
from contentops.coverage.extract import extract_mitre

logger = logging.getLogger(__name__)


ALL_TACTICS: tuple[str, ...] = (
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
    # ARM Microsoft.SecurityInsights/alertRules tactic enum members
    # outside the 14-tactic ATT&CK Enterprise list. Kept in render
    # order at the bottom so the established Enterprise heatmap shape
    # stays stable; populated only when a Sentinel rule carries them.
    "PreAttack",
    "ImpairProcessControl",
    "InhibitResponseFunction",
)

SEVERITIES: tuple[str, ...] = ("informational", "low", "medium", "high")

DETECTION_ASSETS: frozenset[Asset] = frozenset({
    Asset.SENTINEL_ANALYTIC,
    Asset.SENTINEL_HUNTING,
    Asset.DEFENDER_CUSTOM_DETECTION,
})


@dataclass
class TacticCoverage:
    tactic: str
    detection_count: int = 0
    techniques: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    # Status-aware: detections referencing this tactic whose envelope is
    # status: production. Lets a lead distinguish production-grade coverage
    # from a tactic "covered" only by experimental/draft rules. The
    # discriminator is envelope.status, NOT the [DEV] displayName prefix
    # (which is an intentional tuning marker on real production rules).
    production_detection_count: int = 0


@dataclass
class CoverageReport:
    tactics: list[TacticCoverage]
    total_detections: int
    total_with_mitre_data: int
    techniques_without_tactic: tuple[str, ...] = ()
    # Distinct detections with status: production (counted once each,
    # regardless of how many tactics they map to).
    total_production_detections: int = 0


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


def compute_coverage(root: Path) -> CoverageReport:
    """Walk every detection-class asset under *root* and bucket by tactic.

    MITRE attribution is read via :func:`contentops.coverage.extract.extract_mitre`,
    which combines ``envelope.metadata`` (when authored) with the
    asset-native payload location (where the platform itself stores
    tactics / techniques / severity). Detections that have data in
    either place contribute to per-tactic counts; those with neither
    are still counted in ``total_detections`` but contribute zero to
    any per-tactic bucket.
    """
    buckets = _empty_tactics()
    total_detections = 0
    total_with_mitre_data = 0
    total_production_detections = 0
    orphans_seen: set[str] = set()

    if not root.is_dir():
        return CoverageReport(
            tactics=[buckets[t] for t in ALL_TACTICS],
            total_detections=0,
            total_with_mitre_data=0,
        )

    for path in sorted(root.rglob("*.yml")):
        if is_skipped_path(path):
            continue
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
            envelope, payload = parse_envelope(raw)
        except Exception as exc:
            logger.warning("coverage: skipping %s: %s", path, exc)
            continue

        if envelope.asset not in DETECTION_ASSETS:
            continue

        total_detections += 1
        # Read status from the raw doc so a loose-parsed envelope (one that
        # fell back from strict validation) still classifies correctly.
        is_production = (
            str((raw or {}).get("status") or "").strip().lower() == "production"
        )
        if is_production:
            total_production_detections += 1

        coverage = extract_mitre(envelope, payload)
        if coverage.tactics or coverage.techniques:
            total_with_mitre_data += 1
        orphans_seen.update(coverage.techniques_without_tactic)

        for tactic in coverage.tactics:
            if tactic not in buckets:
                continue
            bucket = buckets[tactic]
            bucket.detection_count += 1
            if is_production:
                bucket.production_detection_count += 1
            bucket.by_severity[coverage.severity] = (
                bucket.by_severity.get(coverage.severity, 0) + 1
            )
            for tech in coverage.techniques:
                bucket.techniques[tech] = bucket.techniques.get(tech, 0) + 1

    return CoverageReport(
        tactics=[buckets[t] for t in ALL_TACTICS],
        total_detections=total_detections,
        total_with_mitre_data=total_with_mitre_data,
        techniques_without_tactic=tuple(sorted(orphans_seen)),
        total_production_detections=total_production_detections,
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


def render_markdown(report: CoverageReport) -> str:
    lines: list[str] = []
    lines.append("# MITRE ATT&CK Coverage")
    lines.append("")
    lines.append(
        "|  | Tactic | # Detections | # Production | Severity Mix (H/M/L/I) "
        "| Top Techniques |"
    )
    lines.append("|---|---|---:|---:|---|---|")
    for tc in report.tactics:
        # Flag tactics "covered" only by non-production rules: detections
        # exist but none are production-grade.
        prod = tc.production_detection_count
        prod_cell = (
            f"⚠️ {prod}" if (tc.detection_count > 0 and prod == 0) else str(prod)
        )
        lines.append(
            f"| {_heat_emoji(tc.detection_count)} | {tc.tactic} | "
            f"{tc.detection_count} | {prod_cell} | "
            f"{_severity_mix(tc.by_severity)} | "
            f"{_top_techniques(tc.techniques)} |"
        )
    lines.append("")
    lines.append(
        f"**Totals:** {report.total_detections} detection(s) — "
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
    if report.techniques_without_tactic:
        lines.append("")
        lines.append(
            f"**Note:** {len(report.techniques_without_tactic)} technique ID(s) "
            f"were referenced but have no tactic mapping in the bundled "
            f"ATT&CK matrix. Run `python scripts/refresh_attack_matrix.py` "
            f"to update. Orphans: "
            f"{', '.join(report.techniques_without_tactic)}."
        )
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
    footer, generated catalog) keep working.
    """
    tactics: CoverageLevel
    techniques: CoverageLevel
    sub_techniques: CoverageLevel
    matrix_label: str = "MITRE ATT&CK Enterprise (full)"

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


@lru_cache(maxsize=1)
def _full_matrix() -> dict[str, frozenset[str]]:
    """Return ``{'tactics': set, 'techniques': set, 'sub_techniques': set}``
    from the bundled full ATT&CK Enterprise matrix.

    Cached for the process lifetime — the file is ~80 KB and we read
    it once per invocation today.
    """
    data_path = Path(__file__).parent / "data" / "mitre_attack_full.json"
    raw = json.loads(data_path.read_text(encoding="utf-8"))
    return {
        "tactics": frozenset(
            t["id"] for t in raw.get("tactics", [])
            if isinstance(t.get("id"), str)
        ),
        "techniques": frozenset(
            t["id"] for t in raw.get("techniques", [])
            if isinstance(t.get("id"), str)
        ),
        "sub_techniques": frozenset(
            t["id"] for t in raw.get("sub_techniques", [])
            if isinstance(t.get("id"), str)
        ),
    }


def coverage_summary(root: Path) -> CoverageSummary:
    """Compute three-level MITRE coverage from repo envelopes.

    Deterministic; no external state. Walks every detection-class
    envelope under ``root``, pulls tactics + techniques (incl. sub-
    techniques), matches against the bundled full Enterprise matrix.

    Roll-up semantics:

    * A detection with ``T1059.001`` contributes to BOTH the parent
      ``T1059`` (technique level) AND ``T1059.001`` (sub-technique
      level) — sub-technique hits propagate UP, never DOWN.
    * A detection with only ``T1059`` contributes ONLY to the parent
      level. Parent-only coverage does NOT claim every sub-technique
      under that parent.
    """
    matrix = _full_matrix()
    covered_tactics: set[str] = set()
    covered_techniques: set[str] = set()
    covered_subs: set[str] = set()

    if root.is_dir():
        for path in sorted(root.rglob("*.yml")):
            if is_skipped_path(path):
                continue
            try:
                raw = yaml.safe_load(path.read_text(encoding="utf-8"))
                envelope, payload = parse_envelope(raw)
            except Exception as exc:
                logger.warning("coverage: skipping %s: %s", path, exc)
                continue
            if envelope.asset not in DETECTION_ASSETS:
                continue
            extracted = extract_mitre(envelope, payload)
            for tactic in extracted.tactics:
                if tactic in matrix["tactics"]:
                    covered_tactics.add(tactic)
            for tech in extracted.techniques:
                parent = tech.split(".", 1)[0]
                # Parent always counts at the technique level.
                if parent in matrix["techniques"]:
                    covered_techniques.add(parent)
                # Sub-technique additionally counts at the sub level.
                if "." in tech and tech in matrix["sub_techniques"]:
                    covered_subs.add(tech)

    return CoverageSummary(
        tactics=CoverageLevel(
            covered=len(covered_tactics), total=len(matrix["tactics"]),
        ),
        techniques=CoverageLevel(
            covered=len(covered_techniques), total=len(matrix["techniques"]),
        ),
        sub_techniques=CoverageLevel(
            covered=len(covered_subs), total=len(matrix["sub_techniques"]),
        ),
    )


def render_badge(summary: CoverageSummary) -> str:
    """Render a shields.io-endpoint JSON for the README badge.

    Message: ``"<technique_pct>% (<sub_technique_pct>% sub)"`` — the
    headline number is technique-level coverage (matches what every
    other ATT&CK coverage tool reports), the parenthetical shows the
    sub-technique drill-down so operators see the relative depth.

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
    }
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


__all__ = [
    "ALL_TACTICS",
    "SEVERITIES",
    "CoverageReport",
    "CoverageSummary",
    "TacticCoverage",
    "compute_coverage",
    "coverage_summary",
    "render_badge",
    "render_json",
    "render_markdown",
]
