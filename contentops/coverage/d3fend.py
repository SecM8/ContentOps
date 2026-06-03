# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""MITRE D3FEND coverage report — defensive-axis companion to ATT&CK.

`contentops coverage` (and its `--gaps` mode) answers
"which adversary techniques does our content cover?" The D3FEND
companion answers the orthogonal question: "which *defensive*
techniques does our content implement?" Two operators of the same
detection corpus see different things: the SOC manager cares about
ATT&CK coverage (offensive surface); the detection engineer cares
about D3FEND coverage (defensive surface).

The reference list of defensive techniques lives at
``contentops/coverage/data/d3fend_techniques.json`` (curated subset
— see file note). Operators can substitute their own via
``--d3fend-file`` to drive against an org-specific defensive model.

A D3FEND coverage entry is read from
``metadata.defensiveTechniques: list[str]`` on every envelope. A
"gap" is a (D3FEND tactic, technique_id) pair from the reference
list that no detection envelope references.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from contentops.core.discovery import iter_loaded_assets


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class D3fendTechniqueRef:
    """One reference-list defensive technique."""
    id: str
    name: str
    tactics: tuple[str, ...]


@dataclass
class D3fendTacticGaps:
    """Uncovered defensive techniques bucketed by D3FEND tactic."""
    tactic: str
    uncovered: list[D3fendTechniqueRef] = field(default_factory=list)
    covered: list[D3fendTechniqueRef] = field(default_factory=list)
    total: int = 0


@dataclass
class D3fendReport:
    tactics: list[D3fendTacticGaps]
    techniques_source: str
    total_techniques: int
    total_uncovered: int
    total_covered: int


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------


def _default_d3fend_path() -> Path:
    return Path(__file__).parent / "data" / "d3fend_techniques.json"


def load_d3fend_techniques(
    path: Path | None = None,
) -> tuple[list[D3fendTechniqueRef], str]:
    """Return ``(techniques, source_label)``.

    ``source_label`` is a short string for display in the report
    header. Defaults to the bundled curated subset; a custom
    ``--d3fend-file`` overrides.
    """
    target = path or _default_d3fend_path()
    raw = json.loads(target.read_text(encoding="utf-8"))
    techniques: list[D3fendTechniqueRef] = []
    for entry in raw.get("techniques", []):
        if not isinstance(entry, dict):
            continue
        tid = entry.get("id")
        name = entry.get("name", "")
        tactics = entry.get("tactics", []) or []
        if isinstance(tid, str) and tid:
            techniques.append(D3fendTechniqueRef(
                id=tid,
                name=str(name),
                tactics=tuple(t for t in tactics if isinstance(t, str)),
            ))
    label = (
        raw.get("source")
        or (str(target.relative_to(Path.cwd())) if target.is_absolute() else str(target))
    )
    return techniques, str(label)


# ---------------------------------------------------------------------------
# Extraction + gap computation
# ---------------------------------------------------------------------------


def covered_d3fend_ids(detections_root: Path) -> set[str]:
    """Return the set of D3FEND ids referenced by any envelope's metadata."""
    out: set[str] = set()
    for loaded in iter_loaded_assets(detections_root):
        meta = loaded.envelope.metadata
        if meta is None:
            continue
        for tech in meta.defensiveTechniques or []:
            if isinstance(tech, str) and tech:
                out.add(tech)
    return out


def compute_d3fend_report(
    detections_root: Path,
    techniques: Iterable[D3fendTechniqueRef],
    *,
    source_label: str,
) -> D3fendReport:
    """Build the D3FEND coverage / gap report."""
    covered = covered_d3fend_ids(detections_root)
    by_tactic: dict[str, D3fendTacticGaps] = {}
    total = 0
    total_covered = 0
    for tech in techniques:
        total += 1
        is_covered = tech.id in covered
        if is_covered:
            total_covered += 1
        # A technique may belong to multiple tactics (rare in D3FEND);
        # mirror the ATT&CK side by listing under each.
        for tactic in tech.tactics or ("(uncategorised)",):
            bucket = by_tactic.setdefault(
                tactic, D3fendTacticGaps(tactic=tactic),
            )
            bucket.total += 1
            if is_covered:
                bucket.covered.append(tech)
            else:
                bucket.uncovered.append(tech)
    ordered_tactics = sorted(by_tactic.values(), key=lambda t: t.tactic)
    return D3fendReport(
        tactics=ordered_tactics,
        techniques_source=source_label,
        total_techniques=total,
        total_uncovered=total - total_covered,
        total_covered=total_covered,
    )


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def render_markdown(report: D3fendReport) -> str:
    lines = [
        "# MITRE D3FEND coverage",
        "",
        f"_Source: {report.techniques_source}._",
        "",
        f"**Covered:** {report.total_covered} / {report.total_techniques} "
        f"defensive techniques.",
        "",
    ]
    for bucket in report.tactics:
        pct = (
            f"{100 * (bucket.total - len(bucket.uncovered)) / bucket.total:.0f}"
            if bucket.total else "0"
        )
        lines.append(f"## {bucket.tactic} ({pct}% covered)")
        lines.append("")
        if bucket.covered:
            lines.append("**Covered:**")
            for tech in bucket.covered:
                lines.append(f"- `{tech.id}` {tech.name}")
            lines.append("")
        if bucket.uncovered:
            lines.append("**Uncovered:**")
            for tech in bucket.uncovered:
                lines.append(f"- `{tech.id}` {tech.name}")
            lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def render_json(report: D3fendReport) -> str:
    payload = {
        "techniques_source": report.techniques_source,
        "total_techniques": report.total_techniques,
        "total_covered": report.total_covered,
        "total_uncovered": report.total_uncovered,
        "tactics": [
            {
                "tactic": t.tactic,
                "total": t.total,
                "covered": [
                    {"id": x.id, "name": x.name} for x in t.covered
                ],
                "uncovered": [
                    {"id": x.id, "name": x.name} for x in t.uncovered
                ],
            }
            for t in report.tactics
        ],
    }
    return json.dumps(payload, indent=2) + "\n"


__all__ = [
    "D3fendTechniqueRef",
    "D3fendTacticGaps",
    "D3fendReport",
    "load_d3fend_techniques",
    "covered_d3fend_ids",
    "compute_d3fend_report",
    "render_markdown",
    "render_json",
]
