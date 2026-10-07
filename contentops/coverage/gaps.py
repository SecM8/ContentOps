# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Compute MITRE ATT&CK technique gaps — what we DON'T cover.

Companion to ``contentops.coverage.report``: that module shows what's
covered (heatmap by tactic), this one shows what's missing.

By default the reference is the **full** MITRE ATT&CK Enterprise matrix
(``contentops/coverage/data/mitre_attack_full.json`` — parents + sub-
techniques, refreshed weekly from MITRE by
``.github/workflows/attack-matrix-refresh.yml``). ``--matrix-mode
curated`` selects the smaller hand-curated high-value list
(``mitre_attack_techniques.json``); ``--techniques-file`` substitutes an
org-specific list entirely.

A technique is covered when an in-scope detection references it (or,
for a parent, one of its sub-techniques) -- the same covered set the badge
counts (``CoverageReport.covered_techniques``), so a technique on a rule
without tactics is covered here too. The headline counts distinct
techniques and sub-techniques against the same denominators as the badge;
the per-tactic table lists a technique under every tactic it belongs to.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path

from contentops.coverage.corpus import CorpusDiagnostics
from contentops.coverage.matrix import AttackMatrix, load_matrix
from contentops.coverage.report import (
    ALL_TACTICS,
    CoverageReport,
    render_diagnostics_markdown,
)


@dataclass(frozen=True)
class TechniqueRef:
    """One reference-list technique."""
    id: str
    name: str
    tactics: tuple[str, ...]


@dataclass
class TacticGaps:
    """Uncovered techniques bucketed by tactic."""
    tactic: str
    uncovered: list[TechniqueRef] = field(default_factory=list)
    covered_count: int = 0
    total_in_tactic: int = 0


@dataclass
class GapsReport:
    tactics: list[TacticGaps]
    techniques_source: str
    # (tactic, technique) cells in the per-tactic table -- a technique that
    # belongs to three tactics is three cells. Not a technique count; the
    # headline uses the distinct counts below.
    total_techniques: int
    total_uncovered: int
    # Number of distinct techniques in the reference list (parents + subs).
    reference_count: int = 0
    # Distinct counts, split like the badge (parents vs sub-techniques).
    techniques_total: int = 0
    techniques_covered: int = 0
    sub_techniques_total: int = 0
    sub_techniques_covered: int = 0
    scope_label: str = ""
    diagnostics: CorpusDiagnostics = field(default_factory=CorpusDiagnostics)


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------


# Human-readable source labels (also the discriminators the renderer and
# CLI banner key on — keep them stable).
CURATED_LABEL = "bundled curated list"
FULL_LABEL = "full Enterprise ATT&CK matrix"


def _data_path(filename: str) -> Path:
    """Resolve a bundled coverage-data JSON via importlib.resources.

    In editable installs `contentops.coverage.data` is just a directory;
    resources.files works for both wheel and editable layouts."""
    return Path(str(resources.files("contentops.coverage.data") / filename))


def _techniques_from_raw(raw: dict) -> list[TechniqueRef]:
    """Flatten a reference doc's ``techniques`` + ``sub_techniques`` tables.

    The curated list and custom files carry only ``techniques``; the full
    matrix also carries ``sub_techniques`` (``raw.get`` defaults make the
    merge a no-op when the key is absent)."""
    out: list[TechniqueRef] = []
    for key in ("techniques", "sub_techniques"):
        for t in raw.get(key) or []:
            out.append(TechniqueRef(
                id=str(t["id"]),
                name=str(t.get("name", "")),
                tactics=tuple(t.get("tactics") or ()),
            ))
    return out


def _dedupe(refs: list[TechniqueRef]) -> list[TechniqueRef]:
    seen: set[str] = set()
    out: list[TechniqueRef] = []
    for ref in refs:
        if ref.id not in seen:
            seen.add(ref.id)
            out.append(ref)
    return out


def _resolve_reference(
    refs: list[TechniqueRef], matrix: AttackMatrix, *, matrix_tactics: bool,
) -> list[TechniqueRef]:
    """Point reference ids at the current matrix.

    Revoked ids become their replacement, so a detection tagged with the
    old id (remapped the same way by the extractor) still closes the gap.
    With ``matrix_tactics`` (the bundled curated list) names and tactics
    also come from the matrix so the list cannot drift from it; custom
    lists keep the operator's own tactics.
    """
    out: list[TechniqueRef] = []
    for ref in refs:
        current, status = matrix.resolve(ref.id)
        if current is None:
            out.append(ref)
            continue
        if matrix_tactics:
            out.append(TechniqueRef(
                id=current, name=matrix.names.get(current, ref.name),
                tactics=matrix.tactics_for(current),
            ))
        elif status == "revoked":
            out.append(TechniqueRef(
                id=current, name=ref.name or matrix.names.get(current, ""),
                tactics=ref.tactics or matrix.tactics_for(current),
            ))
        else:
            out.append(ref)
    return _dedupe(out)


def load_techniques(
    path: Path | None = None, *, mode: str = "full",
) -> tuple[list[TechniqueRef], str]:
    """Load the technique reference list and a human-readable source label.

    Resolution order: an explicit ``path`` (custom) wins; otherwise
    ``mode`` selects the bundled ``full`` Enterprise matrix (default,
    parents + sub-techniques) or the ``curated`` high-value subset.
    Returns ``(techniques, source_label)``.
    """
    matrix = load_matrix()
    if path is not None:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        refs = _resolve_reference(_techniques_from_raw(raw), matrix, matrix_tactics=False)
        return refs, f"custom: {Path(path).name}"
    if mode == "curated":
        raw = json.loads(_data_path("mitre_attack_techniques.json").read_text(encoding="utf-8"))
        refs = _resolve_reference(_techniques_from_raw(raw), matrix, matrix_tactics=True)
        return refs, CURATED_LABEL
    # "full" (default): the shared matrix, parents then sub-techniques.
    refs = [
        TechniqueRef(id=tid, name=matrix.names.get(tid, ""), tactics=matrix.tactics_for(tid))
        for tid in sorted(matrix.techniques) + sorted(matrix.sub_techniques)
    ]
    return refs, FULL_LABEL


# ---------------------------------------------------------------------------
# Core computation
# ---------------------------------------------------------------------------


def _covered_technique_ids(report: CoverageReport) -> set[str]:
    """Every technique id the report's detections cover.

    Uses ``report.covered_techniques`` (the badge's covered set, built
    independently of tactic buckets) when present; a hand-built report
    without it falls back to the ids in the tactic buckets. A
    sub-technique (T1059.001) also covers its parent (T1059).
    """
    covered: set[str] = set(report.covered_techniques or ())
    if report.covered_techniques is None:
        for tc in report.tactics:
            covered.update(tc.techniques)
    for tech in list(covered):
        if "." in tech:
            covered.add(tech.split(".", 1)[0])
    return covered


def compute_gaps(
    report: CoverageReport, techniques: list[TechniqueRef],
    *, source: str = "",
) -> GapsReport:
    """Set-difference: which (tactic, technique) cells aren't in the report?

    A technique is considered covered if any of its ids (parent or
    sub-technique) appears in the report's referenced techniques.

    ``source`` is the human-readable origin label from
    ``load_techniques`` (e.g. "bundled curated list" / "custom: foo.json").
    Pass it here so the report is correct by construction — callers that
    forget no longer ship a blank ``_Source:_`` line.
    """
    covered = _covered_technique_ids(report)
    by_tactic: dict[str, TacticGaps] = {
        t: TacticGaps(tactic=t) for t in ALL_TACTICS
    }

    total_techniques = 0
    total_uncovered = 0
    for tech in techniques:
        for tactic in tech.tactics:
            if tactic not in by_tactic:
                # Reference list has a tactic the pipeline doesn't model.
                # Skip rather than silently 'gap' against an unknown tactic.
                continue
            bucket = by_tactic[tactic]
            bucket.total_in_tactic += 1
            total_techniques += 1
            if tech.id in covered:
                bucket.covered_count += 1
            else:
                bucket.uncovered.append(tech)
                total_uncovered += 1

    # Stable ordering for deterministic output.
    for bucket in by_tactic.values():
        bucket.uncovered.sort(key=lambda t: t.id)

    distinct = {t.id for t in techniques}
    parents = {t for t in distinct if "." not in t}
    subs = distinct - parents
    return GapsReport(
        tactics=[by_tactic[t] for t in ALL_TACTICS],
        techniques_source=source,
        total_techniques=total_techniques,
        total_uncovered=total_uncovered,
        reference_count=len(distinct),
        techniques_total=len(parents),
        techniques_covered=len(parents & covered),
        sub_techniques_total=len(subs),
        sub_techniques_covered=len(subs & covered),
        scope_label=report.scope_label,
        diagnostics=report.diagnostics,
    )


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def _format_uncovered(uncovered: list[TechniqueRef]) -> str:
    """Render a tactic's uncovered techniques, grouping sub-techniques
    under their parent so the full-matrix view stays readable.

    * uncovered parent with uncovered subs -> ``T1059 Name (+5 sub)``
    * uncovered parent, no subs             -> ``T1059 Name``
    * covered parent, uncovered subs        -> the subs listed explicitly
    """
    if not uncovered:
        return "—"
    by_parent: dict[str, dict] = {}
    for t in uncovered:
        parent = t.id.split(".", 1)[0]
        grp = by_parent.setdefault(parent, {"parent": None, "subs": []})
        if "." in t.id:
            grp["subs"].append(t)
        else:
            grp["parent"] = t
    parts: list[str] = []
    for parent_id in sorted(by_parent):
        grp = by_parent[parent_id]
        p = grp["parent"]
        subs = sorted(grp["subs"], key=lambda s: s.id)
        if p is not None:
            label = f"`{p.id}` {p.name}"
            if subs:
                label += f" (+{len(subs)} sub)"
            parts.append(label)
        else:
            parts.append(", ".join(f"`{s.id}` {s.name}" for s in subs))
    return " · ".join(parts)


def render_markdown(report: GapsReport) -> str:
    lines: list[str] = []
    lines.append("# MITRE ATT&CK Coverage Gaps")
    lines.append("")
    lines.append(
        f"_Reference list: {report.techniques_source} "
        f"({report.reference_count} technique(s) in scope)._"
    )
    lines.append("")
    # Mode-aware scope note. The curated list is a deliberate subset (say so,
    # and how to get the full matrix); the full matrix yields a large gap
    # surface (say so, so "N uncovered" isn't read as a regression); a custom
    # --techniques-file is the operator's own reference (no caveat).
    if report.techniques_source == CURATED_LABEL:
        lines.append(
            "> **Scope note:** this is the *curated subset* of high-value "
            "techniques, **not** the full MITRE ATT&CK Enterprise matrix. "
            "Use `--matrix-mode full` (the default) for the complete matrix, "
            "or `--techniques-file` for your own threat model."
        )
        lines.append("")
    elif report.techniques_source == FULL_LABEL:
        lines.append(
            "> **Scope note:** this is the *full* MITRE ATT&CK Enterprise "
            "matrix including sub-techniques, refreshed weekly from MITRE. A "
            "large uncovered surface is expected and is **not** a detection "
            "regression — most environments deliberately cover a focused "
            "subset. Use `--matrix-mode curated` for the high-value shortlist."
        )
        lines.append("")
    if report.scope_label:
        lines.append(f"_Detections counted: {report.scope_label}._")
        lines.append("")
    headline = (
        f"**{report.techniques_covered}** of **{report.techniques_total}** "
        f"technique(s) covered"
    )
    if report.sub_techniques_total:
        headline += (
            f", **{report.sub_techniques_covered}** of "
            f"**{report.sub_techniques_total}** sub-technique(s)"
        )
    lines.append(headline + ".")
    lines.append("")
    lines.append("| Tactic | Covered | Total | Uncovered techniques |")
    lines.append("|---|---:|---:|---|")
    for tg in report.tactics:
        if tg.total_in_tactic == 0:
            continue
        lines.append(
            f"| {tg.tactic} | {tg.covered_count} | "
            f"{tg.total_in_tactic} | {_format_uncovered(tg.uncovered)} |"
        )
    lines.append("")
    lines.append(
        "_Per-tactic counts list a technique under every tactic it belongs to, "
        "so they add up to more than the distinct totals above._"
    )
    diag_lines = render_diagnostics_markdown(report.diagnostics)
    if diag_lines:
        lines.append("")
        lines.append("**ATT&CK data quality:**")
        lines.append("")
        lines.extend(diag_lines)
    lines.append("")
    return "\n".join(lines)


def render_json(report: GapsReport) -> str:
    payload = {
        "techniques_source": report.techniques_source,
        "reference_count": report.reference_count,
        "techniques_total": report.techniques_total,
        "techniques_covered": report.techniques_covered,
        "sub_techniques_total": report.sub_techniques_total,
        "sub_techniques_covered": report.sub_techniques_covered,
        "scope": report.scope_label,
        # (tactic, technique) cell counts of the per-tactic table.
        "total_techniques": report.total_techniques,
        "total_uncovered": report.total_uncovered,
        "tactics": [
            {
                "tactic": tg.tactic,
                "covered_count": tg.covered_count,
                "total_in_tactic": tg.total_in_tactic,
                "uncovered": [
                    {"id": t.id, "name": t.name}
                    for t in tg.uncovered
                ],
            }
            for tg in report.tactics
            if tg.total_in_tactic > 0
        ],
    }
    return json.dumps(payload, indent=2, sort_keys=False) + "\n"


__all__ = [
    "TechniqueRef",
    "TacticGaps",
    "GapsReport",
    "CURATED_LABEL",
    "FULL_LABEL",
    "load_techniques",
    "compute_gaps",
    "render_markdown",
    "render_json",
]
