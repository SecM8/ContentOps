# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Render a Markdown PR body for the drift auto-PR workflow.

Input shape (the JSON ``contentops drift --report`` writes):

    {
      "tenant": "production",
      "workspace": "law-sentinel",
      "run_id": "12345",
      "entries": [
        {"asset": "sentinel_analytic", "id": "abc", "kind": "new"},
        {"asset": "sentinel_hunting",  "id": "xyz", "kind": "changed"},
        ...
      ]
    }

The renderer also walks ``detections/`` to look up
``envelope.metadata.owner`` for each changed asset so reviewers can be
auto-tagged via a checkbox list. Pure function — no I/O when callers
pass an explicit ``id_to_owner`` mapping (used by the unit test).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

import yaml


@dataclass(frozen=True)
class DriftEntrySummary:
    asset: str
    id: str
    kind: str  # "new" or "changed"


@dataclass(frozen=True)
class SuppressionSummary:
    asset: str
    id: str
    expires: str = ""  # populated for "unused" rows; empty otherwise


@dataclass(frozen=True)
class DriftReportSummary:
    tenant: str
    workspace: str
    run_id: str
    entries: list[DriftEntrySummary]
    # Suppression accounting (drift_suppressions.yml). Default empty so
    # reports written before F15's report-schema bump still parse.
    suppressed: list[SuppressionSummary] = field(default_factory=list)
    expired: list[SuppressionSummary] = field(default_factory=list)
    unused: list[SuppressionSummary] = field(default_factory=list)


_GH_HANDLE_RE = re.compile(r"^@?[A-Za-z0-9][A-Za-z0-9-]{0,38}$")


def _email_to_handle(owner: str) -> str:
    """Best-effort GitHub handle from an envelope owner email or string.

    Drops the @domain. If the local-part already looks like a handle, we
    use it; otherwise we leave the raw value so reviewers can correct it
    on the PR rather than hiding bad data.
    """
    if not owner:
        return ""
    candidate = owner.split("@", 1)[0] if "@" in owner else owner
    return candidate if _GH_HANDLE_RE.match(candidate) else owner


def parse_report(raw: dict) -> DriftReportSummary:
    entries = [
        DriftEntrySummary(
            asset=str(e.get("asset") or ""),
            id=str(e.get("id") or ""),
            kind=str(e.get("kind") or ""),
        )
        for e in raw.get("entries") or []
    ]

    def _suppressions(key: str) -> list[SuppressionSummary]:
        # Tolerant of older reports that predate the F15 schema bump:
        # a missing key yields an empty list, not a KeyError.
        return [
            SuppressionSummary(
                asset=str(s.get("asset") or ""),
                id=str(s.get("id") or ""),
                expires=str(s.get("expires") or ""),
            )
            for s in raw.get(key) or []
        ]

    return DriftReportSummary(
        tenant=str(raw.get("tenant") or ""),
        workspace=str(raw.get("workspace") or ""),
        run_id=str(raw.get("run_id") or ""),
        entries=entries,
        suppressed=_suppressions("suppressed"),
        expired=_suppressions("expired"),
        unused=_suppressions("unused"),
    )


def collect_owners(detections_root: Path, ids: Iterable[str]) -> dict[str, str]:
    """Map asset id → owner string by scanning every YAML under ``root``.

    Drift may write a *new* envelope on disk that didn't previously
    exist, so we walk the post-write tree. Files without a parseable
    metadata.owner are silently skipped.
    """
    wanted = set(ids)
    out: dict[str, str] = {}
    if not wanted or not detections_root.exists():
        return out
    for yml in detections_root.rglob("*.yml"):
        try:
            raw = yaml.safe_load(yml.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(raw, dict):
            continue
        rid = raw.get("id")
        if rid in wanted:
            metadata = raw.get("metadata") or {}
            owner = metadata.get("owner") if isinstance(metadata, dict) else None
            if isinstance(owner, str) and owner:
                out[rid] = owner
    return out


def labels_for(report: DriftReportSummary) -> list[str]:
    """Default + per-asset-kind label set."""
    labels = {"drift", "automated"}
    for entry in report.entries:
        if entry.asset:
            labels.add(f"asset:{entry.asset}")
    return sorted(labels)


def render_pr_body(
    report: DriftReportSummary,
    *,
    id_to_owner: dict[str, str] | None = None,
) -> str:
    """Markdown PR body. Stable layout — covered by snapshot test."""
    id_to_owner = id_to_owner or {}
    new = [e for e in report.entries if e.kind == "new"]
    changed = [e for e in report.entries if e.kind == "changed"]

    lines: list[str] = []
    lines.append("## Drift detected")
    lines.append("")
    lines.append(
        "This PR was opened automatically by the `drift` workflow. It contains "
        "content found in the live Microsoft Sentinel / Defender XDR tenant "
        "that does not match the YAML in this repository."
    )
    lines.append("")
    lines.append("| Field | Value |")
    lines.append("| --- | --- |")
    lines.append(f"| Tenant | `{report.tenant}` |")
    lines.append(f"| Workspace | `{report.workspace}` |")
    lines.append(f"| Workflow run | `{report.run_id}` |")
    lines.append(f"| New assets | {len(new)} |")
    lines.append(f"| Changed assets | {len(changed)} |")
    lines.append(f"| Suppressed | {len(report.suppressed)} |")
    lines.append("")

    def _section(title: str, rows: list[DriftEntrySummary]) -> None:
        lines.append(f"### {title} ({len(rows)})")
        if not rows:
            lines.append("_None._")
            lines.append("")
            return
        lines.append("| Asset | ID |")
        lines.append("| --- | --- |")
        for e in sorted(rows, key=lambda r: (r.asset, r.id)):
            lines.append(f"| `{e.asset}` | `{e.id}` |")
        lines.append("")

    _section("New", new)
    _section("Changed", changed)

    # Suppression callouts — only rendered when there's something to act
    # on, so a routine drift PR with no expired/unused suppressions stays
    # uncluttered.
    if report.expired:
        lines.append(f"### Expired suppressions ({len(report.expired)})")
        lines.append(
            "These entries were suppressed in `drift_suppressions.yml` but "
            "the suppression has **expired** — they are back in the changed "
            "list above. Renew the suppression or resolve the drift."
        )
        lines.append("| Asset | ID |")
        lines.append("| --- | --- |")
        for s in sorted(report.expired, key=lambda r: (r.asset, r.id)):
            lines.append(f"| `{s.asset}` | `{s.id}` |")
        lines.append("")
    if report.unused:
        lines.append(f"### Unused suppressions ({len(report.unused)})")
        lines.append(
            "These `drift_suppressions.yml` entries matched no drift today "
            "— safe to remove."
        )
        lines.append("| Asset | ID | Expires |")
        lines.append("| --- | --- | --- |")
        for s in sorted(report.unused, key=lambda r: (r.asset, r.id)):
            lines.append(f"| `{s.asset}` | `{s.id}` | {s.expires} |")
        lines.append("")

    # Owner checklist
    owners_seen: dict[str, list[str]] = {}
    for entry in report.entries:
        owner = id_to_owner.get(entry.id)
        if not owner:
            continue
        owners_seen.setdefault(owner, []).append(entry.id)

    lines.append("### Owner checklist")
    if not owners_seen:
        lines.append("_No owners parsed from envelope metadata._")
    else:
        for owner in sorted(owners_seen):
            handle = _email_to_handle(owner)
            ids_str = ", ".join(f"`{i}`" for i in sorted(owners_seen[owner]))
            lines.append(f"- [ ] @{handle.lstrip('@')} — {ids_str}")
    lines.append("")

    lines.append("---")
    lines.append(
        "Review each file carefully. Merge to accept the upstream change, "
        "or close + run `contentops apply` to push the local state back."
    )
    lines.append("")
    return "\n".join(lines)
