# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""`contentops explain <rule-id>` — single-command rule context.

Surfaces everything a Detection Engineer needs when paged about
a misbehaving rule, in one shot:

* YAML envelope summary (owner, runbook, severity, tactics, status,
  path, locked).
* Dependencies (tables, watchlists, parsers, detections).
* State snapshot (last applied at / by / sha, remote name).
* Recent audit (last N records for this id).
* Drift status (if a drift_report.json exists in cwd).

Pure functions; the CLI wraps them. JSON output mirrors the
markdown structure for scripted consumption.
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable

import yaml

from contentops.audit_filter import iter_records
from contentops.core.asset import Asset
from contentops.core.discovery import iter_loaded_assets
from contentops.core.handler import LoadedAsset

logger = logging.getLogger(__name__)


@dataclass
class AuditEntry:
    timestamp: str
    action: str
    status: str
    sha: str
    actor: str
    message: str | None = None


@dataclass
class Explain:
    """The full context document for one rule."""
    found: bool
    rule_id: str

    # Envelope summary
    asset: str | None = None
    status: str | None = None
    locked: bool = False
    path: str | None = None

    # Metadata (None when the envelope carries only ``arm_name``)
    owner: str | None = None
    runbook_url: str | None = None
    severity: str | None = None
    tactics: list[str] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)
    expected_alerts_per_day: float | int | None = None
    fp_handling: str | None = None
    arm_name: str | None = None

    # Dependencies (from detections/dependencies.yml)
    needs_tables: list[str] = field(default_factory=list)
    needs_watchlists: list[str] = field(default_factory=list)
    needs_parsers: list[str] = field(default_factory=list)
    needs_detections: list[str] = field(default_factory=list)

    # State
    last_applied_at: str | None = None
    last_applied_sha: str | None = None
    last_applied_status: str | None = None
    state_remote_id: str | None = None

    # Audit
    recent_audit: list[AuditEntry] = field(default_factory=list)

    # Drift (best-effort; filled if drift_report.json exists)
    drift_status: str | None = None  # "in-sync" | "new" | "changed" | None


# ---------------------------------------------------------------------------
# Gathering
# ---------------------------------------------------------------------------


def _find_loaded(detections_root: Path, rule_id: str) -> LoadedAsset | None:
    """Return the LoadedAsset whose envelope.id matches rule_id, or None."""
    for la in iter_loaded_assets(
        detections_root,
        on_error=lambda p, exc: logger.warning("explain: skipping %s: %s", p, exc),
    ):
        if la.envelope.id == rule_id:
            return la
    return None


def _is_locked(la: LoadedAsset) -> bool:
    """Check the on-disk YAML for a top-level localCustomization flag."""
    try:
        raw = yaml.safe_load(la.path.read_text(encoding="utf-8"))
    except Exception as exc:
        logger.warning("explain: yaml parse failed for %s: %s", la.path, exc)
        return False
    return isinstance(raw, dict) and raw.get("localCustomization") is True


def _load_dependencies(detections_root: Path, rule_id: str) -> dict[str, list[str]]:
    """Read detections/dependencies.yml, return per-rule prereq lists.

    Tolerant of the file being absent.
    """
    out = {
        "tables": [], "watchlists": [], "parsers": [], "detections": [],
    }
    path = detections_root / "dependencies.yml"
    if not path.is_file():
        return out
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception as exc:
        logger.warning("explain: dependencies.yml parse failed: %s", exc)
        return out
    if not isinstance(raw, dict):
        return out
    assets = raw.get("assets") or {}
    if not isinstance(assets, dict):
        return out
    entry = assets.get(rule_id)
    if not isinstance(entry, dict):
        return out
    for key in out:
        v = entry.get(key) or []
        if isinstance(v, list):
            out[key] = [str(x) for x in v if isinstance(x, (str, int))]
    return out


def _load_state_for(rule_id: str, root: Path) -> tuple[str | None, str | None, str | None, str | None]:
    """Return (last_applied_at, last_applied_sha, status, remote_id) for rule_id."""
    try:
        from contentops.config import load_tenant_config
        from contentops.state import load_state
    except Exception as exc:
        logger.warning("explain: cannot import config/state modules: %s", exc)
        return (None, None, None, None)
    try:
        env_name = load_tenant_config().name
    except Exception as exc:
        logger.warning("explain: load_tenant_config failed: %s", exc)
        env_name = ""
    try:
        state = load_state(env=env_name, root=root)
    except Exception as exc:
        logger.warning("explain: load_state failed: %s", exc)
        return (None, None, None, None)
    for kind, entries in state.managed_assets.items():
        if rule_id in entries:
            entry = entries[rule_id]
            return (
                entry.last_applied_at or None,
                entry.last_applied_sha or None,
                entry.status or None,
                entry.remote_id or None,
            )
    return (None, None, None, None)


def _recent_audit(audit_dir: Path, rule_id: str, limit: int = 5) -> list[AuditEntry]:
    """Return up to ``limit`` most recent audit records for rule_id, newest first."""
    if not audit_dir.is_dir():
        return []
    files = sorted(audit_dir.glob("*.jsonl"))
    rows: list[AuditEntry] = []
    for rec in iter_records(files):
        if str(rec.get("id") or "") != rule_id:
            continue
        rows.append(AuditEntry(
            timestamp=str(rec.get("timestamp") or ""),
            action=str(rec.get("action") or ""),
            status=str(rec.get("status") or ""),
            sha=str(rec.get("sha") or "")[:12],
            actor=str(rec.get("actor") or ""),
            message=(str(rec["message"]) if rec.get("message") else None),
        ))
    rows.sort(key=lambda r: r.timestamp, reverse=True)
    return rows[:limit]


def _drift_status(rule_id: str, root: Path) -> str | None:
    """Best-effort: read ``drift_report.json`` (current cwd) to find this rule.

    Returns "new", "changed", "in-sync" or None.
    """
    path = root / "drift_report.json"
    if not path.is_file():
        return None
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        logger.warning("explain: drift_report.json parse failed: %s", exc)
        return None
    entries = doc.get("entries") or []
    if not isinstance(entries, list):
        return None
    for e in entries:
        if isinstance(e, dict) and str(e.get("id") or "") == rule_id:
            kind = str(e.get("kind") or "")
            return kind or None
    # Not in entries means in-sync (drift report only tracks new+changed).
    return "in-sync"


# ---------------------------------------------------------------------------
# Top-level builder
# ---------------------------------------------------------------------------


def build_explain(
    rule_id: str,
    *,
    detections_root: Path,
    audit_dir: Path,
    state_root: Path,
    drift_root: Path,
) -> Explain:
    """Walk every source and assemble one Explain document."""
    la = _find_loaded(detections_root, rule_id)
    if la is None:
        return Explain(found=False, rule_id=rule_id)

    deps = _load_dependencies(detections_root, rule_id)
    state_at, state_sha, state_status, state_remote = _load_state_for(
        rule_id, state_root,
    )
    audit_rows = _recent_audit(audit_dir, rule_id)
    drift = _drift_status(rule_id, drift_root)
    locked = _is_locked(la)

    metadata = la.envelope.metadata
    return Explain(
        found=True,
        rule_id=rule_id,
        asset=la.envelope.asset.value,
        status=la.envelope.status,
        locked=locked,
        path=str(la.path),
        owner=getattr(metadata, "owner", None) if metadata else None,
        runbook_url=getattr(metadata, "runbookUrl", None) if metadata else None,
        severity=getattr(metadata, "severity", None) if metadata else None,
        tactics=list(getattr(metadata, "tactics", []) or []) if metadata else [],
        techniques=list(getattr(metadata, "techniques", []) or []) if metadata else [],
        expected_alerts_per_day=(
            getattr(metadata, "expectedAlertsPerDay", None) if metadata else None
        ),
        fp_handling=getattr(metadata, "fpHandling", None) if metadata else None,
        arm_name=la.envelope.arm_name,
        needs_tables=deps["tables"],
        needs_watchlists=deps["watchlists"],
        needs_parsers=deps["parsers"],
        needs_detections=deps["detections"],
        last_applied_at=state_at,
        last_applied_sha=state_sha,
        last_applied_status=state_status,
        state_remote_id=state_remote,
        recent_audit=audit_rows,
        drift_status=drift,
    )


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def render_markdown(e: Explain) -> str:
    if not e.found:
        return f"## {e.rule_id}\n\n_no rule found with this id under detections/_\n"
    lines: list[str] = []
    lines.append(f"## {e.rule_id}  ({e.asset}, status: {e.status})")
    lines.append("")
    if e.owner:
        lines.append(f"Owner:      {e.owner}")
    if e.runbook_url:
        lines.append(f"Runbook:    {e.runbook_url}")
    if e.severity:
        sev_extras = []
        if e.tactics:
            sev_extras.append(f"Tactics: {', '.join(e.tactics)}")
        if e.techniques:
            sev_extras.append(f"Techniques: {', '.join(e.techniques)}")
        sev_extras_str = ("  •  " + "  •  ".join(sev_extras)) if sev_extras else ""
        lines.append(f"Severity:   {e.severity}{sev_extras_str}")
    lines.append(f"Path:       {e.path}")
    if e.arm_name:
        lines.append(f"ARM name:   {e.arm_name}")
    if e.locked:
        lines.append("Locked:     true (apply will skip without --force-overwrite)")

    lines.append("")
    lines.append("### Dependencies")
    if any([e.needs_tables, e.needs_watchlists, e.needs_parsers, e.needs_detections]):
        if e.needs_tables:
            lines.append(f"  needs tables:     {', '.join(e.needs_tables)}")
        if e.needs_watchlists:
            lines.append(f"  needs watchlists: {', '.join(e.needs_watchlists)}")
        if e.needs_parsers:
            lines.append(f"  needs parsers:    {', '.join(e.needs_parsers)}")
        if e.needs_detections:
            lines.append(f"  needs detections: {', '.join(e.needs_detections)}")
    else:
        lines.append("  (none declared in detections/dependencies.yml)")

    lines.append("")
    lines.append("### State")
    if e.last_applied_at:
        lines.append(f"  last applied: {e.last_applied_at} ({e.last_applied_status})")
        if e.last_applied_sha:
            lines.append(f"  last sha:     {e.last_applied_sha[:12]}")
        if e.state_remote_id:
            lines.append(f"  remote id:    {e.state_remote_id}")
    else:
        lines.append("  (no state record — never applied via the pipeline)")

    lines.append("")
    lines.append("### Recent audit (most recent first)")
    if e.recent_audit:
        for row in e.recent_audit:
            msg = f"   {row.message}" if row.message else ""
            lines.append(
                f"  {row.timestamp}  {row.action:8s}  {row.status:8s}  "
                f"{row.sha:12s}  {row.actor}{msg}"
            )
    else:
        lines.append("  (no audit records)")

    lines.append("")
    lines.append("### Drift status")
    if e.drift_status:
        lines.append(f"  {e.drift_status}")
    else:
        lines.append("  (no drift_report.json in cwd)")
    lines.append("")
    return "\n".join(lines)


def render_json(e: Explain) -> str:
    return json.dumps(asdict(e), indent=2, default=str) + "\n"


__all__ = [
    "AuditEntry",
    "Explain",
    "build_explain",
    "render_markdown",
    "render_json",
]
