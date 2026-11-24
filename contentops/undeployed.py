# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Authored-but-never-deployed reconciliation.

Surfaces the blind spot the coverage heatmap + silent-rules both miss: a
detection that exists in ``detections/`` (authored, in git) but has no
apply record in the env state (``refs/heads/state/<env>`` →
``state/state.json``), i.e. it has never been deployed to the tenant.

The high-value signal is a ``status: production`` rule with no apply
record — it *should* be protecting the tenant but isn't. An undeployed
``experimental`` rule is expected (experimental status does not deploy),
so it's reported but not flagged.

Offline + deterministic: reads git-tracked envelopes + the materialised
state file. No live workspace query (that's `navigator` / `drift`).
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path

import yaml

from contentops.core.discovery import iter_loaded_assets
from contentops.state import EnvState


@dataclass(frozen=True)
class UndeployedRule:
    asset_kind: str
    rule_id: str
    status: str
    path: str


@dataclass
class UndeployedReport:
    env: str
    state_available: bool       # the state file had any managed assets
    total_repo: int
    total_managed: int          # assets with an apply record in state
    undeployed: list[UndeployedRule]

    @property
    def production_undeployed(self) -> list[UndeployedRule]:
        return [r for r in self.undeployed if r.status == "production"]


def find_undeployed(detections_root: Path, state: EnvState) -> UndeployedReport:
    """Reconcile repo envelopes against the applied-state managed set."""
    undeployed: list[UndeployedRule] = []
    total_repo = 0
    for la in iter_loaded_assets(detections_root):
        total_repo += 1
        kind = la.envelope.asset.value
        rule_id = la.envelope.id
        if state.is_managed(kind, rule_id):
            continue
        status = str(getattr(la.envelope, "status", "") or "").strip().lower()
        undeployed.append(UndeployedRule(
            asset_kind=kind, rule_id=rule_id, status=status,
            path=str(la.path).replace("\\", "/"),
        ))
    # Production first (the real concern), then by kind + id — deterministic.
    undeployed.sort(key=lambda r: (r.status != "production", r.asset_kind, r.rule_id))
    return UndeployedReport(
        env=state.env,
        state_available=state.asset_count() > 0,
        total_repo=total_repo,
        total_managed=state.asset_count(),
        undeployed=undeployed,
    )


def _file_id(path: Path) -> str | None:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001 — an unreadable file is simply not flagged
        return None
    rid = raw.get("id") if isinstance(raw, dict) else None
    return str(rid) if rid else None


def _changed_between(repo: Path, sha: str, paths: list[Path]) -> bool:
    """True when ``paths`` differ between commit ``sha`` and ``HEAD``.
    Unknown (the commit is not in this clone, git fails) reads as False."""
    rels: list[str] = []
    for p in paths:
        try:
            rels.append(p.resolve().relative_to(repo.resolve()).as_posix())
        except ValueError:
            rels.append(p.as_posix())
    try:
        result = subprocess.run(
            ["git", "-C", str(repo), "diff", "--quiet", sha, "HEAD", "--", *rels],
            capture_output=True, check=False, timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 1


def changed_since_last_deploy(entries, state: EnvState, *, repo: Path) -> set[tuple[str, str]]:
    """``(asset kind, drift id)`` of the changed drift entries whose local
    file (or playbook sidecar) changed in git after the commit the rule was
    last applied from (its state entry's ``last_applied_sha``).

    Such drift is usually a merged change the tenant has not received yet
    (a repository that deploys by hand): merging the drift PR would undo
    the merge. A rule whose last apply failed is named too (the tenant
    kept an older version). No state entry, no recorded commit, or a
    commit this clone does not have flags nothing.
    """
    flagged: set[tuple[str, str]] = set()
    for entry in entries:
        path = getattr(entry, "local_path", None)
        if path is None:
            continue
        path = Path(path)
        kind = entry.asset.value
        local_id = _file_id(path) or entry.asset_id
        recorded = (state.managed_assets.get(kind) or {}).get(local_id)
        if recorded is not None and recorded.status == "failed":
            # The last apply of this file was rejected: the tenant still
            # holds an older version, whatever commit the state records.
            flagged.add((kind, entry.asset_id))
            continue
        sha = recorded.last_applied_sha if recorded is not None else ""
        if not sha:
            continue
        paths = [path, *sorted(path.parent.glob(f"{path.stem}.*.json"))]
        if _changed_between(repo, sha, paths):
            flagged.add((kind, entry.asset_id))
    return flagged


def render_markdown(report: UndeployedReport) -> str:
    lines: list[str] = ["# Authored but never deployed", ""]
    lines.append(
        "_Detections in `detections/` with no apply record in the "
        f"`{report.env or '(default)'}` state. A **production** rule here "
        "should be protecting the tenant but isn't; an `experimental` rule "
        "is expected (experimental status does not deploy)._"
    )
    lines.append("")

    if not report.state_available:
        lines.append(
            f"> **State unavailable** for env `{report.env or '(default)'}` "
            "(no managed assets recorded). Run `contentops state sync pull` "
            "first — without it every rule looks undeployed, so the list "
            "below is suppressed."
        )
        lines.append("")
        lines.append(
            f"**{report.total_repo}** repo rule(s); **0** with an apply record."
        )
        lines.append("")
        return "\n".join(lines)

    prod = report.production_undeployed
    lines.append(
        f"**{len(report.undeployed)}** of {report.total_repo} repo rule(s) "
        f"have no apply record ({len(prod)} of them `production`). "
        f"{report.total_managed} rule(s) are deployed per state."
    )
    lines.append("")
    if not report.undeployed:
        lines.append("✅ Every authored rule has an apply record.")
        lines.append("")
        return "\n".join(lines)

    lines.append("|  | Status | Asset kind | Rule |")
    lines.append("|---|---|---|---|")
    for r in report.undeployed:
        flag = "⚠️" if r.status == "production" else ""
        lines.append(f"| {flag} | {r.status or '—'} | {r.asset_kind} | `{r.rule_id}` |")
    lines.append("")
    return "\n".join(lines)


def render_json(report: UndeployedReport) -> str:
    import json
    payload = {
        "env": report.env,
        "state_available": report.state_available,
        "total_repo": report.total_repo,
        "total_managed": report.total_managed,
        "production_undeployed_count": len(report.production_undeployed),
        "undeployed": [
            {
                "asset_kind": r.asset_kind,
                "rule_id": r.rule_id,
                "status": r.status,
                "path": r.path,
            }
            for r in report.undeployed
        ],
    }
    return json.dumps(payload, indent=2, sort_keys=False) + "\n"


__all__ = [
    "UndeployedRule",
    "UndeployedReport",
    "changed_since_last_deploy",
    "find_undeployed",
    "render_markdown",
    "render_json",
]
