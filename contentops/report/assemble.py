# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Pure-function row assembler for the SOC-grade detection report.

Joins three sources into one row per detection:

* Envelope (``id``, ``status``, ``severity``, ``tactics`` /
  ``techniques`` from ``metadata``, ``displayName`` from payload,
  ``lastValidatedAt``).
* Git log (first-commit timestamp of the YAML file — the *merge
  date*, the moment the detection landed in the repo).
* Audit JSONL (latest record where ``id`` matches AND ``status ==
  "success"`` — the *deployment date*, the last time the rule
  actually applied without error).

Live enrichment (telemetry, health, schema drift) layers extra
fields onto :class:`ReportRow` in PR-2; this module stays pure and
network-free so it always runs in fork CI / offline.
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from contentops.core.asset import Asset
from contentops.core.discovery import discover_assets, load_asset
from contentops.coverage.extract import extract_mitre

logger = logging.getLogger(__name__)


DETECTION_ASSETS: frozenset[Asset] = frozenset({
    Asset.SENTINEL_ANALYTIC,
    Asset.SENTINEL_HUNTING,
    Asset.DEFENDER_CUSTOM_DETECTION,
})


@dataclass(frozen=True)
class ReportRow:
    """One row in the detection inventory report.

    Static fields (PR-1) always present. Live-enrichment fields
    (PR-2) ship as ``None`` here and get filled in by the optional
    enrichment pass. CFO-polish fields (PR-cfo) are accountability /
    governance signals every CFO-facing inventory carries.
    """

    # Identity
    rule_id: str
    asset_kind: str
    path: str                       # repo-relative

    # Authoring metadata
    title: str                      # payload.displayName or fallback to id
    status: str                     # production / experimental / deprecated / test
    severity: str                   # informational / low / medium / high
    tactics: tuple[str, ...]
    techniques: tuple[str, ...]

    # Lifecycle dates (ISO-8601; None when unknown)
    merge_date: str | None          # git log: first commit touching this path
    deployment_date: str | None     # audit: latest success record
    last_review_date: str | None    # envelope.metadata.lastValidatedAt

    # Live-enrichment fields (PR-2; always None in PR-1)
    alerts_30d: int | None = None
    true_positives_30d: int | None = None
    false_positives_30d: int | None = None
    fp_rate: float | None = None
    effectiveness_score: float | None = None
    data_source_healthy: bool | None = None
    schema_drift_columns: tuple[str, ...] = field(default_factory=tuple)

    # Alert health enrichment (--with-alerts)
    alert_silent_days: int | None = None
    alert_recommendation: str | None = None

    # Governance / accountability fields (PR-cfo)
    owner: str | None = None        # metadata.owner -- accountability
    runbook_url: str | None = None  # metadata.runbookUrl -- response process
    last_pr_number: int | None = None  # GitHub PR# of last change (squash-merge subject)
    last_pr_url: str | None = None  # full URL to the PR for clickthrough


@dataclass(frozen=True)
class ReportSummary:
    """Aggregate stats shown in the report footer + badge.

    Three-level coverage (tactics / techniques / sub-techniques) is
    surfaced via separate fields so the HTML report's summary cards
    can render each level. The legacy ``coverage_*`` triple keeps
    forwarding to the technique level for backwards compat with PR
    #255's renderer / badge code that ships only the single number.
    """

    total: int
    production: int
    experimental: int
    deprecated: int
    # Technique-level coverage (the primary headline number).
    coverage_pct: int
    coverage_covered: int
    coverage_total: int
    generated_at: str               # ISO-8601 UTC
    # Tactic-level and sub-technique-level coverage (PR-polish).
    # Default 0/0 so a caller building ReportSummary directly without
    # the new fields still constructs a valid object.
    coverage_tactics_pct: int = 0
    coverage_tactics_covered: int = 0
    coverage_tactics_total: int = 0
    coverage_sub_techniques_pct: int = 0
    coverage_sub_techniques_covered: int = 0
    coverage_sub_techniques_total: int = 0


# ---------------------------------------------------------------------------
# Git: first-commit timestamp for the YAML file (merge date)
# ---------------------------------------------------------------------------


def _git_merge_date(repo_root: Path, rel_path: str) -> str | None:
    """Return the ISO-8601 timestamp of the first commit touching the file.

    Returns ``None`` when the file isn't tracked (e.g. operator just
    authored it locally and hasn't committed yet) or when git itself
    isn't on the PATH. Doesn't raise — a missing merge date is the
    expected case for in-progress work and shouldn't break report
    generation.

    ``--diff-filter=A`` restricts to the *add* commit (so a rename
    or content edit later doesn't move the merge date forward).
    """
    try:
        proc = subprocess.run(
            [
                "git", "log",
                "--diff-filter=A",
                "--follow",
                "--reverse",
                "--format=%cI",
                "--",
                rel_path,
            ],
            cwd=repo_root,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    first_line = proc.stdout.strip().splitlines()[:1]
    return first_line[0] if first_line else None


# ---------------------------------------------------------------------------
# Git: last PR# for the file (governance link)
# ---------------------------------------------------------------------------


# Squash-merge convention: commit subject ends in "(#NNN)".
_PR_NUM_RE = re.compile(r"\(#(\d+)\)\s*$")


def _github_origin_repo(repo_root: Path) -> str | None:
    """Return ``owner/repo`` from the ``origin`` remote, or None.

    Used to build the per-row PR link. Parses both HTTPS
    (``https://github.com/owner/repo.git``) and SSH
    (``git@github.com:owner/repo.git``) URLs. Returns None for non-
    GitHub origins so the report degrades gracefully (PR# shows but
    isn't clickable).
    """
    try:
        proc = subprocess.run(
            ["git", "remote", "get-url", "origin"],
            cwd=repo_root, capture_output=True, text=True, timeout=5,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    url = proc.stdout.strip()
    # github.com/owner/repo  OR  github.com:owner/repo
    import re as _re
    match = _re.search(r"github\.com[:/]([^/]+)/([^/.]+?)(?:\.git)?/?$", url)
    if not match:
        return None
    return f"{match.group(1)}/{match.group(2)}"


def _git_last_pr_for_path(
    repo_root: Path, rel_path: str, *, origin_repo: str | None,
) -> tuple[int | None, str | None]:
    """Return ``(pr_number, pr_url)`` for the most recent commit touching
    the file.

    Heuristic: this repo uses squash-merge with a ``(#NNN)`` suffix
    on every PR's merge commit subject. ``git log -1 --format=%s --
    <path>`` returns that subject; a regex extracts the number.
    Local commits without a PR ref (``chore(collect): snapshot
    live tenant`` etc.) return ``(None, None)`` — the column renders
    as blank, distinguishing "no PR" from "PR # unknown".
    """
    try:
        proc = subprocess.run(
            [
                "git", "log",
                "-1", "--format=%s",
                "--", rel_path,
            ],
            cwd=repo_root, capture_output=True, text=True, timeout=10,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return (None, None)
    if proc.returncode != 0:
        return (None, None)
    subject = proc.stdout.strip()
    match = _PR_NUM_RE.search(subject)
    if not match:
        return (None, None)
    pr_num = int(match.group(1))
    if origin_repo is None:
        return (pr_num, None)
    return (pr_num, f"https://github.com/{origin_repo}/pull/{pr_num}")


# ---------------------------------------------------------------------------
# Audit: latest successful deployment per rule_id
# ---------------------------------------------------------------------------


def _audit_deploy_dates(audit_dir: Path) -> dict[str, str]:
    """Return ``{rule_id: latest_success_timestamp}`` across every JSONL.

    Walks ``audit/*.jsonl`` in lexicographic (date-ordered) order, parses
    each line, keeps the latest ``timestamp`` per (rule_id, status="success")
    pair. Records without a valid timestamp or matching id are ignored —
    the goal is a best-effort latest-deploy view, not chain verification
    (that's ``audit-verify.yml``'s job).

    Returns an empty dict when ``audit_dir`` doesn't exist or no records
    qualify.
    """
    deploy_dates: dict[str, str] = {}
    if not audit_dir.is_dir():
        return deploy_dates
    for path in sorted(audit_dir.glob("*.jsonl")):
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            if not isinstance(rec, dict):
                continue
            if rec.get("status") != "success":
                continue
            rule_id = rec.get("id")
            ts = rec.get("timestamp")
            if not isinstance(rule_id, str) or not isinstance(ts, str):
                continue
            existing = deploy_dates.get(rule_id)
            if existing is None or ts > existing:
                deploy_dates[rule_id] = ts
    return deploy_dates


# ---------------------------------------------------------------------------
# Top-level assembly
# ---------------------------------------------------------------------------


def _coerce_str_tuple(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(v for v in value if isinstance(v, str) and v)


def _display_name(loaded: Any) -> str:
    """Pull a human-readable title from the payload; fall back to id.

    Each asset kind stores its display string at a slightly different
    path. We accept any of the common ones — failing means we use the
    envelope id, which is still always present.
    """
    payload = loaded.payload if hasattr(loaded, "payload") else None
    if isinstance(payload, dict):
        for key in ("displayName", "display_name", "title"):
            value = payload.get(key)
            if isinstance(value, str) and value:
                return value
    return loaded.envelope.id


def assemble_report(
    detections_root: Path,
    *,
    repo_root: Path | None = None,
    audit_dir: Path | None = None,
    today: date | None = None,
) -> tuple[list[ReportRow], ReportSummary]:
    """Build the report row list + aggregate summary.

    Pure assembly — no network, no live workspace queries. Suitable
    for fork CI and offline runs.

    ``repo_root`` defaults to ``detections_root.parent`` (for git log
    invocation); pass explicitly when the layout is non-standard.
    ``audit_dir`` defaults to ``repo_root / "audit"``.
    ``today`` defaults to the current UTC date (used for the summary
    ``generated_at`` field).
    """
    repo_root = repo_root or detections_root.parent
    audit_dir = audit_dir or (repo_root / "audit")
    deploy_dates = _audit_deploy_dates(audit_dir)
    origin_repo = _github_origin_repo(repo_root)
    rows: list[ReportRow] = []
    status_counts = {"production": 0, "experimental": 0, "deprecated": 0}

    for path in sorted(discover_assets(detections_root)):
        try:
            loaded = load_asset(path)
        except Exception as exc:
            logger.debug("skipping unparseable envelope %s: %s", path, exc)
            continue
        if loaded.envelope.asset not in DETECTION_ASSETS:
            continue

        rel_path = str(path.relative_to(repo_root)).replace("\\", "/")
        meta = loaded.envelope.metadata
        status = str(loaded.envelope.status)
        if status in status_counts:
            status_counts[status] += 1

        pr_num, pr_url = _git_last_pr_for_path(
            repo_root, rel_path, origin_repo=origin_repo,
        )

        mitre = extract_mitre(loaded.envelope, loaded.payload)
        meta_tactics = _coerce_str_tuple(meta.tactics) if meta else ()
        meta_techniques = _coerce_str_tuple(meta.techniques) if meta else ()
        if not meta_tactics and not meta_techniques:
            meta_tactics = mitre.tactics
            meta_techniques = mitre.techniques
        meta_severity = (meta.severity if meta and meta.severity else None) or mitre.severity or "informational"

        rows.append(ReportRow(
            rule_id=loaded.envelope.id,
            asset_kind=loaded.envelope.asset.value,
            path=rel_path,
            title=_display_name(loaded),
            status=status,
            severity=meta_severity,
            tactics=meta_tactics,
            techniques=meta_techniques,
            merge_date=_git_merge_date(repo_root, rel_path),
            deployment_date=deploy_dates.get(loaded.envelope.id),
            last_review_date=(
                meta.lastValidatedAt if meta and meta.lastValidatedAt else None
            ),
            owner=meta.owner if meta and meta.owner else None,
            runbook_url=meta.runbookUrl if meta and meta.runbookUrl else None,
            last_pr_number=pr_num,
            last_pr_url=pr_url,
        ))

    # Coverage from the existing helper — wires the badge to the same
    # number the README displays. Late import to avoid the cycle if
    # coverage_summary ever pulls from report code.
    from contentops.coverage import coverage_summary
    cov = coverage_summary(detections_root)

    now_utc = datetime.now(timezone.utc)
    summary = ReportSummary(
        total=len(rows),
        production=status_counts["production"],
        experimental=status_counts["experimental"],
        deprecated=status_counts["deprecated"],
        coverage_pct=cov.techniques.pct,
        coverage_covered=cov.techniques.covered,
        coverage_total=cov.techniques.total,
        generated_at=now_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
        coverage_tactics_pct=cov.tactics.pct,
        coverage_tactics_covered=cov.tactics.covered,
        coverage_tactics_total=cov.tactics.total,
        coverage_sub_techniques_pct=cov.sub_techniques.pct,
        coverage_sub_techniques_covered=cov.sub_techniques.covered,
        coverage_sub_techniques_total=cov.sub_techniques.total,
    )
    return rows, summary
