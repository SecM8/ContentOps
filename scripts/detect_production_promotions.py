# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Detect detection-rule status promotions to ``production`` in a PR diff.

Compares two git revisions (typically ``origin/<base>`` and ``HEAD``) and emits
GitHub-Flavored Markdown listing every envelope whose ``status`` was promoted
to ``production`` -- either by editing an existing file or by adding a new
file directly in ``production`` status.

**Hard gate (Phase 2.2a):** every detected promotion must carry a
``lifecycle.promotedAt`` stamp within the last ``--max-stamp-age-days``
(default 30) AND a ``lifecycle.promotedBy`` value. ``contentops lifecycle
promote`` writes those fields; a direct YAML edit that flips ``status``
without going through the CLI has no stamp and is rejected here. When
any promotion is missing or stale on the stamp, the script exits 1 so
the workflow turns the check red. Pass ``--no-gate`` to keep the legacy
status-quo "advisory comment, always exit 0" behaviour for the doc-only
case.
"""

from __future__ import annotations

import argparse
import logging
import subprocess
import sys
from dataclasses import dataclass
from datetime import date, datetime, timezone
from pathlib import Path

import yaml

LOG = logging.getLogger("detect_production_promotions")

DETECTION_PREFIX = "detections/"
YAML_SUFFIXES = (".yml", ".yaml")
PRODUCTION = "production"
DEFAULT_MAX_STAMP_AGE_DAYS = 30


@dataclass(frozen=True)
class Promotion:
    path: str
    rule_id: str
    from_status: str
    to_status: str
    # Phase 2.2a fields — populated from the head envelope's lifecycle
    # block. ``stamp_age_days`` is None when the stamp is missing or
    # unparseable; the gate treats both as "missing stamp".
    promoted_at: str | None = None
    promoted_by: str | None = None
    stamp_age_days: int | None = None
    stamp_ok: bool = False  # Computed: stamp present + within window.


def _run_git(args: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        cwd=cwd,
        check=False,
        capture_output=True,
        text=True,
    )


def _changed_files(base: str, head: str, cwd: Path) -> list[str]:
    result = _run_git(
        ["diff", "--name-status", f"{base}...{head}", "--", "detections/**"],
        cwd=cwd,
    )
    if result.returncode != 0:
        LOG.error("git diff failed: %s", result.stderr.strip())
        return []
    files: list[str] = []
    for line in result.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        status, path = parts[0], parts[-1]
        if status.startswith("D"):
            continue
        if not path.startswith(DETECTION_PREFIX):
            continue
        if not path.lower().endswith(YAML_SUFFIXES):
            continue
        files.append(path)
    return files


def _read_at_rev(rev: str, path: str, cwd: Path) -> str | None:
    if rev == "HEAD-WORKTREE":
        full = cwd / path
        if not full.exists():
            return None
        return full.read_text(encoding="utf-8")
    result = _run_git(["show", f"{rev}:{path}"], cwd=cwd)
    if result.returncode != 0:
        return None
    return result.stdout


def _parse_envelope(text: str | None, path: str, label: str) -> dict | None:
    if text is None:
        return None
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        LOG.warning("malformed YAML in %s @ %s: %s", path, label, exc)
        return None
    return data if isinstance(data, dict) else None


def _parse_iso_date(value: str | None) -> date | None:
    """Accept YYYY-MM-DD or full ISO timestamps; return the date.

    Duplicated from ``contentops.lifecycle._parse_iso_date`` so the
    script stays standalone (the workflow runs scripts/ directly
    without invoking the package entry point).
    """
    if not value:
        return None
    s = str(value).strip()
    try:
        normalised = s.replace("Z", "+00:00") if s.endswith("Z") else s
        return datetime.fromisoformat(normalised).date()
    except ValueError:
        return None


def _stamp_from_envelope(
    head_doc: dict, *, today: date, max_stamp_age_days: int,
) -> tuple[str | None, str | None, int | None, bool]:
    """Extract the lifecycle.promotedAt/promotedBy stamp from an envelope.

    Returns (promoted_at, promoted_by, stamp_age_days, stamp_ok).
    ``stamp_ok`` is True iff both fields exist AND the age in days is
    within ``[0, max_stamp_age_days]``.
    """
    lifecycle = head_doc.get("lifecycle") or {}
    if not isinstance(lifecycle, dict):
        return (None, None, None, False)
    promoted_at = lifecycle.get("promotedAt")
    promoted_by = lifecycle.get("promotedBy")
    parsed = _parse_iso_date(promoted_at)
    if parsed is None:
        return (
            str(promoted_at) if promoted_at else None,
            str(promoted_by) if promoted_by else None,
            None,
            False,
        )
    age_days = (today - parsed).days
    stamp_ok = (
        promoted_by is not None
        and str(promoted_by).strip() != ""
        and 0 <= age_days <= max_stamp_age_days
    )
    return (
        parsed.isoformat(),
        str(promoted_by) if promoted_by else None,
        age_days,
        stamp_ok,
    )


def detect_promotions(
    base: str, head: str, cwd: Path,
    *,
    today: date | None = None,
    max_stamp_age_days: int = DEFAULT_MAX_STAMP_AGE_DAYS,
) -> list[Promotion]:
    today = today or date.today()
    promotions: list[Promotion] = []
    for path in _changed_files(base, head, cwd):
        head_text = _read_at_rev(head, path, cwd)
        head_doc = _parse_envelope(head_text, path, head)
        if head_doc is None:
            continue
        head_status = str(head_doc.get("status", "")).strip().lower()
        if head_status != PRODUCTION:
            continue

        base_text = _read_at_rev(base, path, cwd)
        base_doc = _parse_envelope(base_text, path, base)
        base_status = (
            str(base_doc.get("status", "")).strip().lower()
            if base_doc is not None
            else "(new file)"
        )

        if base_status == PRODUCTION:
            continue

        rule_id = str(head_doc.get("id", "(unknown)"))
        promoted_at, promoted_by, stamp_age, stamp_ok = _stamp_from_envelope(
            head_doc, today=today, max_stamp_age_days=max_stamp_age_days,
        )
        promotions.append(
            Promotion(
                path=path,
                rule_id=rule_id,
                from_status=base_status or "(missing)",
                to_status=PRODUCTION,
                promoted_at=promoted_at,
                promoted_by=promoted_by,
                stamp_age_days=stamp_age,
                stamp_ok=stamp_ok,
            )
        )
    return promotions


def gfm_cell(value: object) -> str:
    """Escape a value for a GitHub-Flavored-Markdown table cell.

    Local copy kept self-contained: this is a standalone script run as a
    subprocess (``python scripts/detect_production_promotions.py``) where the
    ``contentops`` package is not guaranteed to be importable. Mirrors
    ``contentops.utils.markdown.gfm_cell``.
    """
    text = "" if value is None else str(value)
    return text.replace("\\", "\\\\").replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def render_markdown(promotions: list[Promotion]) -> str:
    if not promotions:
        return "No production promotions in this PR.\n"
    lines = [
        "### Production promotions detected",
        "",
        "The following detection envelopes are being promoted to `production` in this PR. Code Owners must review before merge.",
        "",
        "Each row reports whether the envelope carries a fresh `lifecycle.promotedAt` stamp written by `contentops lifecycle promote`. A missing or stale stamp means the promotion bypassed the CLI gate — flag this for review or re-run `contentops lifecycle promote <rule-id>` to write the stamp legitimately.",
        "",
        "| File | Rule ID | From | To | Stamp | Promoted by |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for p in sorted(promotions, key=lambda x: x.path):
        if p.stamp_ok:
            stamp_cell = f"✓ {p.promoted_at} ({p.stamp_age_days}d)"
        elif p.promoted_at is None:
            stamp_cell = "✗ missing"
        elif p.stamp_age_days is None:
            stamp_cell = f"✗ unparseable ({p.promoted_at!r})"
        else:
            stamp_cell = f"✗ stale ({p.stamp_age_days}d > 30d)"
        by_cell = gfm_cell(p.promoted_by) if p.promoted_by else "—"
        lines.append(
            f"| `{gfm_cell(p.path)}` | `{gfm_cell(p.rule_id)}` | "
            f"`{gfm_cell(p.from_status)}` | `{gfm_cell(p.to_status)}` | "
            f"{stamp_cell} | `{by_cell}` |"
        )
    lines.append("")
    return "\n".join(lines)


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Detect detection-rule status promotions to production between two git revisions.",
    )
    parser.add_argument("--base", required=True, help="Base git revision (e.g. origin/main).")
    parser.add_argument("--head", default="HEAD", help="Head git revision (default: HEAD).")
    parser.add_argument(
        "--out",
        default="-",
        help="Output path for the Markdown report; '-' writes to stdout (default).",
    )
    parser.add_argument("--repo", default=".", help="Repository root (default: cwd).")
    parser.add_argument(
        "--max-stamp-age-days",
        type=int,
        default=DEFAULT_MAX_STAMP_AGE_DAYS,
        help=(
            "Maximum age (in days) of the lifecycle.promotedAt stamp before a "
            "promotion is rejected as stale. Default: 30."
        ),
    )
    parser.add_argument(
        "--no-gate",
        action="store_true",
        help=(
            "Legacy advisory-only mode: never exit non-zero, just emit the "
            "Markdown report. Use only for the doc-comment workflow where "
            "the script's job is to flag promotions for human review."
        ),
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    args = _parse_args(argv)
    cwd = Path(args.repo).resolve()
    promotions = detect_promotions(
        args.base, args.head, cwd,
        max_stamp_age_days=args.max_stamp_age_days,
    )
    markdown = render_markdown(promotions)
    if args.out == "-":
        sys.stdout.write(markdown)
    else:
        Path(args.out).write_text(markdown, encoding="utf-8")

    # Gate: exit 1 when any detected promotion lacks a fresh stamp.
    if args.no_gate:
        return 0
    unstamped = [p for p in promotions if not p.stamp_ok]
    if unstamped:
        LOG.error(
            "rejecting %d promotion(s) without a fresh lifecycle.promotedAt "
            "stamp: %s",
            len(unstamped),
            ", ".join(p.rule_id for p in unstamped),
        )
        LOG.error(
            "Run `contentops lifecycle promote <rule-id>` to stamp the "
            "envelope through the CLI gate."
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
