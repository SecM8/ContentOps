# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Remediate PAYLOAD001 lint findings: drop dangling templateVersion lines.

PR #34 introduced the PAYLOAD001 lint rule, which flags Sentinel analytic
payloads that set ``templateVersion`` without ``alertRuleTemplateName``.
ARM rejects those PUTs with HTTP 400 -- the field has no operational
meaning without a template name to anchor it -- so the spec-correct fix
is to remove ``templateVersion`` from the YAML. The apply-time scrub
in ``contentops.handlers.sentinel_analytic`` was already dropping it
before sending to ARM, so production behaviour is unchanged.

This script walks ``detections/`` and rewrites each affected envelope
with the dangling ``templateVersion:`` line removed. The edit is
surgical: only the matched line is deleted, every other byte (KQL
block scalars, comments, line endings) is preserved. After the edit
the file is re-parsed to confirm it is still valid YAML and that
``templateVersion`` is gone from the payload.

Idempotent: running twice produces no further changes.
Always exits 0 -- this is a remediation tool, not a gate.

Usage:
    python scripts/remediate_payload001.py            # apply changes
    python scripts/remediate_payload001.py --path detections
    python scripts/remediate_payload001.py --json-report out.json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from contentops.core.discovery import is_skipped_path  # noqa: E402


# Status codes returned by ``remediate_text``. Kept as plain strings so
# the JSON report and the unit tests share the same vocabulary.
STATUS_REMOVED = "removed"
STATUS_NAME_PRESENT = "name-present"
STATUS_NO_TEMPLATE_VERSION = "no-template-version"
STATUS_NO_PAYLOAD = "no-payload"
STATUS_PARSE_ERROR = "parse-error"
STATUS_NOT_DICT = "not-dict-payload"


@dataclass
class Report:
    scanned: int = 0
    changed: list[str] = field(default_factory=list)
    unchanged: list[str] = field(default_factory=list)
    skipped: list[dict] = field(default_factory=list)


def _payload_key(raw: dict[str, Any]) -> str | None:
    """Return the YAML key under which the API payload is nested.

    V1 envelopes nest the payload under the platform name (``sentinel:``
    or ``defender:``). V2 envelopes nest it under ``payload:``.
    """
    if "asset" in raw:
        return "payload"
    platform = raw.get("platform")
    if isinstance(platform, str) and platform:
        return platform
    return None


def _section_bounds(lines: list[str], key: str) -> tuple[int, int] | None:
    """Return the [start, end) line range of the top-level mapping ``key``.

    ``start`` is the line index *after* the ``key:`` line; ``end`` is the
    first line that begins another top-level entry (or len(lines)).
    Returns None if ``key:`` is not found at column 0.
    """
    start: int | None = None
    anchor = f"{key}:"
    for i, line in enumerate(lines):
        if line.startswith(anchor) and (
            len(line) == len(anchor)
            or line[len(anchor)] in " \r\n\t"
        ):
            start = i + 1
            break
    if start is None:
        return None
    end = len(lines)
    for j in range(start, len(lines)):
        stripped = lines[j].rstrip("\r\n")
        if not stripped.strip():
            continue
        if stripped[0] not in " \t":
            end = j
            break
    return start, end


# Match an indented top-level payload key. Greedy on the value so trailing
# inline comments are preserved into the deleted line (which is fine -- we
# discard the whole line anyway).
_TV_LINE_RE = re.compile(r"^( {2,4})templateVersion:[^\n\r]*(\r?\n)?$")


def remediate_text(text: str) -> tuple[str, str, str | None]:
    """Try to remove a dangling ``templateVersion:`` line from ``text``.

    Returns a tuple ``(new_text, status, detail)``. ``new_text`` equals
    ``text`` for every status except ``"removed"``. ``detail`` carries
    a human-readable note for skip/error statuses.
    """
    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        return text, STATUS_PARSE_ERROR, str(exc)

    if not isinstance(raw, dict):
        return text, STATUS_PARSE_ERROR, "top-level YAML is not a mapping"

    key = _payload_key(raw)
    if key is None:
        return text, STATUS_NO_PAYLOAD, "envelope has neither `asset:` nor `platform:`"

    payload = raw.get(key)
    if not isinstance(payload, dict):
        return text, STATUS_NOT_DICT, f"`{key}:` is not a mapping"

    if not payload.get("templateVersion"):
        return text, STATUS_NO_TEMPLATE_VERSION, None
    if payload.get("alertRuleTemplateName"):
        return text, STATUS_NAME_PRESENT, None

    lines = text.splitlines(keepends=True)
    bounds = _section_bounds(lines, key)
    if bounds is None:
        # The YAML parsed but we couldn't find the section header at the
        # left margin. Refuse to mutate -- something unusual is going on.
        return text, STATUS_PARSE_ERROR, f"section `{key}:` not found at top level"

    start, end = bounds
    target_idx: int | None = None
    for i in range(start, end):
        if _TV_LINE_RE.match(lines[i]):
            target_idx = i
            break
    if target_idx is None:
        # YAML claims the key exists but no flat ``templateVersion:`` line
        # at the expected indent. Could be a flow-style mapping. Skip.
        return text, STATUS_PARSE_ERROR, "templateVersion line not found at expected indent"

    new_lines = lines[:target_idx] + lines[target_idx + 1:]
    new_text = "".join(new_lines)

    # Sanity check: re-parse must succeed and the field must be gone.
    try:
        reparsed = yaml.safe_load(new_text)
    except yaml.YAMLError as exc:
        return text, STATUS_PARSE_ERROR, f"post-edit reparse failed: {exc}"
    if not isinstance(reparsed, dict) or not isinstance(reparsed.get(key), dict):
        return text, STATUS_PARSE_ERROR, "post-edit envelope shape changed"
    if "templateVersion" in reparsed[key]:
        return text, STATUS_PARSE_ERROR, "templateVersion still present after edit"

    return new_text, STATUS_REMOVED, None


def process_file(path: Path, *, write: bool) -> tuple[str, str | None]:
    if is_skipped_path(path):
        return "skipped-template", None
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        return STATUS_PARSE_ERROR, str(exc)

    new_text, status, detail = remediate_text(text)
    if status == STATUS_REMOVED and write and new_text != text:
        path.write_text(new_text, encoding="utf-8", newline="")
    return status, detail


def run(base: Path, *, write: bool) -> Report:
    report = Report()
    if not base.is_dir():
        return report
    for yml in sorted(base.rglob("*.yml")):
        if is_skipped_path(yml):
            continue
        report.scanned += 1
        rel = str(yml.relative_to(base.parent if base.parent.exists() else base))
        status, detail = process_file(yml, write=write)
        if status == STATUS_REMOVED:
            report.changed.append(rel)
        elif status in (STATUS_NO_TEMPLATE_VERSION, STATUS_NAME_PRESENT):
            report.unchanged.append(rel)
        else:
            report.skipped.append({"path": rel, "status": status, "detail": detail or ""})
    return report


def print_summary(report: Report, *, write: bool) -> None:
    mode = "WRITE" if write else "DRY-RUN"
    print(f"=== PAYLOAD001 remediation ({mode}) ===")
    print(f"  scanned:   {report.scanned}")
    print(f"  changed:   {len(report.changed)}")
    print(f"  unchanged: {len(report.unchanged)}")
    print(f"  skipped:   {len(report.skipped)}")
    if report.changed:
        for p in report.changed[:10]:
            print(f"    - {p}")
        if len(report.changed) > 10:
            print(f"    ... and {len(report.changed) - 10} more")
    if report.skipped:
        print("  skipped detail:")
        for s in report.skipped[:10]:
            print(f"    ! {s['path']}: {s['status']} -- {s['detail'][:120]}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--path", type=Path, default=REPO_ROOT / "detections",
        help="Base directory to scan (default: detections/)",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Report what would change without writing files.",
    )
    parser.add_argument(
        "--json-report", type=Path, default=None,
        help="Optional path to write a machine-readable JSON report.",
    )
    args = parser.parse_args(argv)

    write = not args.dry_run
    report = run(args.path, write=write)
    print_summary(report, write=write)

    if args.json_report is not None:
        args.json_report.parent.mkdir(parents=True, exist_ok=True)
        args.json_report.write_text(
            json.dumps(asdict(report), indent=2, sort_keys=True),
            encoding="utf-8",
        )
        print(f"  JSON report: {args.json_report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
