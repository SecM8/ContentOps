#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""List detection envelopes missing META002-005 authoring metadata.

Operator assist for the G24 backlog drain. Scans ``detections/`` (or a
path you give), reports every envelope that's missing any of:

  - metadata.description
  - metadata.attackDescription
  - metadata.references (at least one entry)
  - metadata.falsePositives (at least one entry)

By default emits a Markdown checklist suitable for pasting into a tracking
issue. Pass ``--format stubs`` to instead emit a per-rule YAML stub the
operator can copy into the rule's envelope and fill in.

This is intentionally a thin reporting tool. It does NOT auto-author
content — the four fields require human judgement (attack context,
threat-intel references, FP scenarios) and any auto-generated content
would dilute the signal the fields exist to carry. The script's job
is to make the backlog auditable; the human's job is to drain it.

Usage:

    python scripts/list_missing_metadata.py
    python scripts/list_missing_metadata.py --path detections/sentinel_analytic
    python scripts/list_missing_metadata.py --format stubs > backlog-stubs.yml
    python scripts/list_missing_metadata.py --format json --out backlog.json

Exits 0 always (this is a reporting tool, not a CI gate; the gate lives
in ``contentops lint --strict``).
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

import yaml


_FIELDS = ("description", "attackDescription", "references", "falsePositives")


@dataclass
class Missing:
    path: Path
    rule_id: str
    asset_kind: str
    status: str
    missing: list[str] = field(default_factory=list)


def _is_missing(metadata: dict | None, field_name: str) -> bool:
    """Return True if ``field_name`` is absent or empty.

    Strings: empty / whitespace-only counts as missing.
    Lists: empty / not present counts as missing.
    """
    if metadata is None:
        return True
    value = metadata.get(field_name)
    if value is None:
        return True
    if isinstance(value, str):
        return not value.strip()
    if isinstance(value, list):
        return len(value) == 0
    return False


def _scan(root: Path) -> list[Missing]:
    """Walk ``root`` for ``*.yml`` files and report missing fields."""
    out: list[Missing] = []
    for yml in sorted(root.rglob("*.yml")):
        # Skip the templates and samples subtrees the rest of the
        # pipeline already excludes via contentops.core.discovery.
        parts = {p.lower() for p in yml.parts}
        if "templates" in parts or "samples" in parts:
            continue
        try:
            raw = yaml.safe_load(yml.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(raw, dict):
            continue
        rule_id = str(raw.get("id") or yml.stem)
        asset_kind = str(raw.get("asset") or raw.get("platform") or "unknown")
        status = str(raw.get("status") or "unknown")
        metadata = raw.get("metadata") if isinstance(raw.get("metadata"), dict) else None
        missing = [f for f in _FIELDS if _is_missing(metadata, f)]
        if missing:
            out.append(Missing(
                path=yml, rule_id=rule_id, asset_kind=asset_kind,
                status=status, missing=missing,
            ))
    return out


def _render_markdown(items: list[Missing]) -> str:
    """Render the missing-fields list as a Markdown checklist."""
    if not items:
        return "# Metadata backlog\n\nAll detections have META002-005 fields populated. 🎉\n"
    lines: list[str] = [
        "# Metadata authoring backlog (G24)",
        "",
        f"_{len(items)} detection envelope(s) missing one or more of:_",
        "_metadata.description / metadata.attackDescription /_",
        "_metadata.references / metadata.falsePositives_",
        "",
        "Tick each row as the four fields land in the envelope.",
        "Run this script after a batch to see what's left.",
        "",
        "| Status | Rule id | Asset | Missing | Path |",
        "|---|---|---|---|---|",
    ]
    for m in items:
        missing_str = ", ".join(m.missing)
        rel = m.path.as_posix()
        lines.append(
            f"| `{m.status}` | `{m.rule_id}` | `{m.asset_kind}` | "
            f"{missing_str} | `{rel}` |"
        )
    lines.append("")
    return "\n".join(lines)


def _render_stubs(items: list[Missing]) -> str:
    """Render a per-rule YAML stub the operator can paste into the envelope.

    Emits a top-level mapping keyed by rule id; each value is a partial
    metadata block with placeholder strings for the missing fields. The
    operator copies the relevant block into the rule's envelope under
    ``metadata:`` and fills the placeholders.
    """
    if not items:
        return "# All detections have META002-005 fields populated.\n"
    out: dict[str, dict] = {}
    for m in items:
        stub: dict = {}
        if "description" in m.missing:
            stub["description"] = "TODO: one paragraph summarising what this rule detects."
        if "attackDescription" in m.missing:
            stub["attackDescription"] = (
                "TODO: what attackers actually do. SOC analysts read this first on triage."
            )
        if "references" in m.missing:
            stub["references"] = [
                "TODO: https://attack.mitre.org/techniques/T...",
            ]
        if "falsePositives" in m.missing:
            stub["falsePositives"] = [
                "TODO: known FP scenario (e.g. legitimate admin tooling that matches the pattern).",
            ]
        out[m.rule_id] = stub
    header = (
        "# Metadata stubs for the G24 backlog\n"
        "#\n"
        "# Each top-level key is the envelope id of a detection rule that\n"
        "# is missing one or more META002-005 fields. Copy the relevant\n"
        "# block into the rule's envelope under ``metadata:`` and replace\n"
        "# each TODO with real content. Save and re-run this script to\n"
        "# see what's left.\n"
        "#\n"
        "# Authoring guidance: docs/reference/envelope-schema.md\n"
        "\n"
    )
    return header + yaml.safe_dump(out, sort_keys=True, allow_unicode=True)


def _render_json(items: list[Missing]) -> str:
    """Render as JSON for downstream tooling."""
    payload = [
        {
            "path": m.path.as_posix(),
            "rule_id": m.rule_id,
            "asset_kind": m.asset_kind,
            "status": m.status,
            "missing": m.missing,
        }
        for m in items
    ]
    return json.dumps(payload, indent=2)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="List detection envelopes missing META002-005 authoring metadata.",
    )
    parser.add_argument(
        "--path", type=Path, default=Path("detections"),
        help="Root path to scan (default: detections).",
    )
    parser.add_argument(
        "--format", choices=("markdown", "stubs", "json"), default="markdown",
        help="Output format: markdown checklist (default), per-rule YAML stubs, or JSON.",
    )
    parser.add_argument(
        "--out", type=Path, default=None,
        help="Write to this path instead of stdout.",
    )
    args = parser.parse_args()

    if not args.path.is_dir():
        print(f"error: --path is not a directory: {args.path}", file=sys.stderr)
        return 1

    items = _scan(args.path)
    if args.format == "markdown":
        rendered = _render_markdown(items)
    elif args.format == "stubs":
        rendered = _render_stubs(items)
    else:
        rendered = _render_json(items)

    if args.out is not None:
        args.out.write_text(rendered, encoding="utf-8")
        print(f"wrote {args.out}", file=sys.stderr)
    else:
        print(rendered)

    return 0


if __name__ == "__main__":
    sys.exit(main())
