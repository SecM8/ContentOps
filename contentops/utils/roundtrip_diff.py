# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Asset-agnostic round-trip diff helpers.

Used by both the Defender (`contentops/defender_roundtrip.py`) and
Sentinel (`contentops/sentinel_roundtrip.py`) post-apply diagnostics.
Both engines share the same problem shape: when the post-apply GET
returns a body whose canonical projection differs from the pre-PUT
hash, we want a field-by-field report of what diverged.

Pure functions, no I/O. The CLI wrappers in
``contentops/cli/commands/diagnostics.py`` (``defender-roundtrip-diff``
and ``sentinel-roundtrip-diff``) wire these to a live remote fetch.

Single source of truth -- the previous duplication risk (separate
``diff_bodies`` per engine) is the same anti-drift pattern PR #138
caught with ``KQL_FIELDS_BY_ASSET``. Keep new round-trip helpers
HERE rather than per-engine modules.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any


def _get_path(body: dict[str, Any], dotted: str) -> Any:
    """Resolve a dotted path; returns None on miss. Mirrors _verify._get_path."""
    cur: Any = body
    for segment in dotted.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(segment)
    return cur


def _canonical(value: Any) -> str:
    """Canonical JSON of a value -- matches compute_content_hash's projection."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _short_repr(value: Any, *, max_len: int = 240) -> str:
    """Truncated stable repr for display. Strings show repr() (escapes
    whitespace); dicts/lists show canonical JSON; scalars use repr."""
    if isinstance(value, str):
        s = repr(value)
    elif isinstance(value, (dict, list)):
        s = _canonical(value)
    else:
        s = repr(value)
    if len(s) > max_len:
        s = s[: max_len - 3] + "..."
    return s


@dataclass(frozen=True)
class FieldDiff:
    """One field's pre/post values + verdict."""

    field: str           # dotted path, e.g. "schedule" or "alertTemplate.severity"
    differs: bool        # True if local and remote diverge under the canonical projection
    local_repr: str
    remote_repr: str


def diff_bodies(
    local: dict[str, Any],
    remote: dict[str, Any],
    fields: list[str],
) -> list[FieldDiff]:
    """Compare ``local`` and ``remote`` over each ``fields`` path.

    Returns one :class:`FieldDiff` per path, in the order given. A
    diff is determined by canonical-JSON equality -- the same
    projection ``compute_content_hash`` uses -- so this never reports
    spurious differences from dict ordering / whitespace.
    """
    out: list[FieldDiff] = []
    for field in fields:
        lv = _get_path(local, field)
        rv = _get_path(remote, field)
        differs = _canonical(lv) != _canonical(rv)
        out.append(FieldDiff(
            field=field,
            differs=differs,
            local_repr=_short_repr(lv),
            remote_repr=_short_repr(rv),
        ))
    return out


def render_diff(
    diffs: list[FieldDiff],
    *,
    envelope_id: str,
    display_name: str | None = None,
    remote_id: str | None = None,
    remote_id_label: str = "Remote ID",
    fix_hint_module: str | None = None,
) -> str:
    """Format a list of FieldDiffs as a human-readable report.

    ``remote_id`` / ``remote_id_label`` let each engine label its
    remote identifier appropriately ("Graph ID" for Defender, "ARM
    name" for Sentinel). ``fix_hint_module`` -- if provided -- is
    woven into the per-diff fix hints so operators see the right
    file path to edit.
    """
    lines: list[str] = []
    lines.append(f"Envelope: {envelope_id}")
    if display_name:
        lines.append(f"Display:  {display_name}")
    if remote_id:
        lines.append(f"{remote_id_label}: {remote_id}")
    lines.append("")
    differing = [d for d in diffs if d.differs]
    for d in diffs:
        marker = "[DIFF]" if d.differs else "[OK]  "
        lines.append(f"  {marker} {d.field}")
        if d.differs:
            lines.append(f"    local : {d.local_repr}")
            lines.append(f"    remote: {d.remote_repr}")
    lines.append("")
    if not differing:
        lines.append("No differences in projected fields -- round-trip OK.")
    else:
        lines.append(
            f"{len(differing)} of {len(diffs)} field(s) differ. To fix:"
        )
        module_hint = fix_hint_module or "the relevant handler module"
        lines.append(
            f"  * If the field is server-normalised (e.g. ISO duration, "
            f"whitespace), drop it from _HASHED_FIELDS in {module_hint}."
        )
        lines.append(
            "  * If both sides should agree but don't, add a "
            "canonicalisation step in to_envelope (collect-time) or "
            "the body-builder (apply-time)."
        )
    return "\n".join(lines) + "\n"


__all__ = ["FieldDiff", "diff_bodies", "render_diff"]
