# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Content-aware diff between two `contentops collect` archive snapshots (F12).

`git diff` between two collect outputs surfaces every file rename
and reordering as noise. F12 indexes archive contents by
`(asset_kind, envelope_id)` and compares the YAML payloads
directly, so the diff is "what content changed" rather than
"what filenames changed."

Closes G23. Pairs with F10 (`pipeline restore`) — both consume
the same archive shape.
"""

from __future__ import annotations

import hashlib
import json
import tarfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterator

import yaml


class SnapshotDiffError(RuntimeError):
    """Raised when an archive can't be read or has the wrong shape."""


@dataclass(frozen=True)
class IndexedAsset:
    """One asset extracted from a snapshot archive."""
    asset: str          # e.g. 'sentinel_analytic'
    envelope_id: str
    payload_hash: str   # SHA-256 of the canonical-JSON payload
    member_path: str    # original path inside the archive (informational)


@dataclass
class SnapshotDiffReport:
    archive_a: str
    archive_b: str
    created: list[IndexedAsset] = field(default_factory=list)   # in B not A
    deleted: list[IndexedAsset] = field(default_factory=list)   # in A not B
    updated: list[tuple[IndexedAsset, IndexedAsset]] = field(default_factory=list)
    unchanged: int = 0

    def has_changes(self) -> bool:
        return bool(self.created or self.deleted or self.updated)

    @property
    def total_a(self) -> int:
        return self.unchanged + len(self.deleted) + len(self.updated)

    @property
    def total_b(self) -> int:
        return self.unchanged + len(self.created) + len(self.updated)


# ---------------------------------------------------------------------------
# Archive indexing
# ---------------------------------------------------------------------------


def _payload_hash(payload: object) -> str:
    """Deterministic SHA-256 of a canonical-JSON payload.

    Uses sorted keys + no whitespace separators so two payloads
    that differ only in key ordering produce the same hash.
    """
    s = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _iter_yaml_members(archive: Path) -> Iterator[tuple[str, bytes]]:
    """Yield (member_name, raw_bytes) for each YAML in the archive."""
    with tarfile.open(archive, mode="r:gz") as tar:
        for member in tar.getmembers():
            if not member.isfile():
                continue
            if not member.name.endswith((".yml", ".yaml")):
                continue
            f = tar.extractfile(member)
            if f is None:
                continue
            yield member.name, f.read()


def index_archive(archive: Path) -> dict[tuple[str, str], IndexedAsset]:
    """Index every YAML envelope in the archive by (asset, envelope_id).

    Returns the mapping; later lookups are O(1). Asset and id come
    from the YAML envelope itself, not the file path — so a
    rename-only diff produces zero changes.
    """
    if not archive.is_file():
        raise SnapshotDiffError(f"archive not found: {archive}")
    if not str(archive).endswith((".tar.gz", ".tgz")):
        raise SnapshotDiffError(
            f"unrecognised archive extension: {archive} "
            "(expected .tar.gz / .tgz from `contentops collect`)"
        )

    out: dict[tuple[str, str], IndexedAsset] = {}
    for name, body in _iter_yaml_members(archive):
        try:
            raw = yaml.safe_load(body.decode("utf-8"))
        except yaml.YAMLError:
            continue
        if not isinstance(raw, dict):
            continue
        envelope_id = str(raw.get("id") or "")
        if not envelope_id:
            continue
        # v2 carries `asset:`; v1 carries `platform:` (sentinel/defender).
        asset = str(raw.get("asset") or "")
        platform = str(raw.get("platform") or "")
        if not asset:
            if platform == "sentinel":
                asset = "sentinel_analytic"
            elif platform == "defender":
                asset = "defender_custom_detection"
            else:
                continue
        # Payload key: `payload:` (v2) or `<platform>:` (v1).
        payload = raw.get("payload")
        if payload is None and platform:
            payload = raw.get(platform)
        out[(asset, envelope_id)] = IndexedAsset(
            asset=asset,
            envelope_id=envelope_id,
            payload_hash=_payload_hash(payload),
            member_path=name,
        )
    return out


# ---------------------------------------------------------------------------
# Diff
# ---------------------------------------------------------------------------


def diff_archives(archive_a: Path, archive_b: Path) -> SnapshotDiffReport:
    """Compute a content-aware diff between two snapshot archives.

    Asset matching is by ``(asset_kind, envelope_id)`` — same key
    used by ``contentops drift``, so a renamed file with unchanged
    content reports as `unchanged`.
    """
    idx_a = index_archive(archive_a)
    idx_b = index_archive(archive_b)
    keys_a = set(idx_a.keys())
    keys_b = set(idx_b.keys())

    report = SnapshotDiffReport(
        archive_a=str(archive_a), archive_b=str(archive_b),
    )
    for k in sorted(keys_b - keys_a):
        report.created.append(idx_b[k])
    for k in sorted(keys_a - keys_b):
        report.deleted.append(idx_a[k])
    for k in sorted(keys_a & keys_b):
        a = idx_a[k]
        b = idx_b[k]
        if a.payload_hash == b.payload_hash:
            report.unchanged += 1
        else:
            report.updated.append((a, b))
    return report


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def render_markdown(report: SnapshotDiffReport, *, asset: str | None = None) -> str:
    """Render a Markdown summary suitable for a PR body.

    `asset` filter restricts the output to one asset kind (the
    counts in the summary line still reflect the full report).
    """
    lines: list[str] = []
    lines.append("# Snapshot diff")
    lines.append("")
    lines.append(f"- **A:** {report.archive_a} ({report.total_a} envelopes)")
    lines.append(f"- **B:** {report.archive_b} ({report.total_b} envelopes)")
    lines.append("")
    lines.append(
        f"**Summary:** created {len(report.created)}, "
        f"updated {len(report.updated)}, "
        f"deleted {len(report.deleted)}, "
        f"unchanged {report.unchanged}."
    )
    lines.append("")

    def _filter(items: list[IndexedAsset]) -> list[IndexedAsset]:
        return [x for x in items if asset is None or x.asset == asset]

    def _filter_pairs(items):
        return [(a, b) for a, b in items if asset is None or a.asset == asset]

    created = _filter(report.created)
    updated = _filter_pairs(report.updated)
    deleted = _filter(report.deleted)

    if created:
        lines.append(f"## Created ({len(created)})")
        for c in created:
            lines.append(f"- `{c.asset}` `{c.envelope_id}` (in `{c.member_path}`)")
        lines.append("")
    if updated:
        lines.append(f"## Updated ({len(updated)})")
        for a, b in updated:
            lines.append(
                f"- `{a.asset}` `{a.envelope_id}`: "
                f"{a.payload_hash[:8]} -> {b.payload_hash[:8]}"
            )
        lines.append("")
    if deleted:
        lines.append(f"## Deleted ({len(deleted)})")
        for d in deleted:
            lines.append(f"- `{d.asset}` `{d.envelope_id}` (was in `{d.member_path}`)")
        lines.append("")
    return "\n".join(lines)


def render_json(report: SnapshotDiffReport) -> str:
    payload = {
        "archive_a": report.archive_a,
        "archive_b": report.archive_b,
        "summary": {
            "created": len(report.created),
            "updated": len(report.updated),
            "deleted": len(report.deleted),
            "unchanged": report.unchanged,
            "total_a": report.total_a,
            "total_b": report.total_b,
        },
        "created": [asdict(c) for c in report.created],
        "updated": [
            {"asset": a.asset, "envelope_id": a.envelope_id,
             "from_hash": a.payload_hash, "to_hash": b.payload_hash}
            for a, b in report.updated
        ],
        "deleted": [asdict(d) for d in report.deleted],
    }
    return json.dumps(payload, indent=2) + "\n"


__all__ = [
    "SnapshotDiffError",
    "IndexedAsset", "SnapshotDiffReport",
    "index_archive", "diff_archives",
    "render_markdown", "render_json",
]
