# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""`pipeline restore <archive>` — inverse of collect/export.

Reads a tar.gz archive whose top-level layout matches what
`contentops collect` produces (``detections/<asset_kind>/<id>.yml``)
and writes the contents back to ``--out`` (default
``detections/``).

Useful for disaster recovery after a destructive `prune` or a
catastrophic git-history rewrite. Idempotent: re-running with the
same archive overwrites the same files.

Conservative by design — refuses to overwrite a non-empty target
without ``--force`` so an analyst doesn't shoot themselves in
the foot.
"""

from __future__ import annotations

import json
import tarfile
from dataclasses import dataclass, field
from pathlib import Path


class RestoreError(RuntimeError):
    """Raised when the archive can't be read, target is non-empty
    without --force, or content is suspect."""


@dataclass
class RestoreReport:
    archive: str
    target: str
    written: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    manifest_present: bool = False
    manifest_assets: int = 0


def _extract_safely(tar: tarfile.TarFile, dest: Path) -> list[str]:
    """Extract the tar's members into ``dest``, refusing path traversal.

    Returns the list of relative paths actually written.
    """
    written: list[str] = []
    dest_resolved = dest.resolve()
    for member in tar.getmembers():
        if not member.isfile():
            continue
        # Defend against ``../`` traversal: resolve the destination
        # path and ensure it's still under dest.
        target = (dest / member.name).resolve()
        try:
            target.relative_to(dest_resolved)
        except ValueError:
            raise RestoreError(
                f"refusing extraction outside target dir: {member.name!r}"
            )
        target.parent.mkdir(parents=True, exist_ok=True)
        f = tar.extractfile(member)
        if f is None:
            continue
        target.write_bytes(f.read())
        written.append(str(target.relative_to(dest_resolved)))
    return written


def _is_yaml_or_manifest(name: str) -> bool:
    return name.endswith((".yml", ".yaml")) or name.endswith("MANIFEST.json")


def restore_from_archive(
    archive: Path,
    *,
    target: Path,
    force: bool = False,
) -> RestoreReport:
    """Extract ``archive`` into ``target`` and report what landed.

    The archive is expected to contain ``detections/`` at its root
    (matching what `contentops collect` produces). A top-level
    ``MANIFEST.json`` is preserved if present and used as an
    advisory cross-check on asset count.
    """
    if not archive.is_file():
        raise RestoreError(f"archive not found: {archive}")
    if not str(archive).endswith((".tar.gz", ".tgz")):
        raise RestoreError(
            f"unrecognised archive extension: {archive} "
            "(expected .tar.gz / .tgz from `contentops collect` output)"
        )

    target.mkdir(parents=True, exist_ok=True)
    if any(target.iterdir()) and not force:
        raise RestoreError(
            f"target {target} is not empty — pass --force to overwrite "
            "(restore preserves files not in the archive; --force only "
            "lets archive contents win where paths overlap)"
        )

    report = RestoreReport(archive=str(archive), target=str(target))
    with tarfile.open(archive, mode="r:gz") as tar:
        # Filter to YAML + MANIFEST only; archive may include other
        # auxiliary files (logs, etc.) we don't want to splat.
        useful = [m for m in tar.getmembers() if _is_yaml_or_manifest(m.name)]
        for m in tar.getmembers():
            if m not in useful and m.isfile():
                report.skipped.append(m.name)
        # Extract the useful subset into the target via a private
        # helper that defends against path traversal.
        sub = tarfile.open(archive, mode="r:gz")
        try:
            # Build a member-set lookup for safety.
            useful_names = {m.name for m in useful}
            for member in sub.getmembers():
                if member.name not in useful_names:
                    continue
                if not member.isfile():
                    continue
                # Reject path traversal.
                resolved = (target / member.name).resolve()
                try:
                    resolved.relative_to(target.resolve())
                except ValueError:
                    raise RestoreError(
                        f"refusing extraction outside target dir: {member.name!r}"
                    )
                resolved.parent.mkdir(parents=True, exist_ok=True)
                f = sub.extractfile(member)
                if f is None:
                    continue
                resolved.write_bytes(f.read())
                report.written.append(str(resolved.relative_to(target.resolve())))
                if member.name.endswith("MANIFEST.json"):
                    report.manifest_present = True
                    try:
                        manifest = json.loads(resolved.read_text(encoding="utf-8"))
                        if isinstance(manifest, dict):
                            report.manifest_assets = int(
                                manifest.get("asset_count")
                                or len(manifest.get("assets") or [])
                                or 0
                            )
                    except Exception:
                        # Manifest is advisory; bad JSON is non-fatal.
                        pass
        finally:
            sub.close()

    return report


__all__ = ["RestoreError", "RestoreReport", "restore_from_archive"]
