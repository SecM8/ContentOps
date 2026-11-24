# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Fail CI when a detection envelope changed but its ``version`` field did not.

DESIGN §4 requires reviewers to bump ``version`` on every meaningful
change, but nothing enforced it — so the entire corpus has ``version:
0.0.0`` and the field is dead weight. This script closes the gap: for
every YAML file under ``detections/`` whose content differs from the
merge base, parse the envelope, parse the same envelope at the merge
base, and refuse the change if both sides report the identical version.

Limitations (intentional, to keep CI fast):
  * Pure semver comparison; no ordering check beyond "must differ".
  * Files that are added (no base version) are exempt.
  * Files that are deleted are exempt.
  * Cosmetic-only diffs are exempt: the envelope is YAML-parsed on both
    sides and compared by content (the ``version`` key set aside), so a
    semantically-identical edit (whitespace, key reorder, comment, CRLF)
    does not demand a version bump.

Exit codes:
  0 — every changed file has a bumped version (or is new / deleted).
  1 — at least one file changed without a version bump.
  2 — git plumbing failed (unexpected; surfaces as CI red).
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import yaml

DETECTIONS_ROOT = "detections/"


def _run(*args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout


SIDECAR_SUFFIX = ".workflow.json"


def _changed_files(base_ref: str) -> list[tuple[str, str]]:
    """Changed envelopes as ``(path now, path at the base)``.

    A renamed envelope keeps its base path (``-M``), so a rename plus a
    content edit is compared with the old file instead of passing as new.
    A changed playbook sidecar (``.workflow.json``) counts as a change to
    the envelope that loads it, so editing the Logic App definition also
    demands a bump.
    """
    out = _run("diff", "-M", "--name-status", f"{base_ref}...HEAD", "--", DETECTIONS_ROOT)
    files: set[tuple[str, str]] = set()
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        status, path = parts[0], parts[-1]
        base_path = parts[1] if status[:1] in ("R", "C") and len(parts) >= 3 else path
        if path.endswith((".yml", ".yaml")):
            files.add((path, base_path))
        elif path.endswith(SIDECAR_SUFFIX):
            files.update((env, env) for env in _envelopes_for_sidecar(path))
    return sorted(files)


def _definition_file(yml_path: str, doc: dict | None) -> str:
    """The sidecar an envelope loads: its ``payload.definitionFile`` next to
    it, else ``<envelope stem>.workflow.json``."""
    payload = doc.get("payload") if isinstance(doc, dict) else None
    name = payload.get("definitionFile") if isinstance(payload, dict) else None
    folder = yml_path.rsplit("/", 1)[0] if "/" in yml_path else ""
    if isinstance(name, str) and name:
        return f"{folder}/{name}" if folder else name
    return yml_path.rsplit(".", 1)[0] + SIDECAR_SUFFIX


def _envelopes_for_sidecar(sidecar: str) -> list[str]:
    """Envelopes in the sidecar's folder that load it (working tree).

    The file names need not match: ``contentops new --out custom.yml`` writes
    ``<id>.workflow.json`` and records it as ``definitionFile``. Falls back
    to ``<sidecar stem>.yml`` when no envelope names the sidecar.
    """
    folder = Path(sidecar).parent
    found: list[str] = []
    if folder.is_dir():
        for candidate in sorted([*folder.glob("*.yml"), *folder.glob("*.yaml")]):
            try:
                doc = _parse_doc(candidate.read_text(encoding="utf-8"))
            except (OSError, UnicodeDecodeError):
                continue
            path = candidate.as_posix()
            if _definition_file(path, doc) == sidecar:
                found.append(path)
    return found or [sidecar[: -len(SIDECAR_SUFFIX)] + ".yml"]


def _parse_doc(text: str) -> dict | None:
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError:
        return None
    return doc if isinstance(doc, dict) else None


def _sidecar_text(ref: str | None, yml_path: str, doc: dict | None = None) -> str | None:
    """Content of the playbook sidecar the envelope at ``yml_path`` loads,
    at ``ref`` (None = working tree), or None when there is no sidecar.
    ``doc`` is that envelope parsed at the same ref (for ``definitionFile``)."""
    if not yml_path.endswith((".yml", ".yaml")):
        return None
    sidecar = _definition_file(yml_path, doc)
    if ref is None:
        p = Path(sidecar)
        return p.read_text(encoding="utf-8") if p.exists() else None
    return _file_at_ref(ref, sidecar)


def _requires_bump(head_text: str, base_text: str) -> str | None:
    """Return a failure message if ``head_text`` changed semantically from
    ``base_text`` without a version bump, else ``None``.

    The envelope is YAML-parsed on both sides and the ``version`` key is
    set aside; the remaining bodies are compared by ``dict`` equality,
    which ignores key order, indentation, comments, and line endings. So a
    cosmetic-only edit compares equal and demands no bump. Unparseable
    input is exempt — the validate step owns that failure.
    """
    head_doc = _parse_doc(head_text)
    base_doc = _parse_doc(base_text)
    if head_doc is None or base_doc is None:
        return None
    head_body = {k: v for k, v in head_doc.items() if k != "version"}
    base_body = {k: v for k, v in base_doc.items() if k != "version"}
    if head_body == base_body:
        return None  # semantically identical — cosmetic edit, no bump needed
    head_v = head_doc.get("version")
    base_v = base_doc.get("version")
    if head_v is None or base_v is None:
        return None
    if str(head_v) == str(base_v):
        return f"version unchanged ({head_v}) but content changed"
    return None


def _file_at_ref(ref: str, path: str) -> str | None:
    try:
        return _run("show", f"{ref}:{path}")
    except subprocess.CalledProcessError:
        return None  # File didn't exist at base ref → newly added, exempt.


def main(base_ref: str) -> int:
    try:
        changed = _changed_files(base_ref)
    except subprocess.CalledProcessError as exc:
        print(f"git diff failed: {exc.stderr}", file=sys.stderr)
        return 2

    failures: list[str] = []
    for path, base_path in changed:
        head_text = Path(path).read_text(encoding="utf-8") if Path(path).exists() else None
        if head_text is None:
            continue  # Deletion.
        base_text = _file_at_ref(base_ref, base_path)
        if base_text is None:
            continue  # New file.
        msg = _requires_bump(head_text, base_text)
        if msg is None:
            # Unchanged envelope body: a changed sidecar still needs a bump.
            head_sidecar = _sidecar_text(None, path, _parse_doc(head_text))
            base_sidecar = _sidecar_text(base_ref, base_path, _parse_doc(base_text))
            if head_sidecar is not None and base_sidecar is not None and head_sidecar != base_sidecar:
                head_doc = _parse_doc(head_text)
                base_doc = _parse_doc(base_text)
                if (
                    head_doc is not None and base_doc is not None
                    and str(head_doc.get("version")) == str(base_doc.get("version"))
                ):
                    msg = (
                        f"version unchanged ({head_doc.get('version')}) but the "
                        f"{SIDECAR_SUFFIX} sidecar changed"
                    )
        if msg:
            failures.append(f"{path}: {msg}")

    if failures:
        print("Version-bump check failed:", file=sys.stderr)
        for line in failures:
            print(f"  - {line}", file=sys.stderr)
        print(
            "\nBump the `version` field in each changed envelope before merge.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    base = sys.argv[1] if len(sys.argv) > 1 else "origin/main"
    sys.exit(main(base))
