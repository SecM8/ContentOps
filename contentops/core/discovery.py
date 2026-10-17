# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Asset discovery — walk `detections/` finding both v1 and v2 envelopes."""

from __future__ import annotations

import json
from collections.abc import Callable, Iterator
from pathlib import Path

import yaml

from contentops.core.asset import Asset
from contentops.core.envelope import EnvelopeV2, parse_envelope
from contentops.core.handler import LoadedAsset


_SKIP_SEGMENTS = ("templates", "samples")

# Control files that live at the detections/ root but are NOT asset
# envelopes — they configure the pipeline, not a detection. Walkers must
# skip them or `parse_envelope` raises on a non-envelope shape and breaks
# lint / plan / discovery. (Operators create these on demand; they're not
# always present.)
_SKIP_FILENAMES = ("dependencies.yml", "drift_suppressions.yml")


def is_skipped_path(path: Path) -> bool:
    parts = {p.lower() for p in path.parts}
    if any(seg in parts for seg in _SKIP_SEGMENTS):
        return True
    return path.name.lower() in _SKIP_FILENAMES


def discover_assets(base: Path) -> list[Path]:
    """Return every YAML file under `base` that is not a template/sample."""
    if not base.is_dir():
        return []
    out: list[Path] = []
    for yml in sorted(base.rglob("*.yml")):
        if not is_skipped_path(yml):
            out.append(yml)
    return out


def load_asset(path: Path) -> LoadedAsset:
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    envelope, payload = parse_envelope(raw)
    if envelope.asset is Asset.SENTINEL_PLAYBOOK:
        _inline_playbook_sidecar(path, payload)
    return LoadedAsset(path=path, envelope=envelope, payload=payload, raw=raw)


def _inline_playbook_sidecar(path: Path, payload: dict) -> None:
    """Replace ``payload.definitionFile`` with the sidecar's JSON as
    ``payload.definition`` (in place, so ``raw["payload"]`` sees it too).

    The on-disk form keeps the Logic App definition in
    ``<id>.workflow.json`` next to the envelope (a designer export,
    verbatim); every handler and comparison works on the inlined form.
    ``split_sidecars`` in the playbook models is the inverse, used by
    the writers. A sidecar name must be a bare file name so an envelope
    can never read outside its own directory.
    """
    if not isinstance(payload, dict):
        return
    sidecar = payload.get("definitionFile")
    if not sidecar:
        return
    if "definition" in payload:
        raise ValueError(
            f"{path}: payload has both `definition` and `definitionFile`; keep one"
        )
    name = str(sidecar)
    if "/" in name or "\\" in name or name in (".", "..") or not name.endswith(".workflow.json"):
        raise ValueError(
            f"{path}: definitionFile {name!r} must be a bare file name ending in "
            ".workflow.json in the same directory"
        )
    sidecar_path = path.parent / name
    if not sidecar_path.is_file():
        raise FileNotFoundError(
            f"{path}: definitionFile {name!r} not found at {sidecar_path}"
        )
    try:
        definition = json.loads(sidecar_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"{sidecar_path}: not valid JSON ({exc})") from exc
    if not isinstance(definition, dict):
        raise ValueError(f"{sidecar_path}: expected a JSON object (the workflow definition)")
    payload.pop("definitionFile", None)
    payload["definition"] = definition


def iter_loaded_assets(
    base: Path,
    *,
    on_error: Callable[[Path, Exception], None] | None = None,
) -> Iterator[LoadedAsset]:
    """Discover and load every asset under ``base``, yielding each LoadedAsset.

    Consolidates the ``for p in discover_assets(base): try: load_asset(p)
    except ...`` loop that recurs across the CLI and reporting modules. A
    file that fails to parse is skipped; when ``on_error`` is given it is
    called as ``on_error(path, exc)`` so the caller can log/echo in its own
    voice (default: silent skip).
    """
    for path in discover_assets(base):
        try:
            yield load_asset(path)
        except Exception as exc:  # noqa: BLE001 — caller decides how to surface
            if on_error is not None:
                on_error(path, exc)


def filter_by_asset(loaded: list[LoadedAsset], asset: Asset) -> list[LoadedAsset]:
    return [la for la in loaded if la.envelope.asset == asset]


__all__ = [
    "discover_assets",
    "load_asset",
    "iter_loaded_assets",
    "filter_by_asset",
    "is_skipped_path",
    "EnvelopeV2",
]
