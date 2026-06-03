# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Drift detection — fetch remote state and emit YAML for new/changed assets.

This is the data layer the `contentops drift` CLI command builds on.

A handler opts in to drift detection by implementing two methods on top of
the standard Handler protocol:

    list_remote() -> list[dict]
        Returns the raw API objects for every asset of this kind in the
        remote tenant.

    to_envelope(remote: dict) -> dict | None
        Converts one raw remote object into a v2 envelope dict (the same
        shape that lives in YAML on disk). Returning None signals the
        item should be skipped (e.g. it's a built-in / Microsoft-shipped
        rule that we don't want to round-trip into git).

The drift engine then writes envelopes for any asset that:
  * exists remote but not in local YAML (NEW)
  * exists in both but the YAML payload differs from the exported one
    (CHANGED)
"""

from __future__ import annotations

import logging
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Protocol, runtime_checkable

import yaml

from contentops.core.asset import Asset
from contentops.core.discovery import discover_assets, load_asset
from contentops.utils.yaml_io import dump_envelope_yaml

logger = logging.getLogger(__name__)


@runtime_checkable
class DriftCapable(Protocol):
    """Optional handler extension for `contentops drift`."""

    asset: Asset

    def list_remote(self) -> list[dict]: ...

    def to_envelope(self, remote: dict) -> dict | None: ...


@dataclass
class DriftEntry:
    asset: Asset
    asset_id: str
    kind: str  # "new" | "changed" | "in-sync" | "error"
    envelope: dict | None = None  # full v2 envelope to write (None for in-sync/error)
    local_path: Path | None = None  # set when kind == "changed"
    # Populated when ``kind == "error"`` — the exception message that
    # blocked drift from checking this asset kind. Operators see a
    # report that distinguishes "checked, no drift" from "couldn't
    # check" instead of the latter silently looking clean.
    error: str | None = None


@dataclass
class DriftReport:
    entries: list[DriftEntry] = field(default_factory=list)

    @property
    def new(self) -> list[DriftEntry]:
        return [e for e in self.entries if e.kind == "new"]

    @property
    def changed(self) -> list[DriftEntry]:
        return [e for e in self.entries if e.kind == "changed"]

    @property
    def in_sync(self) -> list[DriftEntry]:
        return [e for e in self.entries if e.kind == "in-sync"]

    @property
    def errors(self) -> list[DriftEntry]:
        return [e for e in self.entries if e.kind == "error"]

    def has_drift(self) -> bool:
        return bool(self.new) or bool(self.changed)

    def has_errors(self) -> bool:
        return bool(self.errors)


def _local_index(detections_root: Path, asset: Asset) -> dict[str, tuple[Path, dict]]:
    """Map ``key -> (path, payload)`` for every local YAML of ``asset``.

    The ``key`` is the unique remote identifier this envelope deploys
    against. We prefer ``metadata.arm_name`` (Sentinel) /
    ``metadata.graph_id`` (Defender) when set, because those are the
    authoritative remote names returned by ``list_remote()``. If
    neither is present, we fall back to ``envelope.id``.

    Why this matters: a remote slug like ``aad-failed-mfa`` lives at
    ARM resource name ``6babf568-...`` (the GUID). The local envelope
    on disk has ``id: aad-failed-mfa-6babf568`` (slug-disambiguated)
    and ``metadata.arm_name: 6babf568-...``. Without the arm_name
    lookup, drift and prune both compute the remote-side id as
    ``aad-failed-mfa`` (slug from displayName) and the local-side id
    as ``aad-failed-mfa-6babf568`` — they don't match, so the
    surviving rule gets flagged NEW (drift) / ORPHAN (prune).

    Each local envelope is registered under BOTH its arm_name (the
    primary remote-side key) AND its envelope id, so handlers that
    don't populate arm_name yet still find their local match.
    EnvelopeV2 stores arm_name as a top-level attribute (mirrored
    from ``metadata.arm_name``); Defender handlers reuse the same
    field for the Graph rule id.
    """
    out: dict[str, tuple[Path, dict]] = {}
    for path in discover_assets(detections_root):
        try:
            loaded = load_asset(path)
        except Exception as exc:  # noqa: BLE001 — bad YAML doesn't block drift run
            logger.warning("drift: skipping %s: %s", path, exc)
            continue
        if loaded.envelope.asset != asset:
            continue
        entry = (path, loaded.payload)
        # Fallback key: envelope id (handlers w/o arm_name).
        out[loaded.envelope.id] = entry
        # Primary key: the authoritative remote name when known.
        arm_name = loaded.envelope.arm_name
        if arm_name:
            out[str(arm_name)] = entry
    return out


def _payloads_match(local: dict, remote: dict) -> bool:
    """Stable comparison of two payload dicts.

    Normalises strings the same way the YAML dumper does (strips
    per-line trailing whitespace, normalises CRLF). Without this,
    a remote string ending each line in two trailing spaces would
    diff against the on-disk version every time, because PyYAML's
    literal-block scalar style can't represent trailing whitespace
    so the dumper strips it before writing.
    """
    return _normalize(local) == _normalize(remote)


@dataclass(frozen=True)
class FieldDiff:
    """One field-level difference between two payloads.

    ``kind`` is one of ``added`` (key only in remote), ``removed``
    (key only in local), or ``modified`` (different value at the
    same key path). ``local_repr`` / ``remote_repr`` are short
    string renderings — empty for the side that doesn't have the
    key.
    """
    key: str
    kind: str
    local_repr: str
    remote_repr: str


def _short_repr(value: Any, *, max_len: int = 80) -> str:
    s = repr(value)
    if len(s) > max_len:
        s = s[: max_len - 3] + "..."
    return s


def _diff_walk(local: Any, remote: Any, *, prefix: str) -> list[FieldDiff]:
    if local == remote:
        return []
    if isinstance(local, dict) and isinstance(remote, dict):
        out: list[FieldDiff] = []
        for k in sorted(set(local.keys()) | set(remote.keys())):
            sub = f"{prefix}.{k}" if prefix else k
            if k not in local:
                out.append(FieldDiff(sub, "added", "", _short_repr(remote[k])))
            elif k not in remote:
                out.append(FieldDiff(sub, "removed", _short_repr(local[k]), ""))
            else:
                out.extend(_diff_walk(local[k], remote[k], prefix=sub))
        return out
    # Lists / scalars / type mismatches — surface a single modification.
    return [FieldDiff(prefix or "(root)", "modified",
                      _short_repr(local), _short_repr(remote))]


def field_diff(local: Any, remote: Any) -> list[FieldDiff]:
    """Return per-key differences between two payloads.

    Both sides are normalised (same rules as ``_payloads_match``)
    before walking, so trailing-whitespace and CRLF noise doesn't
    show up as a diff. Useful for diagnosing drift entries that
    report ``changed`` without it being obvious which field is
    triggering the comparison.
    """
    return _diff_walk(_normalize(local), _normalize(remote), prefix="")


def _normalize(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _normalize(v) for k, v in sorted(value.items())}
    if isinstance(value, list):
        return [_normalize(v) for v in value]
    if isinstance(value, str):
        if "\r" in value:
            value = value.replace("\r\n", "\n").replace("\r", "\n")
        # Match the dumper's per-line strip — trailing whitespace is
        # non-semantic and PyYAML's literal-block style can't represent
        # it anyway. Single-line strings get the same treatment so a
        # remote ``"text "`` (trailing space) compares equal to the
        # ``"text"`` we've written to disk.
        return "\n".join(
            line.rstrip() for line in value.split("\n")
        ).rstrip("\n")
    return value


def detect_drift(
    handlers: Iterable[DriftCapable],
    detections_root: Path,
) -> DriftReport:
    report = DriftReport()
    for handler in handlers:
        asset = handler.asset
        local = _local_index(detections_root, asset)
        try:
            remote_items = handler.list_remote()
        except Exception as exc:  # noqa: BLE001
            # Don't silently swallow remote-list failures: a transient
            # ARM/Graph 401 / 500 used to log + continue, producing a
            # report that said "no drift" while the asset kind was never
            # actually checked. Surface the failure so the CLI summary
            # and any JSON report show it.
            logger.error("Failed to list remote %s: %s", asset.value, exc)
            report.entries.append(DriftEntry(
                asset=asset, asset_id="*", kind="error", error=str(exc),
            ))
            continue

        # Pair each ``to_envelope`` result with its source remote so we
        # can look the match key up by the authoritative ARM/Graph name
        # rather than only by the slug-based envelope id (which collides
        # on tenants where two rules share a displayName).
        pairs: list[tuple[dict, dict]] = []
        for remote in remote_items:
            env = handler.to_envelope(remote)
            if env is None:
                continue
            pairs.append((env, remote))
        # C-5: ARM list responses are not order-stable. Without an
        # explicit sort the slug-disambiguation step (which runs in
        # input order) can produce different envelope ids for the same
        # tenant snapshot across drift runs. Sort by (envelope.id,
        # remote.name) so repeated runs are deterministic.
        pairs.sort(key=lambda p: (p[0].get("id") or "", p[1].get("name") or ""))
        # Slug-disambiguate the envelope ids so two un-paired colliding
        # remotes get distinct ids on the *output* side. The pre-disambig
        # envelopes preserve the original metadata.arm_name we use for
        # matching below.
        disambiguated = disambiguate_envelope_ids([e for e, _ in pairs])
        for (envelope, remote), env_id_disambig in zip(pairs, [d.get("id") for d in disambiguated]):
            asset_id = env_id_disambig or envelope.get("id")
            if not asset_id:
                continue
            envelope = dict(envelope)
            envelope["id"] = asset_id
            new_payload = envelope.get("payload", {})
            # Look up by the authoritative remote name first
            # (arm_name == remote.name for Sentinel; same field name
            # for Defender graph_id); fall back to the disambiguated
            # envelope id for envelopes that never carried a remote
            # name.
            remote_key = remote.get("name") or remote.get("id") or ""
            match = local.get(str(remote_key)) if remote_key else None
            if match is None:
                match = local.get(asset_id)
            if match is None:
                report.entries.append(DriftEntry(
                    asset=asset, asset_id=asset_id, kind="new", envelope=envelope,
                ))
                continue
            local_path, local_payload = match
            if _payloads_match(local_payload, new_payload):
                report.entries.append(DriftEntry(
                    asset=asset, asset_id=asset_id, kind="in-sync",
                    local_path=local_path,
                ))
            else:
                report.entries.append(DriftEntry(
                    asset=asset, asset_id=asset_id, kind="changed",
                    envelope=envelope, local_path=local_path,
                ))
    return report


def _preserve_local_version(envelope: dict, local_path: Path) -> dict:
    """Keep the on-disk ``version`` when re-importing an existing asset.

    ``version`` is a repo-side, operator-managed field: the remote tenant
    has no notion of it, so a collected envelope only ever carries the
    synthetic ``COLLECT_BASELINE_VERSION`` (see each handler's
    ``to_envelope``). A drift re-import therefore has nothing
    authoritative to say about version and must not touch it — letting
    the baseline win silently rolled back operator version bumps, which
    is how 7 production Defender detections got reset 0.1.1 -> 0.1.0 by
    the nightly drift PR.

    The baseline only applies to genuinely *new* assets (no local file);
    for those, ``write_drift`` never calls this function.
    """
    try:
        local = yaml.safe_load(local_path.read_text(encoding="utf-8"))
    except Exception:
        return envelope
    if not isinstance(local, dict):
        return envelope
    local_version = local.get("version")
    if local_version:
        envelope["version"] = local_version
    return envelope


def _preserve_local_metadata(envelope: dict, local_path: Path) -> dict:
    """Merge the existing file's metadata block into the remote envelope.

    The remote API never returns operator-authored metadata fields
    (description, attackDescription, references, falsePositives, etc.).
    Without this merge, a drift-write would silently strip them.
    """
    try:
        local = yaml.safe_load(local_path.read_text(encoding="utf-8"))
    except Exception:
        return envelope
    if not isinstance(local, dict):
        return envelope
    local_meta = local.get("metadata")
    if not isinstance(local_meta, dict) or not local_meta:
        return envelope
    remote_meta = envelope.get("metadata")
    if isinstance(remote_meta, dict):
        merged = {**local_meta, **remote_meta}
    else:
        merged = local_meta
    envelope["metadata"] = merged
    return envelope


def write_drift(report: DriftReport, out_dir: Path) -> list[Path]:
    """Write `new` and `changed` envelopes to `out_dir/<asset>/<id>.yml`.

    For `changed` entries, also overwrite the existing local file to
    keep the diff localized to one commit-ready place. Operator-authored
    metadata fields are preserved from the existing file.
    """
    written: list[Path] = []
    for entry in report.new + report.changed:
        if entry.envelope is None:
            continue
        if entry.local_path is not None:
            target = entry.local_path
            entry.envelope = _preserve_local_metadata(
                entry.envelope, target,
            )
            entry.envelope = _preserve_local_version(
                entry.envelope, target,
            )
        else:
            target = out_dir / entry.asset.value / f"{entry.asset_id}.yml"
            target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            dump_envelope_yaml(entry.envelope),
            encoding="utf-8",
        )
        written.append(target)
    return written


def disambiguate_envelope_ids(envelopes: list[dict]) -> list[dict]:
    """Resolve slug collisions within a single asset kind.

    If two envelopes from the same asset kind end up with the same
    base slug (e.g. two analytics named "Test"), both are rewritten
    to ``<slug>-<arm8>`` where ``arm8`` is the first 8 alphanumeric
    chars of the originating ARM resource name. The non-colliding
    envelopes pass through unchanged. Idempotent.
    """
    from contentops.utils.slug import disambiguate
    counts: Counter[tuple[str, str]] = Counter(
        (e.get("asset", ""), e.get("id", "")) for e in envelopes if isinstance(e, dict)
    )
    out: list[dict] = []
    for env in envelopes:
        if not isinstance(env, dict):
            continue
        key = (env.get("asset", ""), env.get("id", ""))
        if counts[key] > 1:
            arm_name = ""
            md = env.get("metadata") or {}
            if isinstance(md, dict):
                arm_name = str(md.get("arm_name") or "")
            new_id = disambiguate(env.get("id", ""), arm_name)
            new_env = dict(env)
            new_env["id"] = new_id
            out.append(new_env)
        else:
            out.append(env)
    return out
