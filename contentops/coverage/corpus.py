# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""One walk over the detection corpus, one scope, for every coverage number.

The heatmap, gaps report, badge, Navigator repo axis, inventory report and
portfolio footer all load detections through :func:`load_corpus` and count
coverage from :meth:`Corpus.covered`, so a published number can only differ
from another when its scope differs -- and the scope is printed with it.

Default scope (:class:`CoverageScope`): **enabled** detections with
``status: production``; Sentinel hunting queries excluded (they never raise
alerts). Disabled and deprecated rules never count. ``--include-non-production``
adds experimental/test rules; ``--include-hunting`` adds hunting queries.

Loading is lenient where coverage needs it: a file whose metadata fails
strict validation (e.g. a bad ``references`` URL) is re-read with the
metadata reduced to ``arm_name`` -- so the detection still counts and its
ATT&CK tags are salvaged from the raw block -- and the error is kept in
``metadata_error`` for the report.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping

import yaml
from pydantic import ValidationError

from contentops.core.asset import DETECTION_ASSETS, Asset, payload_display_name
from contentops.core.discovery import discover_assets
from contentops.core.envelope import EnvelopeV2, parse_envelope
from contentops.core.handler import LoadedAsset
from contentops.coverage.extract import ExtractedCoverage, extract_mitre
from contentops.coverage.matrix import AttackMatrix, load_matrix

# Exclusion reasons, in the order they are checked.
EXCLUDED_DISABLED = "disabled"
EXCLUDED_HUNTING = "hunting"
EXCLUDED_NON_PRODUCTION = "non_production"


@dataclass(frozen=True)
class CoverageScope:
    """Which detections count toward coverage.

    Enabled, non-deprecated rules only, always. ``production_only`` limits
    the count to ``status: production``; ``include_hunting`` adds Sentinel
    hunting queries.
    """

    production_only: bool = True
    include_hunting: bool = False

    @classmethod
    def from_flags(
        cls, *, include_non_production: bool = False, include_hunting: bool = False,
    ) -> CoverageScope:
        return cls(production_only=not include_non_production,
                   include_hunting=include_hunting)

    def exclusion_reason(self, *, asset: Asset, status: str, enabled: bool) -> str | None:
        if status == "deprecated" or not enabled:
            return EXCLUDED_DISABLED
        if asset is Asset.SENTINEL_HUNTING and not self.include_hunting:
            return EXCLUDED_HUNTING
        if self.production_only and status != "production":
            return EXCLUDED_NON_PRODUCTION
        return None

    @property
    def label(self) -> str:
        """Short ASCII description, e.g. ``enabled production detections
        (hunting queries excluded)``."""
        who = "enabled production detections" if self.production_only else (
            "enabled detections of any status"
        )
        hunting = "included" if self.include_hunting else "excluded"
        return f"{who} (hunting queries {hunting})"


DEFAULT_SCOPE = CoverageScope()


def is_detection_enabled(asset: Asset, payload: Mapping[str, Any] | None) -> bool:
    """Whether the rule runs: Sentinel ``enabled`` (default true), Defender
    ``status``/``isEnabled`` (``autoDisabled`` counts as disabled). Hunting
    queries have no switch and are always enabled."""
    payload = payload or {}
    if asset is Asset.SENTINEL_ANALYTIC:
        return payload.get("enabled", True) is not False
    if asset is Asset.DEFENDER_CUSTOM_DETECTION:
        from contentops.defender.rule_status import is_enabled

        return is_enabled(dict(payload))
    return True


@dataclass(frozen=True)
class CorpusEntry:
    """One detection, parsed once, with its ATT&CK attribution and scope."""

    path: Path
    envelope: EnvelopeV2
    payload: Mapping[str, Any]
    raw: Mapping[str, Any]
    status: str
    enabled: bool
    display_name: str
    cohort: str | None
    mitre: ExtractedCoverage
    metadata_error: str | None = None
    exclusion: str | None = None

    @property
    def id(self) -> str:
        return self.envelope.id

    @property
    def asset(self) -> Asset:
        return self.envelope.asset

    @property
    def in_scope(self) -> bool:
        return self.exclusion is None

    @property
    def is_production(self) -> bool:
        return self.status == "production"

    def loaded(self) -> LoadedAsset:
        return LoadedAsset(path=self.path, envelope=self.envelope,
                           payload=dict(self.payload), raw=dict(self.raw))


@dataclass(frozen=True)
class CoveredIds:
    """What a set of detections covers in the current matrix.

    ``techniques`` are parent ids (a sub-technique also covers its parent);
    ``sub_techniques`` are only the sub-techniques named directly.
    """

    tactics: frozenset[str]
    techniques: frozenset[str]
    sub_techniques: frozenset[str]

    @property
    def ids(self) -> frozenset[str]:
        """Parents and sub-techniques together (gap matching set)."""
        return self.techniques | self.sub_techniques


@dataclass(frozen=True)
class CorpusDiagnostics:
    """Data-quality findings over the in-scope detections."""

    invalid_ids: tuple[tuple[str, str], ...] = ()       # (detection id, raw value)
    unknown_ids: tuple[str, ...] = ()
    deprecated_ids: tuple[str, ...] = ()
    remapped_ids: tuple[tuple[str, str], ...] = ()       # (retired, current)
    outside_tactics: tuple[str, ...] = ()                # counted, but under no claimed tactic
    metadata_errors: tuple[tuple[str, str], ...] = ()    # (detection id, error)

    def __bool__(self) -> bool:
        return any((self.invalid_ids, self.unknown_ids, self.deprecated_ids,
                    self.remapped_ids, self.outside_tactics, self.metadata_errors))


@dataclass(frozen=True)
class Corpus:
    root: Path
    scope: CoverageScope
    matrix: AttackMatrix
    entries: tuple[CorpusEntry, ...]
    load_errors: tuple[tuple[Path, str], ...] = ()

    def in_scope(self) -> tuple[CorpusEntry, ...]:
        return tuple(e for e in self.entries if e.in_scope)

    def excluded_counts(self) -> dict[str, int]:
        counts = {EXCLUDED_DISABLED: 0, EXCLUDED_HUNTING: 0, EXCLUDED_NON_PRODUCTION: 0}
        for entry in self.entries:
            if entry.exclusion is not None:
                counts[entry.exclusion] = counts.get(entry.exclusion, 0) + 1
        return counts

    def with_scope(self, scope: CoverageScope) -> Corpus:
        """The same detections re-scoped (no second walk)."""
        entries = tuple(
            replace(e, exclusion=scope.exclusion_reason(
                asset=e.asset, status=e.status, enabled=e.enabled))
            for e in self.entries
        )
        return replace(self, scope=scope, entries=entries)

    def filter(self, predicate: Callable[[CorpusEntry], bool]) -> Corpus:
        return replace(self, entries=tuple(e for e in self.entries if predicate(e)))

    def covered(self) -> CoveredIds:
        return covered_ids(self.in_scope(), self.matrix)

    def diagnostics(self) -> CorpusDiagnostics:
        invalid: list[tuple[str, str]] = []
        unknown: set[str] = set()
        deprecated: set[str] = set()
        remapped: set[tuple[str, str]] = set()
        outside: set[str] = set()
        errors: list[tuple[str, str]] = []
        for entry in self.in_scope():
            mitre = entry.mitre
            invalid.extend((entry.id, value) for value in mitre.invalid_ids)
            unknown.update(mitre.unknown_ids)
            deprecated.update(mitre.deprecated_ids)
            remapped.update(mitre.remapped_ids)
            outside.update(
                t for t in mitre.techniques_without_tactic if self.matrix.is_current(t)
            )
            if entry.metadata_error:
                errors.append((entry.id, entry.metadata_error))
        return CorpusDiagnostics(
            invalid_ids=tuple(invalid),
            unknown_ids=tuple(sorted(unknown)),
            deprecated_ids=tuple(sorted(deprecated)),
            remapped_ids=tuple(sorted(remapped)),
            outside_tactics=tuple(sorted(outside)),
            metadata_errors=tuple(errors),
        )


def covered_ids(entries: Iterable[CorpusEntry], matrix: AttackMatrix) -> CoveredIds:
    """Tactics / parent techniques / sub-techniques covered by ``entries``."""
    tactics: set[str] = set()
    parents: set[str] = set()
    subs: set[str] = set()
    for entry in entries:
        tactics.update(t for t in entry.mitre.tactics if t in matrix.tactics)
        for tid in entry.mitre.counted_techniques:
            parent = tid.split(".", 1)[0]
            if parent in matrix.techniques:
                parents.add(parent)
            if tid in matrix.sub_techniques:
                subs.add(tid)
    return CoveredIds(frozenset(tactics), frozenset(parents), frozenset(subs))


def _short_error(exc: Exception) -> str:
    if isinstance(exc, ValidationError):
        first = exc.errors()[0] if exc.errors() else {}
        loc = ".".join(str(part) for part in first.get("loc", ()))
        msg = first.get("msg", "invalid")
        return f"metadata.{loc}: {msg}" if loc else f"metadata: {msg}"
    return str(exc).splitlines()[0][:200]


def _parse_with_salvage(
    raw: dict[str, Any],
) -> tuple[EnvelopeV2, dict[str, Any], str | None]:
    """``parse_envelope`` that survives strict-metadata failures.

    With all required metadata keys present, ``parse_envelope`` validates
    strictly and raises on any bad field, which would drop the whole file.
    Retry with the metadata reduced to ``arm_name``; the caller still reads
    the ATT&CK tags from the raw block.
    """
    try:
        envelope, payload = parse_envelope(raw)
    except (ValidationError, ValueError, TypeError) as exc:
        metadata = raw.get("metadata")
        if not isinstance(metadata, dict):
            raise
        reduced = {"arm_name": metadata["arm_name"]} if metadata.get("arm_name") else {}
        envelope, payload = parse_envelope({**raw, "metadata": reduced})
        return envelope, payload, _short_error(exc)
    metadata = raw.get("metadata")
    error = None
    if (
        envelope.metadata is None
        and isinstance(metadata, dict)
        and set(metadata) - {"arm_name"}
    ):
        error = "metadata incomplete or invalid (loose parse); ATT&CK tags read from the raw block"
    return envelope, payload, error


def entry_for(
    path: Path,
    raw: dict[str, Any],
    *,
    scope: CoverageScope = DEFAULT_SCOPE,
    matrix: AttackMatrix | None = None,
) -> CorpusEntry | None:
    """Build the :class:`CorpusEntry` for one raw document (``None`` for a
    non-detection asset). Raises when the document is not an envelope."""
    envelope, payload, metadata_error = _parse_with_salvage(raw)
    if envelope.asset not in DETECTION_ASSETS:
        return None
    raw_metadata = raw.get("metadata") if isinstance(raw.get("metadata"), dict) else None
    status = str(raw.get("status") or envelope.status or "").strip().lower()
    enabled = is_detection_enabled(envelope.asset, payload)
    if envelope.metadata is not None:
        cohort = envelope.metadata.cohort
    else:
        value = (raw_metadata or {}).get("cohort")
        cohort = value if isinstance(value, str) and value else None
    return CorpusEntry(
        path=path,
        envelope=envelope,
        payload=payload or {},
        raw=raw,
        status=status,
        enabled=enabled,
        display_name=payload_display_name(payload) or envelope.id,
        cohort=cohort,
        mitre=extract_mitre(envelope, payload, raw_metadata=raw_metadata, matrix=matrix),
        metadata_error=metadata_error,
        exclusion=scope.exclusion_reason(asset=envelope.asset, status=status, enabled=enabled),
    )


def load_corpus(
    root: Path,
    *,
    scope: CoverageScope | None = None,
    matrix: AttackMatrix | None = None,
) -> Corpus:
    """Walk ``root`` once (templates/samples skipped) and return every
    detection-class asset as a :class:`CorpusEntry`.

    Unparseable files are collected in ``load_errors`` rather than raised.
    """
    scope = scope or DEFAULT_SCOPE
    matrix = matrix or load_matrix()
    entries: list[CorpusEntry] = []
    errors: list[tuple[Path, str]] = []
    for path in discover_assets(root):
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
            if not isinstance(raw, dict):
                raise ValueError("not a YAML mapping")
            entry = entry_for(path, raw, scope=scope, matrix=matrix)
        except Exception as exc:  # noqa: BLE001 -- surfaced via load_errors
            errors.append((path, str(exc).splitlines()[0][:200] if str(exc) else type(exc).__name__))
            continue
        if entry is not None:
            entries.append(entry)
    return Corpus(root=root, scope=scope, matrix=matrix,
                  entries=tuple(entries), load_errors=tuple(errors))


__all__ = [
    "DEFAULT_SCOPE",
    "EXCLUDED_DISABLED",
    "EXCLUDED_HUNTING",
    "EXCLUDED_NON_PRODUCTION",
    "Corpus",
    "CorpusDiagnostics",
    "CorpusEntry",
    "CoverageScope",
    "CoveredIds",
    "covered_ids",
    "entry_for",
    "is_detection_enabled",
    "load_corpus",
]
