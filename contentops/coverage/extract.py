# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Per-detection MITRE ATT&CK extractor -- the only one coverage uses.

:func:`extract_mitre` reads one detection and returns an
:class:`ExtractedCoverage`. Every coverage surface (heatmap, gaps, badge,
Navigator layer, report, portfolio) goes through it, so they agree on what
a rule covers.

Sources, unioned:

1. ``envelope.metadata`` (authored metadata). When strict metadata
   validation failed (a missing ``runbookUrl``, one bad reference URL),
   the envelope carries no metadata; pass the raw ``metadata`` mapping as
   ``raw_metadata`` and its ``tactics`` / ``techniques`` / ``severity``
   are still read -- hand-authored ATT&CK tags never silently vanish.
2. The platform-native payload fields:

   * ``sentinel_analytic`` / ``sentinel_hunting``: ``tactics``,
     ``techniques`` and ``subTechniques`` (Sentinel stores sub-techniques
     in their own field); ``severity`` (analytics only).
   * ``defender_custom_detection``: ``detectionAction.alertTemplate``
     ``mitreTechniques``, ``severity``, and ``category`` -- used as the
     rule's tactic when it names one.

Normalisation:

* Technique ids are stripped and upper-cased (``" t1087"`` -> ``T1087``)
  and must match ``T####`` / ``T####.###``; anything else lands in
  ``invalid_ids`` and is never rendered as an ATT&CK id.
* Ids MITRE revoked are replaced by their successor (``remapped_ids``);
  deprecated and unknown ids are reported but never counted.
* Tactics are the rule's claimed tactics (metadata + payload; Defender's
  category). Only a rule that claims none gets tactics inferred from its
  techniques (``tactics_inferred``).
* A technique is attributed to a tactic only when the ATT&CK matrix says
  it belongs there (``tactic_techniques``). Techniques outside every
  claimed tactic still count for technique-level coverage and are listed
  in ``techniques_without_tactic``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Iterable, Mapping

from contentops.core.asset import Asset
from contentops.core.envelope import EnvelopeV2
from contentops.coverage.matrix import (
    ALL_TACTICS,
    AttackMatrix,
    load_matrix,
    normalise_tactic,
    normalise_technique_id,
)

if TYPE_CHECKING:
    from contentops.core.handler import LoadedAsset

# Historical names, kept for importers.
_CANONICAL_TACTICS: frozenset[str] = frozenset(ALL_TACTICS)

_CANONICAL_SEVERITIES: frozenset[str] = frozenset(
    {"informational", "low", "medium", "high"}
)

_DEFAULT_SEVERITY = "informational"


@dataclass(frozen=True)
class ExtractedCoverage:
    """Normalised ATT&CK attribution for one detection.

    ``techniques`` lists every well-formed id on the rule (sorted, after
    revoked ids are remapped); ``counted_techniques`` is the subset present
    in the current matrix -- the only ids any coverage number counts.
    ``tactic_techniques`` maps each tactic to the counted techniques that
    belong to it in the matrix. ``severity`` is one of the four canonical
    lowercase values (default ``"informational"``).
    """

    tactics: tuple[str, ...] = ()
    techniques: tuple[str, ...] = ()
    severity: str = _DEFAULT_SEVERITY
    techniques_without_tactic: tuple[str, ...] = ()
    counted_techniques: tuple[str, ...] = ()
    tactic_techniques: tuple[tuple[str, tuple[str, ...]], ...] = ()
    invalid_ids: tuple[str, ...] = ()
    unknown_ids: tuple[str, ...] = ()
    deprecated_ids: tuple[str, ...] = ()
    remapped_ids: tuple[tuple[str, str], ...] = ()
    tactics_inferred: bool = False

    def techniques_for(self, tactic: str) -> tuple[str, ...]:
        """Counted techniques the matrix files under ``tactic``."""
        for name, techniques in self.tactic_techniques:
            if name == tactic:
                return techniques
        return ()


def _technique_to_tactics() -> dict[str, tuple[str, ...]]:
    """Return ``{technique_id: (tactic, ...)}`` for every current parent and
    sub-technique in the bundled ATT&CK matrix (see
    :func:`contentops.coverage.matrix.load_matrix`)."""
    return dict(load_matrix().technique_tactics)


# ---------------------------------------------------------------------------
# Small coercion helpers
# ---------------------------------------------------------------------------


def _str_list(value: Any) -> list[str]:
    """Coerce a payload field to a ``list[str]``; tolerant of None / non-list."""
    if isinstance(value, str):
        return [value] if value.strip() else []
    if not isinstance(value, (list, tuple)):
        return []
    return [v for v in value if isinstance(v, str) and v.strip()]


def _normalise_severity(value: Any) -> "str | None":
    """Return one of the canonical severities, or ``None`` if unrecognised."""
    if not isinstance(value, str) or not value:
        return None
    lowered = value.strip().lower()
    if lowered in _CANONICAL_SEVERITIES:
        return lowered
    return None


def _tactics(values: Iterable[Any]) -> list[str]:
    out: list[str] = []
    for value in values:
        tactic = normalise_tactic(value)
        if tactic is not None and tactic not in out:
            out.append(tactic)
    return out


def _dedupe(values: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(values))


# ---------------------------------------------------------------------------
# Per-asset payload readers: (claimed tactics, raw technique ids, severity)
# ---------------------------------------------------------------------------

_ReaderResult = tuple[list[str], list[str], "str | None"]


def _defender_payload(payload: Mapping[str, Any]) -> _ReaderResult:
    detection_action = payload.get("detectionAction")
    alert: Mapping[str, Any] = {}
    if isinstance(detection_action, Mapping):
        candidate = detection_action.get("alertTemplate")
        if isinstance(candidate, Mapping):
            alert = candidate
    # Defender has no tactics field; its alert ``category`` names the
    # tactic the author chose when it is one (e.g. "Execution"). Other
    # categories ("Malware", "SuspiciousActivity") claim no tactic.
    return (
        _tactics([alert.get("category")]),
        _str_list(alert.get("mitreTechniques")),
        _normalise_severity(alert.get("severity")),
    )


def _sentinel_analytic_payload(payload: Mapping[str, Any]) -> _ReaderResult:
    return (
        _tactics(_str_list(payload.get("tactics"))),
        _str_list(payload.get("techniques")) + _str_list(payload.get("subTechniques")),
        _normalise_severity(payload.get("severity")),
    )


def _sentinel_hunting_payload(payload: Mapping[str, Any]) -> _ReaderResult:
    """Hunting queries carry no severity; the caller falls back to the default."""
    return (
        _tactics(_str_list(payload.get("tactics"))),
        _str_list(payload.get("techniques")) + _str_list(payload.get("subTechniques")),
        None,
    )


_PAYLOAD_READERS = {
    Asset.DEFENDER_CUSTOM_DETECTION: _defender_payload,
    Asset.SENTINEL_ANALYTIC: _sentinel_analytic_payload,
    Asset.SENTINEL_HUNTING: _sentinel_hunting_payload,
}


def _metadata_fields(
    envelope: EnvelopeV2, raw_metadata: Mapping[str, Any] | None,
) -> _ReaderResult:
    """Tactics / techniques / severity from authored metadata.

    Strict metadata (``envelope.metadata``) wins; otherwise the raw
    mapping is read leniently -- each value is validated on its own, so
    one bad field elsewhere in the block no longer discards the tags.
    """
    meta = envelope.metadata
    if meta is not None:
        return list(meta.tactics), list(meta.techniques), meta.severity
    if not isinstance(raw_metadata, Mapping):
        return [], [], None
    return (
        _tactics(_str_list(raw_metadata.get("tactics"))),
        _str_list(raw_metadata.get("techniques")),
        _normalise_severity(raw_metadata.get("severity")),
    )


# ---------------------------------------------------------------------------
# Top-level extractor
# ---------------------------------------------------------------------------


def extract_mitre(
    envelope: EnvelopeV2,
    payload: Mapping[str, Any] | None,
    *,
    raw_metadata: Mapping[str, Any] | None = None,
    matrix: AttackMatrix | None = None,
) -> ExtractedCoverage:
    """Return the normalised ATT&CK attribution for one detection.

    Returns an empty :class:`ExtractedCoverage` for non-detection assets.
    ``raw_metadata`` is the envelope's raw ``metadata`` mapping (only read
    when strict metadata parsing failed); ``matrix`` defaults to the
    bundled ATT&CK release.
    """
    reader = _PAYLOAD_READERS.get(envelope.asset)
    if reader is None:
        return ExtractedCoverage()
    matrix = matrix or load_matrix()

    payload_tactics, payload_ids, payload_sev = reader(payload or {})
    meta_tactics, meta_ids, meta_sev = _metadata_fields(envelope, raw_metadata)

    display: list[str] = []
    counted: list[str] = []
    invalid: list[str] = []
    unknown: list[str] = []
    deprecated: list[str] = []
    remapped: list[tuple[str, str]] = []
    for raw_id in meta_ids + payload_ids:
        tid = normalise_technique_id(raw_id)
        if tid is None:
            invalid.append(raw_id.strip())
            continue
        current, status = matrix.resolve(tid)
        if status == "current":
            counted.append(tid)
            display.append(tid)
        elif status == "revoked" and current is not None:
            remapped.append((tid, current))
            counted.append(current)
            display.append(current)
        elif status == "deprecated":
            deprecated.append(tid)
            display.append(tid)
        else:
            unknown.append(tid)
            display.append(tid)
    counted = sorted(set(counted))

    tactics = _dedupe(meta_tactics + payload_tactics)
    inferred = False
    if not tactics and counted:
        tactics = _dedupe(t for tid in counted for t in matrix.tactics_for(tid))
        inferred = True
    tactics = sorted(tactics)

    tactic_techniques = tuple(
        (tactic, tuple(t for t in counted if tactic in matrix.tactics_for(t)))
        for tactic in tactics
    )
    attributed = {t for _, techniques in tactic_techniques for t in techniques}

    return ExtractedCoverage(
        tactics=tuple(tactics),
        techniques=tuple(sorted(set(display))),
        severity=meta_sev or payload_sev or _DEFAULT_SEVERITY,
        techniques_without_tactic=tuple(sorted(set(display) - attributed)),
        counted_techniques=tuple(counted),
        tactic_techniques=tactic_techniques,
        invalid_ids=tuple(_dedupe(invalid)),
        unknown_ids=tuple(sorted(set(unknown))),
        deprecated_ids=tuple(sorted(set(deprecated))),
        remapped_ids=tuple(sorted(set(remapped))),
        tactics_inferred=inferred,
    )


def extract_mitre_for(
    loaded: "LoadedAsset", *, matrix: AttackMatrix | None = None,
) -> ExtractedCoverage:
    """:func:`extract_mitre` for a loaded asset, passing its raw
    ``metadata`` block so tags survive a failed strict parse."""
    raw = getattr(loaded, "raw", None)
    raw = raw if isinstance(raw, Mapping) else {}
    raw_metadata = raw.get("metadata")
    return extract_mitre(
        loaded.envelope, loaded.payload,
        raw_metadata=raw_metadata if isinstance(raw_metadata, Mapping) else None,
        matrix=matrix,
    )


__all__ = [
    "ExtractedCoverage",
    "extract_mitre",
    "extract_mitre_for",
]
