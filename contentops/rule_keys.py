# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Rule identity keys: join workspace telemetry to repo detections.

``SecurityAlert`` / ``SecurityIncident`` rows name the rule that produced
them two ways:

* **by id** -- for Sentinel analytics, ``SecurityAlert.AlertType`` is
  ``<workspace-guid>_<rule name>`` (Microsoft documents it as "taken from
  the rule ID") and ``SecurityIncident.RelatedAnalyticRuleIds`` lists the
  rule ids (sometimes as full ARM resource ids);
* **by display name** -- ``AlertName`` / ``Title``.

Display names are unreliable: ``alertDisplayNameFormat`` templates them per
alert ("Brute Force Attack from 10.1.2.3") and analysts rename incidents.
Joined by name, such a rule looks silent, takes the silence penalty and is
flagged for retirement. So the telemetry KQL (``contentops.workspace_kql``)
emits one row per **rule key** -- ``id:<rule name>`` when the row carries a
rule id, else ``name:<display name>`` -- and :class:`TelemetryIndex` gathers
every row of a rule: its id (``metadata.arm_name``, else envelope id) and its
names (``displayName``; Defender ``alertTemplate.title``). One rule's
telemetry can be split across several keys (alerts under the rule id, an
incident without ``RelatedAnalyticRuleIds`` under its title), so the rows are
summed rather than the first match taken.

Key normalisation here must match the KQL: ids are the last path segment
with any ``<guid>_`` workspace prefix removed, lower-cased; names are
trimmed and lower-cased.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from itertools import chain
from typing import Any, Iterable, Mapping

ID_PREFIX = "id:"
NAME_PREFIX = "name:"

# Count columns of ``contentops.workspace_kql.telemetry_query`` rows; summed
# when one rule's telemetry spans several rows.
COUNT_COLUMNS = (
    "alerts_30d", "incidents_30d", "closed_tp_30d", "closed_fp_30d", "closed_bp_30d",
)

_WORKSPACE_PREFIX = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}_(.+)$",
    re.IGNORECASE,
)


def normalise_rule_id(value: object) -> str | None:
    """``/subscriptions/.../alertRules/ABC`` / ``<ws-guid>_ABC`` / ``ABC`` -> ``abc``."""
    if not isinstance(value, str):
        return None
    text = value.strip().rstrip("/")
    if not text:
        return None
    text = text.rsplit("/", 1)[-1]
    match = _WORKSPACE_PREFIX.match(text)
    if match:
        text = match.group(1)
    return text.lower() or None


def normalise_rule_name(value: object) -> str | None:
    """Trim + lower-case (KQL: ``tolower(trim(@"\\s+", name))``)."""
    if not isinstance(value, str):
        return None
    text = value.strip().lower()
    return text or None


@dataclass(frozen=True)
class RuleKeys:
    """How one detection can appear in telemetry, most specific first."""

    ids: tuple[str, ...] = ()
    names: tuple[str, ...] = ()

    def candidates(self) -> tuple[str, ...]:
        """``id:`` keys then ``name:`` keys (the KQL ``rule_key`` space)."""
        return tuple(ID_PREFIX + i for i in self.ids) + tuple(NAME_PREFIX + n for n in self.names)

    @classmethod
    def from_candidates(cls, keys: Iterable[str]) -> RuleKeys:
        ids = tuple(k[len(ID_PREFIX):] for k in keys if k.startswith(ID_PREFIX))
        names = tuple(k[len(NAME_PREFIX):] for k in keys if k.startswith(NAME_PREFIX))
        return cls(ids=ids, names=names)


def _dedupe(values: Iterable[str | None]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(v for v in values if v))


def _defender_alert_title(payload: Mapping[str, Any]) -> str | None:
    action = payload.get("detectionAction")
    template = action.get("alertTemplate") if isinstance(action, Mapping) else None
    title = template.get("title") if isinstance(template, Mapping) else None
    return title if isinstance(title, str) else None


def rule_keys(
    asset: object,
    *,
    envelope_id: str | None,
    arm_name: str | None,
    payload: Mapping[str, Any] | None,
) -> RuleKeys:
    """Telemetry keys for one detection.

    ids: the resource name apply deploys to (``metadata.arm_name``, else
    the envelope id -- as the Sentinel handler resolves it). names: the
    payload ``displayName`` and, for Defender custom detections, the
    alert title (Defender alerts carry ``alertTemplate.title`` as their
    name, which often differs).
    """
    payload = payload or {}
    asset_value = getattr(asset, "value", asset)
    names = [payload.get("displayName"), payload.get("DisplayName")]
    if asset_value == "defender_custom_detection":
        names.append(_defender_alert_title(payload))
    return RuleKeys(
        ids=_dedupe([normalise_rule_id(arm_name or envelope_id)]),
        names=_dedupe(normalise_rule_name(v) for v in names),
    )


def rule_keys_for(item: Any) -> RuleKeys:
    """Keys for a ``LoadedAsset`` or ``CorpusEntry``."""
    envelope = item.envelope
    return rule_keys(
        envelope.asset, envelope_id=envelope.id, arm_name=envelope.arm_name,
        payload=item.payload,
    )


def rule_keys_from_raw(doc: Mapping[str, Any]) -> RuleKeys:
    """Keys from a raw envelope dict (tolerates missing fields)."""
    metadata = doc.get("metadata") if isinstance(doc.get("metadata"), Mapping) else {}
    payload = doc.get("payload") if isinstance(doc.get("payload"), Mapping) else {}
    return rule_keys(
        doc.get("asset"), envelope_id=doc.get("id") if isinstance(doc.get("id"), str) else None,
        arm_name=metadata.get("arm_name") if isinstance(metadata.get("arm_name"), str) else None,
        payload=payload,
    )


class TelemetryIndex:
    """Telemetry rows by rule key, for :meth:`rows_for` / :meth:`lookup`.

    Rows carry ``rule_key`` (``id:...`` / ``name:...``) and ``rule_name``;
    rows without ``rule_key`` (hand-built test rows) are indexed by
    ``rule_name``.

    A rule's rows are its ``id:`` rows plus its ``name:`` rows. The KQL
    puts every alert in exactly one row and every incident in at most one
    row per rule, so those rows are disjoint and :meth:`lookup` sums them.
    Only when a rule has none of them do ``id:`` rows whose ``rule_name``
    matches count -- the display-name join used before rule keys, for a rule
    whose id the telemetry doesn't carry as the repo expects.
    """

    def __init__(self, rows: Iterable[Mapping[str, Any]]) -> None:
        self._by_id: dict[str, list[Mapping[str, Any]]] = {}
        self._by_name: dict[str, list[Mapping[str, Any]]] = {}
        self._by_id_row_name: dict[str, list[Mapping[str, Any]]] = {}
        for row in rows:
            key = str(row.get("rule_key") or "")
            if key.startswith(ID_PREFIX):
                self._by_id.setdefault(key[len(ID_PREFIX):], []).append(row)
                name = normalise_rule_name(row.get("rule_name"))
                if name:
                    self._by_id_row_name.setdefault(name, []).append(row)
            elif key.startswith(NAME_PREFIX):
                self._by_name.setdefault(key[len(NAME_PREFIX):], []).append(row)
            else:
                name = normalise_rule_name(row.get("rule_name"))
                if name:
                    self._by_name.setdefault(name, []).append(row)

    def rows_for(self, keys: RuleKeys) -> list[Mapping[str, Any]]:
        """Every telemetry row of the rule, ids first, each row once."""
        own = _unique(chain(
            chain.from_iterable(self._by_id.get(i, ()) for i in keys.ids),
            chain.from_iterable(self._by_name.get(n, ()) for n in keys.names),
        ))
        if own:
            return own
        return _unique(chain.from_iterable(self._by_id_row_name.get(n, ()) for n in keys.names))

    def lookup(self, keys: RuleKeys) -> dict[str, Any] | None:
        """The rule's telemetry with the count columns summed, or None."""
        rows = self.rows_for(keys)
        return merge_rows(rows) if rows else None


def _unique(rows: Iterable[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
    return list({id(row): row for row in rows}.values())


def merge_rows(rows: list[Mapping[str, Any]]) -> dict[str, Any]:
    """One rule's telemetry rows as one row: :data:`COUNT_COLUMNS` summed
    (a column absent from every row stays absent), other fields from the
    first row, and ``rule_keys`` listing the contributing keys."""
    merged = dict(rows[0])
    for column in COUNT_COLUMNS:
        values = [row.get(column) for row in rows]
        if any(v is not None for v in values):
            merged[column] = sum(int(v or 0) for v in values)
    merged["rule_keys"] = [str(row["rule_key"]) for row in rows if row.get("rule_key")]
    return merged


__all__ = [
    "COUNT_COLUMNS",
    "ID_PREFIX",
    "NAME_PREFIX",
    "RuleKeys",
    "TelemetryIndex",
    "merge_rows",
    "normalise_rule_id",
    "normalise_rule_name",
    "rule_keys",
    "rule_keys_for",
    "rule_keys_from_raw",
]
