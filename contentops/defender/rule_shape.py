# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Old and new property names of a Defender custom detection rule.

Graph deprecates several ``detectionRule`` properties in favour of new
ones; the v1.0 resource carries only the new ones, and the service
rejects a property it does not know. Graph beta still returns both, so
collected payloads have carried both, side by side.

==============================================  ====================
Old key(s)                                      New key
==============================================  ====================
``schedule.period``                             ``schedule.frequency``
``alertTemplate.category``, ``mitreTechniques``  ``alertTemplate.tactics``
``alertTemplate.impactedAssets``                ``alertTemplate.entityMappings``
``detectionAction.responseActions``             ``detectionAction.automatedActions``
``organizationalScope.scopeType``, ``scopeNames`` ``organizationalScope.deviceGroups``
``isEnabled``                                   ``status``
==============================================  ====================

For each pair the pipeline uses exactly ONE of the two keys, so a
request never carries two answers to the same question:

* the new key, when it has content;
* the old key, when the new key has no content and the old one has: a
  filled value is never dropped in favour of an empty one;
* otherwise the (empty) new key when it is in the payload, else the old
  key as written, so an old-format file can still clear a value.

Everything that sends, compares, collects or reads these properties goes
through this module so they agree. Enabled state (``isEnabled`` /
``status``) keeps its own rules in ``rule_status``.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Any, Callable, Literal

from contentops.models import _has_entity_mapping

Source = Literal["new", "old", "none"]

_PERIOD_TO_FREQUENCY = {"0": "PT0S", "1H": "PT1H", "3H": "PT3H", "12H": "PT12H", "24H": "P1D"}


def _blank(value: Any) -> bool:
    return value is None or (isinstance(value, str) and not value.strip())


def _filled_list(value: Any) -> bool:
    return isinstance(value, list) and len(value) > 0


def _tactic_entries(template: dict) -> list[dict]:
    tactics = template.get("tactics")
    return [entry for entry in tactics if isinstance(entry, dict)] if isinstance(tactics, list) else []


def _techniques_under(template: dict) -> list[str]:
    """Technique and sub-technique ids under every tactic, in order."""
    ids: list[str] = []
    for tactic in _tactic_entries(template):
        techniques = tactic.get("techniques")
        for technique in techniques if isinstance(techniques, list) else []:
            if not isinstance(technique, dict):
                continue
            if not _blank(technique.get("technique")):
                ids.append(str(technique["technique"]))
            subs = technique.get("subTechniques")
            ids.extend(str(sub) for sub in (subs if isinstance(subs, list) else []) if not _blank(sub))
    return list(dict.fromkeys(ids))


def _tactics_have_content(template: dict) -> bool:
    # Tactic names without techniques do not outrank techniques that sit
    # only in the old key: that would drop a filled value for an empty one.
    if _techniques_under(template):
        return True
    named = any(not _blank(tactic.get("tactic")) for tactic in _tactic_entries(template))
    return named and not _filled_list(template.get("mitreTechniques"))


def _old_tactics_have_content(template: dict) -> bool:
    return not _blank(template.get("category")) or _filled_list(template.get("mitreTechniques"))


def _entities_have_content(template: dict) -> bool:
    mappings = template.get("entityMappings")
    return _has_entity_mapping(mappings if isinstance(mappings, dict) else None)


def _actions_have_content(action: dict) -> bool:
    automated = action.get("automatedActions")
    return isinstance(automated, dict) and any(_filled_list(entries) for entries in automated.values())


@dataclass(frozen=True)
class Pair:
    """One deprecated property (or two) and its replacement."""

    name: str
    #: Path from the payload root to the mapping that holds both keys.
    parent: tuple[str, ...]
    old: tuple[str, ...]
    new: str
    new_has_content: Callable[[dict], bool]
    old_has_content: Callable[[dict], bool]


PAIRS: tuple[Pair, ...] = (
    Pair(
        "schedule", ("schedule",), ("period",), "frequency",
        lambda schedule: not _blank(schedule.get("frequency")),
        lambda schedule: not _blank(schedule.get("period")),
    ),
    Pair(
        "tactics", ("detectionAction", "alertTemplate"), ("category", "mitreTechniques"), "tactics",
        _tactics_have_content, _old_tactics_have_content,
    ),
    Pair(
        "entities", ("detectionAction", "alertTemplate"), ("impactedAssets",), "entityMappings",
        _entities_have_content,
        lambda template: _filled_list(template.get("impactedAssets")),
    ),
    Pair(
        "actions", ("detectionAction",), ("responseActions",), "automatedActions",
        _actions_have_content,
        lambda action: _filled_list(action.get("responseActions")),
    ),
    Pair(
        "scope", ("detectionAction", "organizationalScope"), ("scopeType", "scopeNames"), "deviceGroups",
        lambda scope: _filled_list(scope.get("deviceGroups")),
        lambda scope: _filled_list(scope.get("scopeNames")),
    ),
)
_BY_NAME = {pair.name: pair for pair in PAIRS}


@dataclass(frozen=True)
class LegacyKey:
    """An old key found in a payload, for lint."""

    #: Dotted path from the payload root, e.g. ``schedule.period``.
    path: str
    #: True when the old key is the one sent (its new key has no content).
    sent: bool
    #: True when the old key is ignored AND says something else than the
    #: new key; None where the two cannot be compared.
    differs: bool | None
    #: Dotted path of the key to use instead, e.g. ``schedule.frequency``.
    replacement: str = ""


def _parent(payload: Any, path: tuple[str, ...]) -> dict | None:
    node = payload
    for key in path:
        if not isinstance(node, dict):
            return None
        node = node.get(key)
    return node if isinstance(node, dict) else None


def _source(pair: Pair, parent: dict) -> Source:
    if pair.new_has_content(parent):
        return "new"
    if pair.old_has_content(parent):
        return "old"
    if pair.new in parent:
        return "new"
    return "old" if any(key in parent for key in pair.old) else "none"


def source_of(payload: dict[str, Any], pair_name: str) -> Source:
    """Which key of ``pair_name`` this payload is read and sent from."""
    pair = _BY_NAME[pair_name]
    parent = _parent(payload, pair.parent)
    return _source(pair, parent) if parent is not None else "none"


def to_current_shape(payload: dict[str, Any]) -> dict[str, Any]:
    """Return a deep copy of ``payload`` with one source key per pair.

    ``payload`` is not changed. A payload with new keys only, or with old
    keys only, comes back equal to the input.
    """
    out = copy.deepcopy(payload)
    if "status" in out:
        out.pop("isEnabled", None)
    for pair in PAIRS:
        parent = _parent(out, pair.parent)
        if parent is None:
            continue
        source = _source(pair, parent)
        if source == "new":
            for key in pair.old:
                parent.pop(key, None)
        elif source == "old":
            parent.pop(pair.new, None)
    return out


def _differs(pair: Pair, key: str, parent: dict) -> bool | None:
    """Does an ignored old key say something else than its new key?"""
    if pair.name == "schedule":
        if _blank(parent.get("period")):
            return False
        expected = _PERIOD_TO_FREQUENCY.get(str(parent["period"]))
        return None if expected is None else expected != parent.get("frequency")
    if pair.name == "tactics":
        if key == "category":
            if _blank(parent.get("category")):
                return False
            names = [tactic.get("tactic") for tactic in _tactic_entries(parent)]
            return not names or parent["category"] != names[0]
        old_ids = parent.get("mitreTechniques")
        if not _filled_list(old_ids):
            return False
        return {str(item) for item in old_ids} != set(_techniques_under(parent))
    if pair.name == "scope" and key == "scopeNames":
        if not _filled_list(parent.get("scopeNames")):
            return False
        return sorted(map(str, parent["scopeNames"])) != sorted(map(str, parent.get("deviceGroups") or []))
    return None


def legacy_keys(payload: dict[str, Any]) -> list[LegacyKey]:
    """Every old key present in ``payload``, in a stable order."""
    found: list[LegacyKey] = []
    if isinstance(payload, dict) and "isEnabled" in payload:
        found.append(LegacyKey("isEnabled", sent=False, differs=None, replacement="status"))
    for pair in PAIRS:
        parent = _parent(payload, pair.parent)
        if parent is None:
            continue
        source = _source(pair, parent)
        for key in pair.old:
            if key not in parent:
                continue
            found.append(LegacyKey(
                ".".join((*pair.parent, key)),
                sent=source == "old",
                differs=_differs(pair, key, parent) if source == "new" else None,
                replacement=".".join((*pair.parent, pair.new)),
            ))
    return found


def _alert_template(payload: Any) -> dict:
    return _parent(payload, ("detectionAction", "alertTemplate")) or {}


def tactic_names(payload: dict[str, Any]) -> list[str]:
    """Every tactic the rule names, from whichever key is the source."""
    template = _alert_template(payload)
    if _source(_BY_NAME["tactics"], template) == "new":
        return [str(t["tactic"]) for t in _tactic_entries(template) if not _blank(t.get("tactic"))]
    category = template.get("category")
    return [] if _blank(category) else [str(category)]


def technique_ids(payload: dict[str, Any]) -> list[str]:
    """Every technique and sub-technique id, from whichever key is the source."""
    template = _alert_template(payload)
    if _source(_BY_NAME["tactics"], template) == "new":
        return _techniques_under(template)
    old_ids = template.get("mitreTechniques")
    return [str(item) for item in old_ids if not _blank(item)] if isinstance(old_ids, list) else []


def entity_columns(payload: dict[str, Any]) -> list[str]:
    """Query columns named by ``entityMappings`` when it is the source.

    Empty when the rule still identifies its entities through
    ``impactedAssets``: those name identifiers, not columns. An OData
    annotation such as ``@odata.type`` names a type, not a column, and is
    left out (the validator sets annotations aside in the same way).
    """
    template = _alert_template(payload)
    if _source(_BY_NAME["entities"], template) != "new":
        return []
    columns: list[str] = []
    mappings = template.get("entityMappings")
    for entries in (mappings.values() if isinstance(mappings, dict) else []):
        for entry in entries if isinstance(entries, list) else []:
            if isinstance(entry, dict):
                columns.extend(
                    str(value).strip() for name, value in entry.items()
                    if not str(name).startswith("@") and isinstance(value, str) and value.strip()
                )
    return list(dict.fromkeys(columns))


__all__ = [
    "LegacyKey",
    "PAIRS",
    "Pair",
    "entity_columns",
    "legacy_keys",
    "source_of",
    "tactic_names",
    "technique_ids",
    "to_current_shape",
]
