# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""What differs between a Defender rule file and the rule in the tenant.

A deploy asks this twice: before the write ("is there anything to
send?") and after it ("did what was sent arrive?"). Both answers come
from :func:`diff_rule`, so they cannot disagree.

The comparison follows the file:

* Only a field the request body carries is compared. The body holds one
  key per old/new pair (see ``rule_shape``), so the key that is sent is
  the key that is compared.
* Empty values are alike: ``null``, ``''``, ``[]`` and ``{}``. ``false``
  and ``0`` are values.
* The tenant returns every value in its expanded form (every entity
  collection, every column of a mapping, every action list). A short,
  hand-written value equals the expanded one when the filled parts agree.
* Lists are compared without regard to order, text without regard to
  line endings and trailing spaces, durations as durations (``PT60M``
  equals ``PT1H``).
* ``lookback``, the event grouping and the incident configuration are
  filled in by the service when a file leaves them empty, so an empty
  value there is not compared.
* Any other field that is empty in the file and filled in the tenant is
  reported apart (``not_cleared``) and is not a difference: which empty
  form clears a field is not documented. An update sends the tenant's
  own value back for such a field (:func:`keep_tenant_values`), so
  "left as it is" holds whatever the service does with an empty value.

Results name fields, never values.
"""

from __future__ import annotations

import copy
import re
from dataclasses import dataclass
from typing import Any, Iterable

_TEXT = "text"
_EXACT = "exact"
_DURATION = "duration"
_TREE = "tree"

_TEMPLATE = "detectionAction.alertTemplate"
_SCOPE = "detectionAction.organizationalScope"

#: Compared fields, in report order: (dotted path, kind, skipped when the
#: file leaves it empty). Old and new keys are both listed; a body holds
#: only the one it sends.
_FIELDS: tuple[tuple[str, str, bool], ...] = (
    ("displayName", _TEXT, False),
    ("description", _TEXT, False),
    ("queryCondition.queryText", _TEXT, False),
    ("schedule.frequency", _DURATION, False),
    ("schedule.period", _EXACT, False),
    ("schedule.lookback", _DURATION, True),
    (f"{_TEMPLATE}.title", _TEXT, False),
    (f"{_TEMPLATE}.description", _TEXT, False),
    (f"{_TEMPLATE}.severity", _EXACT, False),
    (f"{_TEMPLATE}.recommendedActions", _TEXT, False),
    (f"{_TEMPLATE}.customDetails", _TREE, False),
    (f"{_TEMPLATE}.eventGroupingKind", _EXACT, True),
    (f"{_TEMPLATE}.tactics", _TREE, False),
    (f"{_TEMPLATE}.category", _EXACT, False),
    (f"{_TEMPLATE}.mitreTechniques", _TREE, False),
    (f"{_TEMPLATE}.entityMappings", _TREE, False),
    (f"{_TEMPLATE}.impactedAssets", _TREE, False),
    ("detectionAction.automatedActions", _TREE, False),
    ("detectionAction.responseActions", _TREE, False),
    (f"{_SCOPE}.deviceGroups", _TREE, False),
    (f"{_SCOPE}.scopeType", _EXACT, False),
    (f"{_SCOPE}.scopeNames", _TREE, False),
    ("detectionAction.incidentConfiguration", _TREE, True),
)

#: Keys that move together in what the tenant returns: writing one of
#: them changes the others. Used to tell an expected side effect of an
#: update from an unexpected one.
_MOVES_WITH: tuple[frozenset[str], ...] = (
    frozenset({"schedule.frequency", "schedule.period", "schedule.lookback"}),
    frozenset({f"{_TEMPLATE}.tactics", f"{_TEMPLATE}.category", f"{_TEMPLATE}.mitreTechniques"}),
    frozenset({f"{_TEMPLATE}.entityMappings", f"{_TEMPLATE}.impactedAssets"}),
    frozenset({"detectionAction.automatedActions", "detectionAction.responseActions"}),
    frozenset({f"{_SCOPE}.deviceGroups", f"{_SCOPE}.scopeType", f"{_SCOPE}.scopeNames"}),
)

_MISSING = object()

_DURATION_RE = re.compile(
    r"P(?:([0-9]+)W|(?:([0-9]+)D)?(?:T(?=[0-9])(?:([0-9]+)H)?(?:([0-9]+)M)?(?:([0-9]+)S)?)?)"
)


@dataclass(frozen=True)
class RuleDiff:
    """Field names only; no value from a file or a tenant."""

    #: Fields whose value in the tenant is not the value the file gives.
    changed: tuple[str, ...] = ()
    #: Fields the file leaves empty while the tenant holds a value.
    not_cleared: tuple[str, ...] = ()


def _get(node: Any, path: str) -> Any:
    for key in path.split("."):
        if not isinstance(node, dict) or key not in node:
            return _MISSING
        node = node[key]
    return node


def _annotation(key: Any) -> bool:
    """An OData annotation (``@odata.type``, ``x@odata.type``): it names a
    type, it is not a value a file sets."""
    return "@odata." in str(key)


def _empty(value: Any) -> bool:
    if value is _MISSING or value is None:
        return True
    if isinstance(value, str):
        return not value.strip()
    if isinstance(value, dict):
        # An entry that holds nothing but an annotation is empty: the
        # tenant adds ``@odata.type`` to a mapping whose columns are all
        # blank, and that must not make the entry count as filled.
        return all(_empty(item) for key, item in value.items() if not _annotation(key))
    if isinstance(value, (list, tuple)):
        return all(_empty(item) for item in value)
    return False


def _text(value: Any) -> str:
    lines = str(value).replace("\r\n", "\n").replace("\r", "\n").split("\n")
    return "\n".join(line.rstrip() for line in lines).strip("\n")


def _seconds(value: Any) -> int | None:
    match = _DURATION_RE.fullmatch(value) if isinstance(value, str) else None
    if match is None or all(part is None for part in match.groups()):
        return None
    weeks, days, hours, minutes, seconds = (int(part or 0) for part in match.groups())
    return (((weeks * 7 + days) * 24 + hours) * 60 + minutes) * 60 + seconds


def _same(local: Any, remote: Any) -> bool:
    """Is the tenant's value the value the file gives?"""
    if _empty(local) or _empty(remote):
        return _empty(local) and _empty(remote)
    if isinstance(local, dict) and isinstance(remote, dict):
        for key in set(local) | set(remote):
            if _annotation(key) and (key not in local or key not in remote):
                # An annotation only one side carries is set aside. Where
                # both carry it (the old keys, whose ``@odata.type`` says
                # which asset or action is meant) it is compared.
                continue
            if not _same(local.get(key, _MISSING), remote.get(key, _MISSING)):
                return False
        return True
    if isinstance(local, (list, tuple)) and isinstance(remote, (list, tuple)):
        left = [item for item in local if not _empty(item)]
        right = [item for item in remote if not _empty(item)]
        if len(left) != len(right):
            return False
        for item in left:
            for index, candidate in enumerate(right):
                if _same(item, candidate):
                    del right[index]
                    break
            else:
                return False
        return True
    if isinstance(local, bool) or isinstance(remote, bool):
        return local is remote
    if isinstance(local, str) and isinstance(remote, str):
        return _text(local) == _text(remote)
    return local == remote


def _same_as(kind: str, local: Any, remote: Any) -> bool:
    if kind == _DURATION:
        left, right = _seconds(local), _seconds(remote)
        if left is not None and right is not None:
            return left == right
    return _same(local, remote)


def diff_rule(body: dict[str, Any], remote: dict[str, Any]) -> RuleDiff:
    """Compare the request body of a rule file with the tenant's rule.

    ``body`` is what ``rule_status.to_wire_body`` returns. Neither
    argument is changed. The enabled state (``status``) has its own rule
    in the handler and is not part of this comparison.
    """
    changed: list[str] = []
    not_cleared: list[str] = []
    for path, kind, service_fills_in in _FIELDS:
        local = _get(body, path)
        if local is _MISSING:
            continue
        there = _get(remote, path)
        if _empty(local):
            if not service_fills_in and not _empty(there):
                not_cleared.append(path)
            continue
        if not _same_as(kind, local, there):
            changed.append(path)
    # A scope that is written as empty as a whole (``organizationalScope:
    # null``) has no key underneath to compare.
    scope = _get(body, _SCOPE)
    if scope is not _MISSING and _empty(scope) and not _empty(_get(remote, _SCOPE)):
        not_cleared.append(_SCOPE)
    return RuleDiff(changed=tuple(changed), not_cleared=tuple(not_cleared))


def added_in_tenant(body: dict[str, Any], remote: dict[str, Any]) -> tuple[str, ...]:
    """Fields the tenant holds a value for that the file leaves out entirely.

    :func:`diff_rule` compares only the fields a body carries, which is right
    for a deploy: a field the file leaves out is not sent, so the tenant keeps
    it. Drift must still see a value added in the portal (a response action,
    a description, custom details). A missing field counts only when no key of
    its old/new group is in the file either (Graph fills the old key next to
    the new one: ``category`` next to ``tactics``, ``impactedAssets`` next to
    ``entityMappings``), and not where the service fills a value in itself.
    """
    added: list[str] = []
    for path, _kind, service_fills_in in _FIELDS:
        if service_fills_in or _get(body, path) is not _MISSING:
            continue
        group = next((g for g in _MOVES_WITH if path in g), frozenset({path}))
        if any(_get(body, other) is not _MISSING for other in group):
            continue
        if path.startswith(_SCOPE + ".") and _get(body, _SCOPE) is not _MISSING:
            continue  # a scope written as a whole is compared by diff_rule
        if not _empty(_get(remote, path)):
            added.append(path)
    return tuple(added)


def _set(node: dict[str, Any], path: str, value: Any) -> None:
    keys = path.split(".")
    for key in keys[:-1]:
        node = node[key]
    node[keys[-1]] = value


def keep_tenant_values(
    body: dict[str, Any], remote: dict[str, Any], intended: Iterable[str],
) -> dict[str, Any]:
    """The body of an update, with no empty value where the tenant holds one.

    In a PATCH, ``null`` (and, for some properties, ``''`` or ``{}``)
    means "clear". A file that is empty where the tenant holds a value is
    reported as "left as it is", so it must not travel as it is: a scope
    written as ``null`` would be cleared and the rule broadened to every
    device before any check could notice. For such a field the tenant's
    own value is sent back, which leaves it unchanged whatever the
    service does with an empty or a missing key.

    One exception: a value the service derives (``lookback``) is not sent
    back when the value it derives from (``intended``, e.g. the
    frequency) is what the update changes; the old one may not fit.

    Returns a copy; ``body`` and ``remote`` are not changed.
    """
    from contentops.defender.rule_shape import to_current_shape

    intended_set = set(intended)
    out = copy.deepcopy(body)
    for path, _kind, service_fills_in in _FIELDS:
        local = _get(out, path)
        if local is _MISSING or not _empty(local):
            continue
        there = _get(remote, path)
        if _empty(there):
            continue
        if service_fills_in and any(path in group and group & intended_set for group in _MOVES_WITH):
            continue
        _set(out, path, copy.deepcopy(there))
    scope = _get(out, _SCOPE)
    there = _get(remote, _SCOPE)
    if scope is not _MISSING and _empty(scope) and not _empty(there):
        # The tenant returns the scope under old and new keys; send one.
        projected = to_current_shape({"detectionAction": {"organizationalScope": copy.deepcopy(there)}})
        _set(out, _SCOPE, projected["detectionAction"]["organizationalScope"])
    return out


def compared_fields(body: dict[str, Any]) -> list[str]:
    """The fields of ``body`` that :func:`diff_rule` compares, in order."""
    return [path for path, _kind, _fills in _FIELDS if _get(body, path) is not _MISSING]


def unexpected_changes(
    before: dict[str, Any], after: dict[str, Any], intended: Iterable[str],
) -> list[str]:
    """Fields that changed in the tenant although the update did not mean to.

    ``before`` and ``after`` are the tenant's rule read before and after
    the update, ``intended`` the fields the update set out to change
    (``diff_rule(...).changed``). Keys that move together with an
    intended one (the old key of a pair, a derived ``lookback``) are
    expected. Everything else must be the same before and after.
    """
    allowed: set[str] = set()
    for path in intended:
        allowed.add(path)
        for group in _MOVES_WITH:
            if path in group:
                allowed |= group
    unexpected: list[str] = []
    for path, kind, _service_fills_in in _FIELDS:
        if path in allowed:
            continue
        if not _same_as(kind, _get(before, path), _get(after, path)):
            unexpected.append(path)
    return unexpected


__all__ = ["RuleDiff", "compared_fields", "diff_rule", "keep_tenant_values", "unexpected_changes"]
