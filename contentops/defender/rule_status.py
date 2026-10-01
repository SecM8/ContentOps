# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Enabled-state handling for Defender custom detection rules.

Graph beta replaced the boolean ``isEnabled`` with a ``status`` enum
(``enabled`` / ``disabled`` / ``autoDisabled``) and removed
``isEnabled`` from the ``detectionRule`` resource on 2026-10-01.
Authored YAML may carry either field: ``status`` is the current
contract, ``isEnabled`` is still accepted so existing repos keep
validating. Everything that reads or writes the enabled state goes
through this module so collect, apply, verify and reporting agree.
"""

from __future__ import annotations

from typing import Any

DEFENDER_RULE_STATUSES = ("enabled", "disabled", "autoDisabled")

# Defender switches a rule to ``autoDisabled`` after repeated run
# failures. Re-enabling one is a deliberate operator act, so apply
# never sends this value back and never flips it on its own.
AUTO_DISABLED = "autoDisabled"


def rule_status(rule: dict[str, Any]) -> str:
    """Return the rule's status, falling back to legacy ``isEnabled``."""
    status = rule.get("status")
    if status in DEFENDER_RULE_STATUSES:
        return status
    return "enabled" if rule.get("isEnabled", True) is not False else "disabled"


def is_enabled(rule: dict[str, Any]) -> bool:
    """True when the rule runs: ``status: enabled`` (or legacy ``isEnabled: true``)."""
    return rule_status(rule) == "enabled"


def to_wire_body(payload: dict[str, Any], *, deprecated: bool = False) -> dict[str, Any]:
    """Build the Graph request body from an authored payload.

    * ``isEnabled`` is never sent (removed from the API); its value is
      folded into ``status`` when the payload has no ``status``.
    * ``deprecated`` envelopes are always sent as ``status: disabled``.
    * ``autoDisabled`` is not sent, so the PATCH leaves the server-side
      state untouched.

    Returns a new dict; ``payload`` is not mutated.
    """
    body = dict(payload)
    body.pop("isEnabled", None)
    status = rule_status(payload)
    if deprecated:
        body["status"] = "disabled"
    elif status == AUTO_DISABLED:
        body.pop("status", None)
    else:
        body["status"] = status
    return body


def hashed_fields(base: list[str], body: dict[str, Any]) -> list[str]:
    """Return the hash projection for ``body``.

    ``description`` joins the projection only when the authored body
    sets a non-empty one. YAML collected before Graph exposed the field
    has no ``description``, and a PATCH without it leaves the portal
    value alone, so hashing it unconditionally would report a mismatch
    on every such rule.
    """
    if body.get("description"):
        return [*base, "description"]
    return list(base)
