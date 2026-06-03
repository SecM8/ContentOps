# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Allowlist for `kql_strict` (.NET wrapper) false-positive findings.

The Kusto.Language wrapper validates KQL against the vendored
Sentinel + Defender schemas but doesn't model three known-good
constructs the operator-side detection corpus uses heavily:

* **Join-suffix columns.** When two tables joined together share a
  column name, KQL appends a numeric suffix to the right-side copy
  (``SHA1`` → ``SHA11``). The wrapper sees ``SHA11`` as an unknown
  column and emits ``KS142``.
* **Dynamic extend columns.** ``extend foo_s = tostring(props.bar)``
  produces a typed column whose suffix (``_s``/``_d``/``_b``/``_g``/
  ``_l``) the wrapper doesn't track.
* **Invoke functions.** ``FileProfile()`` and similar Defender-only
  invoke functions aren't in Kusto.Language's stdlib, so calls emit
  ``KS211`` and their projected output columns emit ``KS142``.

Each pattern carries a required ``reason`` field so an auditor can
see *why* a finding is suppressed (and the operator can revisit
once a wrapper update closes the gap).

Suppression is restricted to rule IDs in ``ALLOWED_RULES``
(currently ``KS142``, ``KS211``). Heuristic rules (``KQL001``-
``KQL007``) and the strict-mode policy (``KQL101``) cannot be
allowlisted -- they're operator-tuned and should stay loud. Refusing
to allowlist them at load time prevents an over-broad pattern from
silently masking real bugs the heuristic rules catch.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import yaml

from contentops.lint.kql import LintFinding


DEFAULT_CONFIG_PATH = Path("config") / "kql_lint_allowlist.yml"


# Only wrapper-emitted rules are allowlistable. Heuristic + policy
# rules stay loud -- they're authored by us, not by the upstream
# Kusto.Language parser, so a false positive is a code bug to fix
# rather than a wrapper gap to suppress.
ALLOWED_RULES: frozenset[str] = frozenset({"KS142", "KS211"})


@dataclass(frozen=True)
class AllowlistEntry:
    rule_id: str
    pattern: re.Pattern[str]
    reason: str


def _parse_entry(raw: object, idx: int) -> tuple[AllowlistEntry | None, str | None]:
    """Return (entry, info_or_None). On any error returns (None, info)."""
    if not isinstance(raw, dict):
        return None, f"allowlist[{idx}] is not a mapping; skipping."
    rule_id = raw.get("rule")
    pattern_text = raw.get("pattern")
    reason = raw.get("reason")
    if not isinstance(rule_id, str) or not rule_id:
        return None, f"allowlist[{idx}] missing 'rule' field; skipping."
    if rule_id not in ALLOWED_RULES:
        return None, (
            f"allowlist[{idx}] rule {rule_id!r} is not allowlistable; "
            f"only {sorted(ALLOWED_RULES)} can be suppressed. Skipping."
        )
    if not isinstance(pattern_text, str) or not pattern_text:
        return None, f"allowlist[{idx}] missing 'pattern' field; skipping."
    if not isinstance(reason, str) or not reason.strip():
        return None, (
            f"allowlist[{idx}] missing 'reason' field; "
            "every entry must carry an auditable reason. Skipping."
        )
    try:
        compiled = re.compile(pattern_text)
    except re.error as exc:
        return None, (
            f"allowlist[{idx}] pattern {pattern_text!r} not a valid regex "
            f"({exc}); skipping."
        )
    return AllowlistEntry(rule_id=rule_id, pattern=compiled, reason=reason.strip()), None


def load_allowlist(
    path: Path | None = None,
) -> tuple[tuple[AllowlistEntry, ...], list[str]]:
    """Load the allowlist; return ``(entries, info_notes)``.

    Returns an empty tuple when the file is missing or malformed.
    ``info_notes`` collects human-readable warnings for the CLI to
    surface (one per skipped / malformed entry) so the operator
    can see WHY an entry didn't load.
    """
    target = path if path is not None else DEFAULT_CONFIG_PATH
    if not target.exists():
        return (), []
    try:
        data = yaml.safe_load(target.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        return (), [f"kql_lint_allowlist: failed to parse {target} ({exc})."]
    if not isinstance(data, dict):
        return (), [
            f"kql_lint_allowlist: {target} top-level is not a mapping; "
            "ignoring."
        ]

    raw_list = data.get("allowlist")
    if raw_list is None:
        return (), []
    if not isinstance(raw_list, list):
        return (), [
            f"kql_lint_allowlist: {target}:allowlist is not a list; ignoring."
        ]

    entries: list[AllowlistEntry] = []
    notes: list[str] = []
    for idx, raw in enumerate(raw_list):
        entry, note = _parse_entry(raw, idx)
        if note is not None:
            notes.append(note)
        if entry is not None:
            entries.append(entry)
    return tuple(entries), notes


def should_suppress(
    finding: LintFinding, allowlist: tuple[AllowlistEntry, ...],
) -> bool:
    """Return True iff the finding matches any allowlist entry.

    A match requires both rule_id AND pattern (against the finding
    message) to agree. The pattern is searched (not fullmatch'd) so
    operators can write column names directly without anchoring.
    """
    if not allowlist:
        return False
    for entry in allowlist:
        if entry.rule_id != finding.rule_id:
            continue
        if entry.pattern.search(finding.message):
            return True
    return False


__all__ = [
    "ALLOWED_RULES",
    "AllowlistEntry",
    "DEFAULT_CONFIG_PATH",
    "load_allowlist",
    "should_suppress",
]
