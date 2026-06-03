# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Pure-Python strict-mode lint rules (F1).

Strict rules encode *policy* — what is not allowed in production
detection logic — rather than the heuristic style/perf checks in
``contentops.lint.kql``. They run regardless of whether the optional
Kusto.Language wrapper (also gated on ``--strict``) is installed.

Adding a rule is intentionally cheap: write a function that takes
a query string and yields ``LintFinding``s, then append it to the
``RULES`` tuple at the bottom. Each rule is responsible for its
own ID, severity, and message — keep messages actionable.
"""

from __future__ import annotations

import re
from typing import Callable, Iterable

from contentops.lint.kql import LintFinding, _line_of, _strip_strings_and_comments


# ---------------------------------------------------------------------------
# KQL101 — `| take` / `| limit` forbidden in production rules
# ---------------------------------------------------------------------------

# Match the pipe-prefixed operator. Word boundary on the right
# avoids false positives on identifiers like `takeover`, `limited`.
_TAKE_OR_LIMIT = re.compile(r"\|\s*(take|limit)\b", re.IGNORECASE)


def no_take_or_limit(query: str) -> Iterable[LintFinding]:
    """KQL101 — `| take` and `| limit` are not allowed.

    Both operators cap the result set non-deterministically; in a
    deployed detection that means real telemetry volume is hidden,
    a noisy rule looks well-behaved during tuning, and once the
    cap is reached genuine alerts get dropped silently. Use
    ``top N by <field>`` for a deterministic bounded result, or
    remove the operator entirely and let the engine evaluate the
    full set.
    """
    stripped, _ = _strip_strings_and_comments(query)
    for m in _TAKE_OR_LIMIT.finditer(stripped):
        op = m.group(1).lower()
        yield LintFinding(
            rule_id="KQL101",
            severity="error",
            message=(
                f"`| {op}` is not allowed in production detections — it "
                f"caps results and masks true rule volume. Use "
                f"`top N by <field>` if a bounded result set is "
                f"required, or remove the operator."
            ),
            line=_line_of(query, m.start()),
        )


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

Rule = Callable[[str], Iterable[LintFinding]]

RULES: tuple[Rule, ...] = (
    no_take_or_limit,
)


def run_python_rules(query: str) -> list[LintFinding]:
    """Run every registered strict rule and collect findings."""
    findings: list[LintFinding] = []
    for rule in RULES:
        findings.extend(rule(query))
    return findings


__all__ = ["RULES", "Rule", "no_take_or_limit", "run_python_rules"]
