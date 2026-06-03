# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Pure-Python KQL lint rules.

Conservative, false-positive-averse checks. We deliberately avoid a real
KQL parser to keep zero install friction; richer checks belong behind a
future `--strict` mode that shells out to `Kusto.Language`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class LintFinding:
    rule_id: str
    severity: str
    message: str
    line: int | None = None


SEVERITY_RANK: dict[str, int] = {"info": 0, "warning": 1, "error": 2}


def _strip_strings_and_comments(query: str) -> tuple[str, bool]:
    """Return a copy of `query` with string contents and `//` line comments
    replaced by spaces (newlines preserved), plus a flag for whether the
    scanner ended inside an unterminated string.

    Recognises three string forms:

    * Regular ``"..."`` and ``'...'`` — backslash escapes the next char;
      the matching quote ends the string.
    * Kusto verbatim ``@"..."`` and ``@'...'`` — backslash is literal
      (so Windows paths like ``@"C:\\Windows\\"`` don't trip the
      ``unterminated string`` check); the matching quote ends the string,
      with ``""``/``''`` doubling to embed a literal quote.

    Without verbatim handling, common Defender custom detections that
    use ``@"..."`` for filesystem paths produced false-positive
    ``KQL003 unterminated string`` and ``KQL001 unbalanced bracket``
    findings whenever a path ended in a backslash.
    """
    out: list[str] = []
    i = 0
    n = len(query)
    # ``in_str`` is the closing quote character for non-verbatim strings,
    # ``in_verbatim`` is the closing quote character for verbatim strings.
    in_str: str | None = None
    in_verbatim: str | None = None
    while i < n:
        c = query[i]
        if in_verbatim is not None:
            # Doubled-quote escape: ``""`` inside @"..." is a literal ".
            if c == in_verbatim and i + 1 < n and query[i + 1] == in_verbatim:
                out.append("  ")
                i += 2
                continue
            if c == in_verbatim:
                in_verbatim = None
                out.append(" ")
                i += 1
                continue
            out.append("\n" if c == "\n" else " ")
            i += 1
            continue
        if in_str is not None:
            if c == "\\" and i + 1 < n:
                out.append(" ")
                nxt = query[i + 1]
                out.append("\n" if nxt == "\n" else " ")
                i += 2
                continue
            if c == in_str:
                in_str = None
                out.append(" ")
                i += 1
                continue
            out.append("\n" if c == "\n" else " ")
            i += 1
            continue
        if c == "/" and i + 1 < n and query[i + 1] == "/":
            while i < n and query[i] != "\n":
                out.append(" ")
                i += 1
            continue
        # Kusto verbatim string opener: @" or @'
        if c == "@" and i + 1 < n and query[i + 1] in ('"', "'"):
            in_verbatim = query[i + 1]
            out.append("  ")
            i += 2
            continue
        if c == '"' or c == "'":
            in_str = c
            out.append(" ")
            i += 1
            continue
        out.append(c)
        i += 1
    # An unterminated verbatim string is the same defect as a regular one.
    return "".join(out), (in_str is not None or in_verbatim is not None)


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _check_balanced_brackets(query: str, stripped: str) -> list[LintFinding]:
    pairs = {")": "(", "]": "[", "}": "{"}
    openers = set(pairs.values())
    closers = set(pairs.keys())
    stack: list[tuple[str, int]] = []
    findings: list[LintFinding] = []
    for idx, c in enumerate(stripped):
        if c in openers:
            stack.append((c, idx))
        elif c in closers:
            if not stack or stack[-1][0] != pairs[c]:
                findings.append(LintFinding(
                    "KQL001", "error",
                    f"unbalanced bracket: unexpected '{c}'",
                    _line_of(query, idx),
                ))
                if stack:
                    stack.pop()
            else:
                stack.pop()
    if stack:
        opener, off = stack[0]
        findings.append(LintFinding(
            "KQL001", "error",
            f"unbalanced bracket: '{opener}' never closed",
            _line_of(query, off),
        ))
    return findings


def _check_unterminated_string(ended_in_string: bool) -> list[LintFinding]:
    if ended_in_string:
        return [LintFinding(
            "KQL002", "error",
            "unterminated string at end of query",
        )]
    return []


def _check_non_empty(query: str) -> list[LintFinding]:
    cleaned_lines: list[str] = []
    for line in query.splitlines():
        cleaned_lines.append(line.split("//", 1)[0])
    if not "".join(cleaned_lines).strip():
        return [LintFinding("KQL003", "error", "query is empty")]
    return []


_PROJECT_STAR = re.compile(r"\bproject\s*\*", re.IGNORECASE)


def _check_project_star(query: str, stripped: str) -> list[LintFinding]:
    out: list[LintFinding] = []
    for m in _PROJECT_STAR.finditer(stripped):
        out.append(LintFinding(
            "KQL004", "warning",
            "avoid `project *` (perf risk; project explicit columns)",
            _line_of(query, m.start()),
        ))
    return out


_BARE_TAKE = re.compile(r"\|\s*take(?:\s+(?!\d)\S+|\s*$|\s*\|)", re.MULTILINE | re.IGNORECASE)


def _check_bare_take(query: str, stripped: str) -> list[LintFinding]:
    out: list[LintFinding] = []
    for m in _BARE_TAKE.finditer(stripped):
        out.append(LintFinding(
            "KQL005", "warning",
            "`| take` without explicit numeric limit",
            _line_of(query, m.start()),
        ))
    return out


_BAG_UNPACK = re.compile(r"\bevaluate\s+bag_unpack\b", re.IGNORECASE)


def _check_bag_unpack(query: str, stripped: str) -> list[LintFinding]:
    out: list[LintFinding] = []
    for m in _BAG_UNPACK.finditer(stripped):
        out.append(LintFinding(
            "KQL006", "warning",
            "`evaluate bag_unpack` can be expensive; consider explicit columns",
            _line_of(query, m.start()),
        ))
    return out


_UNION_STAR = re.compile(
    r"\bunion\b(?:\s+(?:isfuzzy|kind|withsource)\s*=\s*\w+)*\s+\*(?=\s|$|,|\|)",
    re.IGNORECASE,
)


def _check_union_star(query: str, stripped: str) -> list[LintFinding]:
    out: list[LintFinding] = []
    for m in _UNION_STAR.finditer(stripped):
        out.append(LintFinding(
            "KQL007", "error",
            "`union *` fans out across all tables; enumerate sources explicitly",
            _line_of(query, m.start()),
        ))
    return out


_EXTERNALDATA = re.compile(r"\bexternaldata\s*\(", re.IGNORECASE)


def _check_externaldata(query: str, stripped: str) -> list[LintFinding]:
    out: list[LintFinding] = []
    for m in _EXTERNALDATA.finditer(stripped):
        out.append(LintFinding(
            "KQL008", "warning",
            "`externaldata()` references external infrastructure — "
            "ensure the source URL is approved and auditable",
            _line_of(query, m.start()),
        ))
    return out


_CROSS_SCOPE = re.compile(r"\b(cluster|workspace)\s*\(", re.IGNORECASE)


def _check_cross_scope(query: str, stripped: str) -> list[LintFinding]:
    out: list[LintFinding] = []
    for m in _CROSS_SCOPE.finditer(stripped):
        op = m.group(1)
        out.append(LintFinding(
            "KQL010", "error",
            f"`{op}()` crosses workspace/cluster scope — detections must "
            "target only the workspace they are deployed to",
            _line_of(query, m.start()),
        ))
    return out


def lint_kql(query: str, *, kind: str | None = None) -> list[LintFinding]:
    """Run all KQL lint rules over `query`.

    `kind` (optional) is accepted for forward compatibility with rules
    that key off the asset kind; the current heuristic rules are kind-
    agnostic.
    """
    del kind  # currently unused; reserved for future per-kind rules
    findings: list[LintFinding] = []
    findings.extend(_check_non_empty(query))
    stripped, ended_in_string = _strip_strings_and_comments(query)
    findings.extend(_check_balanced_brackets(query, stripped))
    findings.extend(_check_unterminated_string(ended_in_string))
    findings.extend(_check_project_star(query, stripped))
    findings.extend(_check_bare_take(query, stripped))
    findings.extend(_check_bag_unpack(query, stripped))
    findings.extend(_check_union_star(query, stripped))
    findings.extend(_check_externaldata(query, stripped))
    findings.extend(_check_cross_scope(query, stripped))
    return findings


def at_or_above(findings: Iterable[LintFinding], threshold: str) -> list[LintFinding]:
    floor = SEVERITY_RANK[threshold]
    return [f for f in findings if SEVERITY_RANK[f.severity] >= floor]


__all__ = ["LintFinding", "SEVERITY_RANK", "lint_kql", "at_or_above"]
