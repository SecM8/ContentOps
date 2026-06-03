# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Lint rules for KQL snippet placeholders.

The substitution engine in ``contentops/snippets/`` resolves
``{{folder/file.yml}}`` placeholders against ``overrides/`` at apply
time. These lint rules enforce the syntax + safety constraints so a
malformed placeholder fails at PR time, not at deploy time.

Rules:

* ``KQLOVERRIDE001`` - placeholder must match the strict regex
  ``\\{\\{[A-Za-z0-9_\\-./\\\\]+\\.yml\\}\\}``. Catches leading /
  trailing whitespace, missing ``.yml`` suffix, illegal characters.

* ``KQLOVERRIDE002`` - the path inside the placeholder must be
  relative, with no ``..`` segments and no leading ``/`` or ``\\``.
  Defends against path traversal during resolution.

* ``KQLOVERRIDE003`` - the placeholder must be the only non-whitespace
  token on its line (trailing ``//`` line comments tolerated). The
  3-tier resolution drops the entire line on a both-missing fallback,
  so a placeholder mid-line would silently delete surrounding KQL.

  KNOWN LIMITATION: the ``//`` comment strip is a naive
  ``line.find('//')``, NOT a KQL-aware tokeniser. A line that places a
  placeholder on the same line as a KQL string literal containing
  ``//`` (e.g. ``where Url contains "https://example.com"``) may have
  its tail truncated by the heuristic before the residue check. In
  practice placeholders almost always live on their own line; if the
  edge case bites you, move the placeholder to its own line.

* ``KQLOVERRIDE004`` - every file under ``overrides/**/*.yml`` must
  parse as YAML and contain a ``content:`` (string) key.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from contentops.lint.kql import LintFinding


# Strict shape: any character class change here MUST keep the
# placeholder regex in contentops/snippets/apply.py in sync.
_STRICT_PLACEHOLDER_RE = re.compile(r"\{\{([A-Za-z0-9_\-./\\]+\.yml)\}\}")
# Loose shape: matches anything between ``{{`` and ``}}`` so we can
# fail KQLOVERRIDE001 on malformed forms (e.g. extra spaces, missing
# ``.yml``) instead of silently ignoring them.
_LOOSE_PLACEHOLDER_RE = re.compile(r"\{\{(.*?)\}\}")


def lint_kql_placeholders(query: str) -> list[LintFinding]:
    """Run KQLOVERRIDE001 / 002 / 003 against a single KQL string.

    Returns one finding per violation; a single line can produce
    multiple findings (e.g. mid-line + bad syntax = two errors).
    """
    if "{{" not in query and "}}" not in query:
        return []

    findings: list[LintFinding] = []

    for line_no, line in enumerate(query.split("\n"), start=1):
        if "{{" not in line and "}}" not in line:
            continue

        for loose in _LOOSE_PLACEHOLDER_RE.finditer(line):
            inner = loose.group(1)
            literal = loose.group(0)

            # KQLOVERRIDE001 - strict syntax
            strict_ok = bool(_STRICT_PLACEHOLDER_RE.fullmatch(literal))
            if not strict_ok:
                findings.append(LintFinding(
                    rule_id="KQLOVERRIDE001",
                    severity="error",
                    message=(
                        f"snippet placeholder {literal!r} is malformed; "
                        "expected exactly '{{folder/file.yml}}' (no spaces, "
                        "trailing '.yml' required)"
                    ),
                    line=line_no,
                ))
                # If it's not even valid syntax, the path-inside-it
                # checks would be misleading. Keep going so the operator
                # sees every placeholder's complaints, but skip the
                # path-traversal sub-check when the inner is empty.
                if not inner:
                    continue

            # KQLOVERRIDE002 - path traversal / absolute paths
            normalised = inner.replace("\\", "/")
            traversal = (
                normalised.startswith("/")
                or ".." in normalised.split("/")
            )
            if traversal:
                findings.append(LintFinding(
                    rule_id="KQLOVERRIDE002",
                    severity="error",
                    message=(
                        f"snippet placeholder {literal!r} resolves to an "
                        "unsafe path (absolute or contains '..'); use a "
                        "relative path under overrides/"
                    ),
                    line=line_no,
                ))

        # KQLOVERRIDE003 - placeholder must be the only non-whitespace
        # token on its line (modulo a trailing // comment)
        if _STRICT_PLACEHOLDER_RE.search(line) is None:
            continue
        # Strip everything after a '//' line comment first so 'foo //
        # explanation' isn't penalised when 'foo' is a placeholder.
        comment_idx = line.find("//")
        scan = line if comment_idx < 0 else line[:comment_idx]
        # Strip every strict placeholder from the line; what remains
        # must be whitespace only.
        residue = _STRICT_PLACEHOLDER_RE.sub("", scan).strip()
        if residue:
            findings.append(LintFinding(
                rule_id="KQLOVERRIDE003",
                severity="error",
                message=(
                    "snippet placeholder must be the only non-whitespace "
                    "token on its line (trailing '//' comment allowed); "
                    "place '{{...}}' on its own line so the both-missing "
                    "fallback can drop the line cleanly"
                ),
                line=line_no,
            ))

    return findings


def lint_overrides_directory(overrides_root: Path) -> list[tuple[Path, LintFinding]]:
    """KQLOVERRIDE004 - validate every ``overrides/**/*.yml`` file shape.

    Returns ``(file_path, finding)`` pairs. Caller wires findings into
    its per-file reporting structure (overrides files don't have an
    ``Asset`` so they don't fit the ``LintedFile`` shape natively).
    """
    if not overrides_root.exists():
        return []

    out: list[tuple[Path, LintFinding]] = []
    for path in sorted(overrides_root.rglob("*.yml")):
        if not path.is_file():
            continue
        try:
            raw = path.read_text(encoding="utf-8")
            parsed = yaml.safe_load(raw)
        except (OSError, yaml.YAMLError) as exc:
            out.append((path, LintFinding(
                rule_id="KQLOVERRIDE004",
                severity="error",
                message=f"snippet file unreadable / not valid YAML: {exc}",
            )))
            continue
        if not isinstance(parsed, dict):
            out.append((path, LintFinding(
                rule_id="KQLOVERRIDE004",
                severity="error",
                message=(
                    "snippet file top-level must be a mapping with a "
                    "'content:' key; got "
                    f"{type(parsed).__name__}"
                ),
            )))
            continue
        if "content" not in parsed:
            out.append((path, LintFinding(
                rule_id="KQLOVERRIDE004",
                severity="error",
                message="snippet file missing required 'content:' key",
            )))
            continue
        if not isinstance(parsed["content"], str):
            out.append((path, LintFinding(
                rule_id="KQLOVERRIDE004",
                severity="error",
                message=(
                    "snippet file 'content' must be a string; got "
                    f"{type(parsed['content']).__name__}"
                ),
            )))

    return out


__all__ = [
    "lint_kql_placeholders",
    "lint_overrides_directory",
]
