# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Snippet substitution engine.

``apply_snippets(loaded, workspace_name)`` returns a new
``LoadedAsset`` whose KQL fields have been rewritten:

* every ``{{folder/file.yml}}`` placeholder is replaced with the
  resolved snippet content, OR
* if neither the workspace-specific nor the generic snippet file
  exists, the entire line containing the placeholder is dropped.

The function is pure (no env-var coupling, no I/O against the wire);
``workspace_name`` is passed in so callers can iterate per workspace
without env-var monkeypatching.
"""

from __future__ import annotations

import copy
import re
from dataclasses import replace
from pathlib import Path
from typing import Any

import click

from contentops.core.asset import KQL_FIELDS_BY_ASSET, Asset
from contentops.core.handler import LoadedAsset
from contentops.snippets.loader import SnippetFormatError, resolve_snippet


DEFAULT_OVERRIDES_ROOT = Path("overrides")


# Matches ``{{folder/file.yml}}`` and ``{{folder\file.yml}}``. The path
# segment allows letters, digits, ``_``, ``-``, ``.``, and the two
# separator forms; a trailing ``.yml`` is required so the file-on-disk
# identity is unambiguous from the KQL alone.
PLACEHOLDER_RE = re.compile(r"\{\{([A-Za-z0-9_\-./\\]+\.yml)\}\}")


# Backwards-compatible alias. The single source of truth lives in
# ``contentops.core.asset.KQL_FIELDS_BY_ASSET`` -- both the lint runner
# and this engine import the same dict so a future asset addition
# updates KQL coverage in one place. The previous duplicated maps
# diverged: ``sentinel_parser`` was missing from both, so parser KQL
# silently leaked ``{{...}}`` placeholders to ARM.
_KQL_FIELDS_BY_ASSET = KQL_FIELDS_BY_ASSET


class SnippetError(ValueError):
    """Raised when snippet substitution cannot complete (e.g. malformed
    snippet file). Distinct from ``SnippetFormatError`` so callers can
    handle "couldn't read a snippet" separately from the broader apply
    failure surface."""


def find_placeholders(text: str) -> list[str]:
    """Return the normalised relative paths of every placeholder in ``text``.

    Path separators normalised to ``/``. Order preserved (first
    occurrence wins for duplicates).
    """
    seen: dict[str, None] = {}
    for match in PLACEHOLDER_RE.finditer(text):
        rel = match.group(1).replace("\\", "/")
        seen.setdefault(rel, None)
    return list(seen.keys())


def _normalised_placeholder(literal: str) -> str:
    """Convert a placeholder literal (with ``\\`` or ``/``) to the
    canonical ``/`` form for resolver lookup."""
    return literal.replace("\\", "/")


def _substitute_text(
    text: str,
    *,
    overrides_root: Path,
    workspace_name: str | None,
    asset_id: str | None = None,
) -> str:
    """Apply the 3-tier resolution to every placeholder in ``text``.

    Lines whose only resolvable placeholder is missing-on-both-paths
    are dropped (KQLOVERRIDE003 lint rule guarantees the placeholder
    is alone on its line, so dropping the line is always safe). A
    ``click.echo`` warning is emitted on stderr for each dropped
    line so operators see the fallback in the apply summary instead
    of silently shipping a narrowed rule.

    NOTE: When a line carries multiple placeholders and any one of
    them is unresolvable, the whole line is dropped (including any
    siblings that DID resolve). KQLOVERRIDE003 still allows multiple
    placeholders on one line; operators who want partial-resolution
    semantics should put each placeholder on its own line. This is
    documented in ``docs/operations/multi-workspace.md``.
    """
    if "{{" not in text:
        return text  # cheap fast-path: no placeholders at all

    ws_label = workspace_name or "<no-workspace>"
    asset_label = f"asset={asset_id} " if asset_id else ""

    out_lines: list[str] = []
    for line_no, line in enumerate(text.split("\n"), start=1):
        if "{{" not in line:
            out_lines.append(line)
            continue

        # Resolve every placeholder on this line. If any placeholder is
        # unresolved (both files missing), the whole line is dropped.
        first_unresolved: str | None = None
        rewritten = line
        for match in PLACEHOLDER_RE.finditer(line):
            literal = match.group(0)  # ``{{folder/file.yml}}``
            rel = _normalised_placeholder(match.group(1))
            try:
                resolved = resolve_snippet(
                    overrides_root, rel, workspace_name,
                )
            except SnippetFormatError as exc:
                raise SnippetError(str(exc)) from exc
            if resolved is None:
                first_unresolved = literal
                break
            rewritten = rewritten.replace(literal, resolved)

        if first_unresolved is None:
            out_lines.append(rewritten)
        else:
            click.echo(
                f"[snippets] {asset_label}dropped line {line_no} "
                f"(placeholder {first_unresolved} unresolved in "
                f"workspace={ws_label})",
                err=True,
            )

    return "\n".join(out_lines)


def _set_dotted(
    payload: dict[str, Any], dotted: str, value: str,
) -> bool:
    """Set ``dotted`` (e.g. ``queryCondition.queryText``) in ``payload``.

    Returns True when the key existed and was updated, False when the
    path didn't fully resolve (caller should leave payload untouched
    for that field). Used for the few Defender envelopes that nest the
    KQL under a sub-key.
    """
    cur: Any = payload
    parts = dotted.split(".")
    for part in parts[:-1]:
        if not isinstance(cur, dict) or part not in cur:
            return False
        cur = cur[part]
    if not isinstance(cur, dict) or parts[-1] not in cur:
        return False
    cur[parts[-1]] = value
    return True


def apply_snippets(
    loaded: LoadedAsset,
    workspace_name: str | None,
    *,
    overrides_root: Path = DEFAULT_OVERRIDES_ROOT,
) -> LoadedAsset:
    """Return a new ``LoadedAsset`` with placeholders resolved.

    For Defender envelopes, ``workspace_name`` is forced to ``None``
    (Defender is tenant-scoped — only the generic tier applies).

    The original ``loaded`` is never mutated; this function deep-copies
    the payload before rewriting so the per-workspace iteration in
    ``apply_cmd`` / ``plan_cmd`` reuses the same ``loaded`` list across
    workspaces without cross-talk.
    """
    asset = loaded.envelope.asset
    fields = _KQL_FIELDS_BY_ASSET.get(asset)
    if not fields:
        return loaded  # asset has no KQL field; nothing to substitute

    # Defender is tenant-scoped — generic-only lookup.
    effective_ws = (
        None if asset.value.startswith("defender_") else workspace_name
    )

    new_payload = copy.deepcopy(loaded.payload)
    changed = False
    for dotted in fields:
        current = _get_dotted(new_payload, dotted)
        if not isinstance(current, str):
            continue
        if "{{" not in current:
            continue
        rewritten = _substitute_text(
            current,
            overrides_root=overrides_root,
            workspace_name=effective_ws,
            asset_id=loaded.envelope.id,
        )
        if rewritten != current:
            _set_dotted(new_payload, dotted, rewritten)
            changed = True

    if not changed:
        return loaded

    return replace(loaded, payload=new_payload)


def _get_dotted(payload: dict[str, Any], dotted: str) -> Any:
    cur: Any = payload
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


__all__ = [
    "DEFAULT_OVERRIDES_ROOT",
    "PLACEHOLDER_RE",
    "SnippetError",
    "apply_snippets",
    "find_placeholders",
]
