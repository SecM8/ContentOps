# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Redact tenant-identifying values from status markdown.

The status-refresh workflow commits ``docs/status/configuration.md``
to the repo every day. When that page reflects L3-L7 conformance, the
underlying :class:`contentops.devex.conformance.ConformanceReport`
carries detail strings that include Azure tenant identifiers --
subscription IDs, GUID-shaped tenant / app object IDs, full ARM
resource paths. Even truncated 8-char GUID prefixes leak more than is
healthy for a file that lives in the public-mirror surface.

This module is the structural defence: every ``detail`` and
``remediation`` cell flows through :func:`redact` before it lands in
the rendered markdown. The complementary belt is a ``.gitleaks.toml``
rule that scans ``docs/status/*.md`` for raw GUIDs, so a bug in the
redactor surfaces at CI time rather than after a commit lands.

Redacted:

* Full GUIDs (8-4-4-4-12 hex) -> ``<redacted-guid>``.
* Truncated GUID prefixes (8 hex digits followed by ``...`` or U+2026
  ellipsis -- the format ``contentops conformance`` uses to surface
  the first 8 chars of a tenant / sub / object ID) -> ``<redacted>``.
* Full Azure ARM resource paths ``/subscriptions/<id>/resourceGroups/
  <name>/providers/...`` -> ``<redacted-resource-path>``. The path
  carries subscription + RG + workspace name in one substring; the
  whole match goes.

Preserved (operator-readable, not sensitive on a private repo):

* Workspace names by themselves (``law-sentinel-prod``).
* Asset kinds (``sentinel_analytic``).
* AAD error codes (``AADSTS7000215``).
* App Registration display names (``ContentOps``).
* HTTP status codes and counts (``200, 5 rule(s)``).
"""

from __future__ import annotations

import re

# Full 8-4-4-4-12 hex GUID. Case-insensitive. ``\b`` anchors so we
# don't accidentally clip a longer hash that happens to start with a
# GUID-shaped prefix.
_GUID_RE = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
    re.IGNORECASE,
)

# Truncated GUID prefix: 8 hex digits followed by ``...`` (three or
# more dots) or U+2026 (...). ``contentops conformance`` uses both
# styles depending on which check produced the detail string.
_GUID_TRUNCATED_RE = re.compile(
    r"\b[0-9a-f]{8}(?:\.{3,}|…)",
    re.IGNORECASE,
)

# Full Azure resource path. Matches up to the next whitespace, closing
# parenthesis, or closing bracket -- the path almost always sits inside
# prose like "lacks Reader on /subscriptions/.../workspaces/foo (RBAC
# role assignment missing)". The greedy form is fine because resource
# paths don't contain unescaped whitespace.
_RESOURCE_PATH_RE = re.compile(
    r"/subscriptions/[^/\s]+/resourceGroups/[^/\s]+/providers/[^\s\)\]]*",
    re.IGNORECASE,
)


def redact(text: str) -> str:
    """Replace tenant-identifying substrings with stable placeholder tokens.

    Idempotent: running on already-redacted text is a no-op.
    """
    if not text:
        return text
    out = _RESOURCE_PATH_RE.sub("<redacted-resource-path>", text)
    out = _GUID_RE.sub("<redacted-guid>", out)
    out = _GUID_TRUNCATED_RE.sub("<redacted>", out)
    return out


__all__ = ["redact"]
