# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Slug helpers for envelope ids derived from human-readable display names.

Collected resources arrive with two identifiers: a server-side ARM
``name`` (often a GUID) and a human ``displayName``. Filenames in
``detections/<asset>/`` should track the displayName so an analyst can
find a rule by its title; the GUID lives on under
``metadata.arm_name`` so apply / delete still address the right
remote resource.

The functions here are pure — collision handling lives at the
collect-orchestration layer (we only have visibility of name
collisions across the full inventory, not from a single envelope
in isolation).
"""

from __future__ import annotations

import re

_NON_SLUG = re.compile(r"[^a-z0-9]+")
_ID_RE = re.compile(r"^[a-z0-9][a-z0-9\-]*[a-z0-9]$")
_SLUG_MAX_LEN = 80


def displayname_slug(name: str | None, fallback_id: str | None = None) -> str:
    """Convert a displayName into a filesystem- and envelope-id-safe slug.

    Rules:
      * lowercase
      * replace any char not in ``[a-z0-9]`` with ``-``
      * collapse runs of ``-``
      * strip leading / trailing ``-``
      * cap length at 80 chars

    If the result is empty (or ``name`` is ``None`` / pure punctuation),
    returns ``displayname_slug(fallback_id, None)``. If both are empty,
    returns ``""`` — the caller is expected to skip the resource.
    """
    candidate = (name or "").strip().lower()
    slug = _NON_SLUG.sub("-", candidate).strip("-")
    if len(slug) > _SLUG_MAX_LEN:
        slug = slug[:_SLUG_MAX_LEN].rstrip("-")
    if slug and _ID_RE.match(slug):
        return slug
    if fallback_id is None:
        return ""
    fallback_clean = (fallback_id or "").strip().lower()
    fallback_slug = _NON_SLUG.sub("-", fallback_clean).strip("-")
    if len(fallback_slug) > _SLUG_MAX_LEN:
        fallback_slug = fallback_slug[:_SLUG_MAX_LEN].rstrip("-")
    if fallback_slug and _ID_RE.match(fallback_slug):
        return fallback_slug
    return ""


def arm_name_suffix(arm_name: str | None) -> str:
    """First 8 chars of ``arm_name`` after stripping non-alphanumerics.

    Used to disambiguate two envelopes whose displayNames slug to the
    same value. A bare GUID like ``1840b991-a12b-4e67-a685-...`` yields
    ``1840b991`` so the suffix is human-recognisable in filenames.
    """
    if not arm_name:
        return ""
    cleaned = re.sub(r"[^a-z0-9]+", "", arm_name.lower())
    return cleaned[:8]


def disambiguate(slug: str, arm_name: str | None) -> str:
    """Return ``slug`` suffixed with ``-<arm8>`` for collision resolution.

    Falls back to ``slug`` unchanged if no usable arm8 can be derived
    (so the caller can pin a stable id even when the ARM name is
    pathological).
    """
    suffix = arm_name_suffix(arm_name)
    if not suffix:
        return slug
    base_max = _SLUG_MAX_LEN - len(suffix) - 1
    base = slug[:base_max].rstrip("-") if base_max > 0 else slug
    return f"{base}-{suffix}" if base else suffix


def is_valid_envelope_id(value: str) -> bool:
    """True if ``value`` matches the strict envelope-id regex."""
    return bool(_ID_RE.match(value))
