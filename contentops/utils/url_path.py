# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Safe URL path segments for ARM and Graph resource names.

Resource names reach URL builders from YAML (``metadata.arm_name``, the
envelope id, a watchlist alias, a Graph rule id). They are interpolated
into a request path, and httpx normalises ``..`` segments before sending,
so an unchecked name such as ``../../automationRules/x`` would address a
different resource with the deploy identity. Every name therefore goes
through :func:`safe_path_segment`: dangerous values are rejected and the
rest are percent-encoded so they can only ever be one path segment.

The check is a deny-list, not a GUID allow-list: real ARM names include
non-GUID values (``BuiltInFusion``, slug envelope ids, watchlist aliases,
numeric Graph ids), and a narrow allow-list would break them.
"""

from __future__ import annotations

from urllib.parse import quote


class UnsafePathSegment(ValueError):
    """A resource name that cannot be used as a single URL path segment."""


# Characters that change how a URL is parsed: path separators, the query /
# fragment delimiters, and ``%`` (a pre-encoded ``%2e%2e`` or ``%2f`` would
# otherwise survive as a traversal after the server decodes it).
_FORBIDDEN_CHARS = frozenset("/\\?#%")


def safe_path_segment(value: object, *, kind: str = "resource name") -> str:
    """Return ``value`` percent-encoded as exactly one URL path segment.

    Raises :class:`UnsafePathSegment` for an empty value, ``.`` or ``..``,
    any of ``/ \\ ? # %``, or a control character. ``kind`` names the value
    in the error message (e.g. ``"alert rule name"``).
    """
    text = "" if value is None else str(value)
    if not text or not text.strip():
        raise UnsafePathSegment(f"{kind} is empty")
    if text in (".", ".."):
        raise UnsafePathSegment(f"{kind} {text!r} is a relative path segment")
    bad = sorted({ch for ch in text if ch in _FORBIDDEN_CHARS})
    if bad:
        raise UnsafePathSegment(
            f"{kind} {text!r} contains a character that is not allowed in a "
            f"resource name: {' '.join(bad)}"
        )
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in text):
        raise UnsafePathSegment(f"{kind} {text!r} contains a control character")
    return quote(text, safe="")


__all__ = ["UnsafePathSegment", "safe_path_segment"]
