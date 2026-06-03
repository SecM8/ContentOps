# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Stdio helpers — UTF-8 reconfigure for the CLI entry-point.

On Windows the default Python stdout codepage tracks the host locale
(cp1252 on many EN/EU installs), which raises ``UnicodeEncodeError``
when CLI output contains characters like ``→`` (U+2192) or ``—``
(U+2014). Operators have to set ``PYTHONIOENCODING=utf-8`` before every
invocation as a workaround.

This module centralises the fix: ``force_utf8_stdio()`` retargets
``sys.stdout`` / ``sys.stderr`` to UTF-8 with ``errors='replace'`` so a
stray non-ASCII character never crashes the CLI. It's idempotent and
no-ops on streams that don't expose ``reconfigure`` (pytest's
``CliRunner`` swaps stdout for a ``StringIO`` during tests; that path
short-circuits cleanly).

Discovered 2026-05-15 when ``contentops retry-failed --role
integration`` crashed at ``contentops/cli/commands/lifecycle.py:320``
on a Windows PowerShell session. The fix lives at CLI entry rather
than at the offending call site so future non-ASCII output is also
covered without per-call instrumentation.
"""

from __future__ import annotations

import sys


def force_utf8_stdio() -> None:
    """Reconfigure stdout + stderr to UTF-8 with replace-on-error.

    Safe to call multiple times. No-ops when the stream is not a
    ``TextIOWrapper`` (e.g. pytest capture buffers). Swallows
    ``ValueError`` / ``OSError`` from ``reconfigure`` so a deeply
    unusual host stdout can't break CLI startup.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except (ValueError, OSError):  # pragma: no cover — defensive
                pass
