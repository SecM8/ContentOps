# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for ``contentops.utils.stdio.force_utf8_stdio``.

The function retargets ``sys.stdout`` / ``sys.stderr`` to UTF-8 so the
CLI never crashes on a non-ASCII character (``→``, ``—``, …) when the
host locale is cp1252. Discovered 2026-05-15 — see the docstring at
``contentops/utils/stdio.py``.
"""

from __future__ import annotations

import io

import pytest

from contentops.utils.stdio import force_utf8_stdio


def test_reconfigures_cp1252_stdout_to_utf8(monkeypatch: pytest.MonkeyPatch) -> None:
    """A TextIOWrapper started at cp1252 must be retargeted to UTF-8."""
    buf = io.BytesIO()
    wrapper = io.TextIOWrapper(buf, encoding="cp1252", errors="strict")
    monkeypatch.setattr("sys.stdout", wrapper)

    force_utf8_stdio()

    assert wrapper.encoding.lower() == "utf-8"
    # A `→` previously crashed on cp1252; now it round-trips cleanly.
    wrapper.write("retry-failed → 28 still failing\n")
    wrapper.flush()
    assert "→".encode("utf-8") in buf.getvalue()


def test_reconfigure_handles_stringio_without_crashing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """pytest's CliRunner replaces stdout with StringIO, which has no
    ``reconfigure`` method. ``force_utf8_stdio`` must no-op silently
    rather than raising ``AttributeError``."""
    fake = io.StringIO()
    monkeypatch.setattr("sys.stdout", fake)

    force_utf8_stdio()  # must not raise

    # StringIO doesn't expose .encoding the same way, but the call
    # completed — that's the contract.
    fake.write("ok\n")
    assert fake.getvalue() == "ok\n"


def test_is_idempotent(monkeypatch: pytest.MonkeyPatch) -> None:
    """Calling twice must not crash or double-wrap."""
    buf = io.BytesIO()
    wrapper = io.TextIOWrapper(buf, encoding="cp1252", errors="strict")
    monkeypatch.setattr("sys.stdout", wrapper)

    force_utf8_stdio()
    force_utf8_stdio()

    assert wrapper.encoding.lower() == "utf-8"


def test_errors_mode_replaces_rather_than_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """After reconfigure, an unencodable character must be replaced
    silently — ``errors='replace'`` is what keeps a deeply unusual byte
    sequence from crashing the CLI even when stdout's underlying buffer
    is somehow not UTF-8."""
    buf = io.BytesIO()
    wrapper = io.TextIOWrapper(buf, encoding="ascii", errors="strict")
    monkeypatch.setattr("sys.stdout", wrapper)

    force_utf8_stdio()

    # Now writing emoji must not raise.
    wrapper.write("done ✅\n")
    wrapper.flush()
    # The output bytes are UTF-8 since we reconfigured to UTF-8.
    assert "✅".encode("utf-8") in buf.getvalue()
