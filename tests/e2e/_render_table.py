# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Plain-text PASS / FAIL / SKIP table renderer for the e2e matrix.

Reads from either an in-memory list[_RowRecord] (called from conftest)
or a JSON sidecar (called from the PowerShell wrapper).

No external dependencies — uses ``str.ljust`` / ``str.rjust`` so we
don't pull in Rich just for one table.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Iterable, Sequence


_HEADER = ("CAPABILITY", "STATUS", "DURATION", "MESSAGE")


def render_rows(rows: Sequence[object]) -> str:
    """Render rows. Each row is expected to expose:

      * ``capability`` (str)
      * ``status``     (str — PASS / FAIL / SKIP)
      * ``duration_ms`` (float)
      * ``message``    (str)

    Both _RowRecord dataclasses and dicts work, so the same renderer
    can render the live in-memory collector and the JSON-sidecar
    output without conversion.
    """
    norm: list[tuple[str, str, str, str]] = []
    for r in rows:
        get = (lambda k: r.get(k, "")) if isinstance(r, dict) else (lambda k: getattr(r, k, ""))
        message_lines = str(get("message") or "").splitlines() or [""]
        norm.append((
            str(get("capability")),
            str(get("status")),
            f"{float(get('duration_ms') or 0.0):>8.1f} ms",
            message_lines[0][:80],
        ))

    if not norm:
        return "(no e2e results recorded)\n"

    widths = [
        max(len(_HEADER[0]), max(len(r[0]) for r in norm)),
        max(len(_HEADER[1]), max(len(r[1]) for r in norm)),
        max(len(_HEADER[2]), max(len(r[2]) for r in norm)),
        max(len(_HEADER[3]), max(len(r[3]) for r in norm)),
    ]

    def _row(r: tuple[str, str, str, str]) -> str:
        return (
            f"  {r[0].ljust(widths[0])}  "
            f"{r[1].ljust(widths[1])}  "
            f"{r[2].rjust(widths[2])}  "
            f"{r[3].ljust(widths[3])}"
        )

    lines: list[str] = [
        _row((_HEADER[0], _HEADER[1], _HEADER[2], _HEADER[3])),
        _row(("-" * widths[0], "-" * widths[1], "-" * widths[2], "-" * widths[3])),
    ]
    lines.extend(_row(r) for r in norm)

    pass_n = sum(1 for r in rows if (r.get("status") if isinstance(r, dict) else getattr(r, "status", "")) == "PASS")
    fail_n = sum(1 for r in rows if (r.get("status") if isinstance(r, dict) else getattr(r, "status", "")) == "FAIL")
    skip_n = sum(1 for r in rows if (r.get("status") if isinstance(r, dict) else getattr(r, "status", "")) == "SKIP")

    lines.append("")
    lines.append(
        f"Summary: {pass_n} PASS  |  {fail_n} FAIL  |  {skip_n} SKIP  "
        f"(total {len(rows)})"
    )
    return "\n".join(lines) + "\n"


def _main(argv: list[str]) -> int:
    """Standalone entry: ``python -m tests.e2e._render_table --json <path>``."""
    json_path: str | None = None
    i = 0
    while i < len(argv):
        if argv[i] == "--json" and i + 1 < len(argv):
            json_path = argv[i + 1]
            i += 2
        else:
            i += 1
    if json_path is None:
        sys.stderr.write("usage: _render_table.py --json <path>\n")
        return 2
    p = Path(json_path)
    if not p.exists():
        sys.stderr.write(f"no such file: {p}\n")
        return 1
    data = json.loads(p.read_text(encoding="utf-8"))
    sys.stdout.write(render_rows(data))
    return 0 if all(r.get("status") != "FAIL" for r in data) else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(_main(sys.argv[1:]))


__all__ = ["render_rows"]
