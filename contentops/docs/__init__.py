# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Per-detection markdown documentation generator.

Borrowed from NVISO Part 4 of the Detection-as-Code series. Renders
each detection envelope into its own markdown page under
``docs/detections/<id>.md`` plus an index at ``docs/detections/README.md``,
so SOC analysts can browse the corpus without parsing YAML.

Parallel to :mod:`contentops.catalog` — same byte-identical-output
pure-function pattern and same CI drift gate. NOT an extension of
``catalog/render.py``: that module renders code-introspection
(``Inventory``); this one renders envelope content.

Public surface:

* :func:`render_all` — pure function: list of loaded envelopes in,
  ``dict[str, str]`` keyed by repo-relative path out.

CLI lives in ``contentops/cli/commands/detection_docs.py``.
"""

from __future__ import annotations

from contentops.docs.render import (
    DETECTION_DOCS_DIR,
    INDEX_FILE,
    render_all,
    render_detection,
    render_index,
)

__all__ = [
    "DETECTION_DOCS_DIR",
    "INDEX_FILE",
    "render_all",
    "render_detection",
    "render_index",
]
