# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Defender custom-detection round-trip diagnostic surface.

The diff engine itself was extracted to
``contentops/utils/roundtrip_diff.py`` so the new Sentinel
roundtrip-diff command can share the renderer (
single-source-of-truth pattern, mirroring KQL_FIELDS_BY_ASSET in
PR #138). The Defender CLI command in
``contentops/cli/commands/diagnostics.py`` continues to import
``FieldDiff`` / ``diff_bodies`` / ``render_diff`` from THIS module
to preserve the historical import surface; this module re-exports
them as a thin shim.

When ``contentops apply`` reports ``verified=False`` with status
``MISMATCH`` for a Defender custom detection, the cause is always
the same: the post-apply GET of the rule returns a body whose
``compute_content_hash(_HASHED_FIELDS)`` projection differs from
the pre-PUT body's hash. Once we know the offending field, the
fix is either:

* Remove it from ``_HASHED_FIELDS`` in
  ``contentops/handlers/defender_custom_detection.py`` if the
  server's normalisation doesn't change semantic content (most
  common -- e.g. ISO duration formatting, whitespace folding in
  KQL).
* Add canonicalisation in ``to_envelope`` (collect-time) or
  ``to_defender_body`` (apply-time) so both sides see the same
  form.
"""

from __future__ import annotations

from contentops.utils.roundtrip_diff import FieldDiff, diff_bodies, render_diff


__all__ = ["FieldDiff", "diff_bodies", "render_diff"]
