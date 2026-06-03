# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for scripts/check_version_bump.py — the semantic-diff version gate.

Covers the pure comparison core (``_requires_bump``): a cosmetic-only edit
must NOT demand a version bump, while a real content change with an
unchanged version must. The git plumbing (_changed_files / _file_at_ref)
is a thin subprocess wrapper exercised end-to-end in CI, not unit-tested
here.
"""

from __future__ import annotations

import sys
from pathlib import Path

# The script lives under scripts/ which isn't on sys.path by default.
SCRIPTS_DIR = Path(__file__).resolve().parents[2] / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

import check_version_bump as cvb  # noqa: E402


_BASE = """\
id: my-rule
version: 1.0.0
asset: sentinel_analytic
status: experimental
metadata:
  owner: secops@example.com
  severity: medium
payload:
  displayName: My Rule
  query: SecurityEvent | take 1
"""


def test_cosmetic_whitespace_diff_needs_no_bump() -> None:
    # Trailing whitespace + a blank line: byte-different, semantically same.
    head = _BASE.replace("status: experimental", "status: experimental   ") + "\n"
    assert cvb._requires_bump(head, _BASE) is None


def test_key_reorder_needs_no_bump() -> None:
    # Reorder top-level keys: dict equality ignores order.
    head = (
        "asset: sentinel_analytic\n"
        "id: my-rule\n"
        "version: 1.0.0\n"
        "status: experimental\n"
        "metadata:\n"
        "  severity: medium\n"
        "  owner: secops@example.com\n"
        "payload:\n"
        "  query: SecurityEvent | take 1\n"
        "  displayName: My Rule\n"
    )
    assert cvb._requires_bump(head, _BASE) is None


def test_comment_only_diff_needs_no_bump() -> None:
    head = "# a new comment\n" + _BASE
    assert cvb._requires_bump(head, _BASE) is None


def test_content_change_without_bump_fails() -> None:
    head = _BASE.replace("take 1", "take 999")  # query changed, version same
    msg = cvb._requires_bump(head, _BASE)
    assert msg is not None
    assert "version unchanged (1.0.0)" in msg


def test_content_change_with_bump_passes() -> None:
    head = _BASE.replace("take 1", "take 999").replace("version: 1.0.0", "version: 1.1.0")
    assert cvb._requires_bump(head, _BASE) is None


def test_unparseable_is_exempt() -> None:
    # The validate step owns malformed YAML; this gate must not double-fail.
    assert cvb._requires_bump("::: not yaml :::", _BASE) is None


def test_parse_doc_rejects_non_mapping() -> None:
    assert cvb._parse_doc("- just\n- a\n- list\n") is None
    assert cvb._parse_doc("id: x\nversion: 1.0.0\n") == {"id": "x", "version": "1.0.0"}
