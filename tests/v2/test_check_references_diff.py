# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for the --diff-base PR-time path in scripts/check_references.py.

Verifies that the diff-mode extractor surfaces only URLs newly
introduced by the PR's changes, leaving the weekly scheduled run
to cover the full corpus.
"""

from __future__ import annotations

import sys
from collections import defaultdict
from pathlib import Path

import pytest

# The script lives under scripts/ which isn't on sys.path by default.
SCRIPTS_DIR = Path(__file__).resolve().parents[2] / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

import check_references as cr  # noqa: E402


def test_extract_urls_from_blob_picks_references_and_runbook() -> None:
    blob = """
id: x
metadata:
  runbookUrl: https://runbook.example.com/x
  references:
    - https://attack.mitre.org/techniques/T1059/
    - https://blog.example.com/post
"""
    urls: dict[str, list[str]] = defaultdict(list)
    cr._extract_urls_from_blob(blob, source="x.yml", urls=urls)
    assert "https://runbook.example.com/x" in urls
    assert "https://attack.mitre.org/techniques/T1059/" in urls
    assert "https://blog.example.com/post" in urls


def test_extract_urls_skips_non_http_strings() -> None:
    """Pydantic enforces http(s) on the way in; the script is defensive
    and skips anything that doesn't match. We mirror the Pydantic
    behaviour so a hand-edit can't sneak a non-URL through."""
    blob = """
metadata:
  runbookUrl: not-a-url
  references:
    - ftp://legacy.example.com/x
    - https://kept.example.com/y
"""
    urls: dict[str, list[str]] = defaultdict(list)
    cr._extract_urls_from_blob(blob, source="x.yml", urls=urls)
    assert "https://kept.example.com/y" in urls
    assert "not-a-url" not in urls
    assert "ftp://legacy.example.com/x" not in urls


def test_extract_urls_tolerates_malformed_yaml() -> None:
    """Lint catches the YAML error elsewhere; this helper just bails."""
    urls: dict[str, list[str]] = defaultdict(list)
    cr._extract_urls_from_blob(":\nnot valid", source="x.yml", urls=urls)
    assert not urls


def test_iter_added_urls_filters_existing(monkeypatch, tmp_path: Path) -> None:
    """The diff path returns only URLs present in HEAD's envelope but
    absent in the BASE envelope. A URL that was already there at base
    must NOT show up in the result, even if the PR otherwise modified
    the file."""
    head_file = tmp_path / "rule.yml"
    head_file.write_text(
        "id: x\n"
        "metadata:\n"
        "  runbookUrl: https://runbook.example.com/x\n"
        "  references:\n"
        "    - https://existing.example.com/old\n"
        "    - https://added.example.com/new\n",
        encoding="utf-8",
    )

    def fake_changed_paths(diff_base: str) -> list[str]:
        assert diff_base == "origin/main"
        return [str(head_file)]

    def fake_git_show(ref: str, path: str) -> str | None:
        # Base version had only the runbookUrl + one references entry.
        return (
            "id: x\n"
            "metadata:\n"
            "  runbookUrl: https://runbook.example.com/x\n"
            "  references:\n"
            "    - https://existing.example.com/old\n"
        )

    monkeypatch.setattr(cr, "_changed_envelope_paths", fake_changed_paths)
    monkeypatch.setattr(cr, "_git_show", fake_git_show)

    added = cr._iter_added_urls("origin/main")
    assert "https://added.example.com/new" in added
    assert "https://existing.example.com/old" not in added
    assert "https://runbook.example.com/x" not in added


def test_iter_added_urls_handles_brand_new_envelope(monkeypatch, tmp_path: Path) -> None:
    """A brand-new envelope: every URL in it is added."""
    head_file = tmp_path / "new-rule.yml"
    head_file.write_text(
        "id: x\n"
        "metadata:\n"
        "  runbookUrl: https://runbook.example.com/new\n"
        "  references:\n"
        "    - https://ref.example.com/a\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(cr, "_changed_envelope_paths", lambda b: [str(head_file)])
    # Base ref doesn't have the file → git show returns None.
    monkeypatch.setattr(cr, "_git_show", lambda ref, path: None)

    added = cr._iter_added_urls("origin/main")
    assert "https://runbook.example.com/new" in added
    assert "https://ref.example.com/a" in added
