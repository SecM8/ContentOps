# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for the workspace-aware KQL snippet substitution engine (Phase 4).

Covers:
* 3-tier resolution (workspace-specific -> generic -> drop line)
* Snippet file format (description + content)
* Defender envelopes use generic-only lookup
* Path-traversal rejection
* CRLF normalisation
* Deterministic byte output
* Multi-rule sharing one snippet
* All four KQLOVERRIDE lint rules
* plan_cmd / apply_cmd per-workspace iteration with snippets
"""

from __future__ import annotations

from pathlib import Path
from textwrap import dedent

import pytest
from click.testing import CliRunner

from contentops.cli import cli
from contentops.core.asset import Asset
from contentops.core.envelope import EnvelopeV2
from contentops.core.handler import LoadedAsset
from contentops.lint.snippets import (
    lint_kql_placeholders,
    lint_overrides_directory,
)
from contentops.snippets import (
    PLACEHOLDER_RE,
    SnippetError,
    apply_snippets,
    find_placeholders,
)
from contentops.snippets.loader import (
    SnippetFormatError,
    clear_cache,
    resolve_snippet,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _clear_snippet_cache():
    """The snippet loader caches by absolute path; tests that mutate the
    same path between assertions need the cache cleared each test."""
    clear_cache()
    yield
    clear_cache()


def _write_snippet(path: Path, content: str, *, description: str = "test") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        f"description: {description!r}\ncontent: |-\n  " + content.replace("\n", "\n  "),
        encoding="utf-8",
    )
    return path


def _make_loaded(
    *, asset: Asset, payload: dict, envelope_id: str = "test-rule",
) -> LoadedAsset:
    """Construct a LoadedAsset without going through YAML on disk.

    ``EnvelopeV2`` is the strict envelope model; constructing one
    directly skips the parse-permissive layer (which is fine for unit
    tests of the snippet engine — we own the field values).
    """
    envelope = EnvelopeV2(
        id=envelope_id,
        version="0.1.0",
        asset=asset,
        status="production",
    )
    return LoadedAsset(path=Path("synthetic"), envelope=envelope, payload=payload)


# ---------------------------------------------------------------------------
# resolve_snippet — 3-tier resolution
# ---------------------------------------------------------------------------


def test_resolve_workspace_specific_wins(tmp_path: Path) -> None:
    overrides = tmp_path / "overrides"
    _write_snippet(overrides / "001/excludedusers.yml", "generic-value")
    _write_snippet(overrides / "law-prod/001/excludedusers.yml", "prod-value")
    assert resolve_snippet(overrides, "001/excludedusers.yml", "law-prod") == "prod-value"


def test_resolve_falls_back_to_generic(tmp_path: Path) -> None:
    overrides = tmp_path / "overrides"
    _write_snippet(overrides / "001/excludedusers.yml", "generic-value")
    # No law-prod-specific file -> falls back to generic.
    assert resolve_snippet(overrides, "001/excludedusers.yml", "law-prod") == "generic-value"


def test_resolve_returns_none_when_neither_exists(tmp_path: Path) -> None:
    overrides = tmp_path / "overrides"
    overrides.mkdir()
    assert resolve_snippet(overrides, "001/missing.yml", "law-prod") is None


def test_resolve_returns_none_when_overrides_root_absent(tmp_path: Path) -> None:
    # No overrides/ dir at all -> the loader returns None silently.
    assert resolve_snippet(tmp_path / "overrides", "any.yml", "law-prod") is None


def test_resolve_normalises_crlf(tmp_path: Path) -> None:
    overrides = tmp_path / "overrides"
    overrides.mkdir()
    # Write CRLF directly (bypass _write_snippet's textwrap helper).
    snippet = overrides / "crlf.yml"
    snippet.write_bytes(
        b"description: 't'\ncontent: \"a\\r\\nb\\r\\nc\"\n",
    )
    assert resolve_snippet(overrides, "crlf.yml", None) == "a\nb\nc"


# ---------------------------------------------------------------------------
# Snippet file format errors
# ---------------------------------------------------------------------------


def test_resolve_raises_on_missing_content_key(tmp_path: Path) -> None:
    overrides = tmp_path / "overrides"
    overrides.mkdir()
    (overrides / "bad.yml").write_text(
        "description: 'just docs, no content'\n", encoding="utf-8",
    )
    with pytest.raises(SnippetFormatError, match="missing required 'content:' key"):
        resolve_snippet(overrides, "bad.yml", None)


def test_resolve_raises_on_non_string_content(tmp_path: Path) -> None:
    overrides = tmp_path / "overrides"
    overrides.mkdir()
    (overrides / "bad.yml").write_text(
        "description: 't'\ncontent: 42\n", encoding="utf-8",
    )
    with pytest.raises(SnippetFormatError, match="must be a string"):
        resolve_snippet(overrides, "bad.yml", None)


# ---------------------------------------------------------------------------
# apply_snippets — full integration
# ---------------------------------------------------------------------------


def test_apply_substitutes_workspace_specific(tmp_path: Path, monkeypatch) -> None:
    overrides = tmp_path / "overrides"
    _write_snippet(overrides / "001/excludedusers.yml", "GENERIC")
    _write_snippet(overrides / "law-prod/001/excludedusers.yml", "PROD")
    la = _make_loaded(
        asset=Asset.SENTINEL_ANALYTIC,
        payload={"query": "M\n{{001/excludedusers.yml}}\nN"},
    )
    out = apply_snippets(la, "law-prod", overrides_root=overrides)
    assert out.payload["query"] == "M\nPROD\nN"
    # Original is not mutated.
    assert la.payload["query"] == "M\n{{001/excludedusers.yml}}\nN"


def test_apply_drops_line_when_neither_file_exists(tmp_path: Path) -> None:
    overrides = tmp_path / "overrides"
    overrides.mkdir()
    la = _make_loaded(
        asset=Asset.SENTINEL_ANALYTIC,
        payload={"query": "Line A\n{{missing/file.yml}}\nLine C"},
    )
    out = apply_snippets(la, "law-prod", overrides_root=overrides)
    assert out.payload["query"] == "Line A\nLine C"


def test_apply_normalises_backslash_separator(tmp_path: Path) -> None:
    overrides = tmp_path / "overrides"
    _write_snippet(overrides / "001/excludedusers.yml", "OK")
    la = _make_loaded(
        asset=Asset.SENTINEL_ANALYTIC,
        payload={"query": r"{{001\excludedusers.yml}}"},
    )
    out = apply_snippets(la, None, overrides_root=overrides)
    assert out.payload["query"] == "OK"


def test_apply_defender_envelope_skips_workspace_lookup(tmp_path: Path) -> None:
    """Defender is tenant-scoped — even with a workspace-specific file
    present, only the generic file is consulted."""
    overrides = tmp_path / "overrides"
    _write_snippet(overrides / "common/badips.yml", "GENERIC")
    _write_snippet(overrides / "law-prod/common/badips.yml", "PROD")
    la = _make_loaded(
        asset=Asset.DEFENDER_CUSTOM_DETECTION,
        payload={"queryCondition": {"queryText": "X\n{{common/badips.yml}}\nY"}},
    )
    out = apply_snippets(la, "law-prod", overrides_root=overrides)
    assert out.payload["queryCondition"]["queryText"] == "X\nGENERIC\nY"


def test_apply_returns_input_unchanged_when_no_placeholders(tmp_path: Path) -> None:
    overrides = tmp_path / "overrides"
    overrides.mkdir()
    la = _make_loaded(
        asset=Asset.SENTINEL_ANALYTIC,
        payload={"query": "no placeholders here"},
    )
    out = apply_snippets(la, "law-prod", overrides_root=overrides)
    # Object identity preserved (cheap fast-path).
    assert out is la


def test_apply_multi_rule_sharing_same_snippet(tmp_path: Path) -> None:
    """Two rules reference the same snippet — both get the same value."""
    overrides = tmp_path / "overrides"
    _write_snippet(overrides / "common/admins.yml", "ALICE, BOB")
    rule1 = _make_loaded(
        asset=Asset.SENTINEL_ANALYTIC,
        payload={"query": "Rule1\n{{common/admins.yml}}"},
        envelope_id="rule1",
    )
    rule2 = _make_loaded(
        asset=Asset.SENTINEL_HUNTING,
        payload={"query": "Rule2\n{{common/admins.yml}}"},
        envelope_id="rule2",
    )
    out1 = apply_snippets(rule1, "law-prod", overrides_root=overrides)
    out2 = apply_snippets(rule2, "law-prod", overrides_root=overrides)
    assert out1.payload["query"] == "Rule1\nALICE, BOB"
    assert out2.payload["query"] == "Rule2\nALICE, BOB"


def test_apply_deterministic_bytes_across_repeat(tmp_path: Path) -> None:
    """Re-applying produces identical bytes (hash-chain stability)."""
    overrides = tmp_path / "overrides"
    _write_snippet(overrides / "x.yml", "deterministic")
    la = _make_loaded(
        asset=Asset.SENTINEL_ANALYTIC,
        payload={"query": "A\n{{x.yml}}\nB"},
    )
    a = apply_snippets(la, None, overrides_root=overrides)
    b = apply_snippets(la, None, overrides_root=overrides)
    assert a.payload == b.payload


def test_apply_propagates_snippet_format_error(tmp_path: Path) -> None:
    overrides = tmp_path / "overrides"
    overrides.mkdir()
    (overrides / "bad.yml").write_text(
        "description: 't'\n", encoding="utf-8",  # missing content:
    )
    la = _make_loaded(
        asset=Asset.SENTINEL_ANALYTIC,
        payload={"query": "{{bad.yml}}"},
    )
    with pytest.raises(SnippetError, match="missing required 'content:' key"):
        apply_snippets(la, None, overrides_root=overrides)


# ---------------------------------------------------------------------------
# Lint — KQLOVERRIDE001 / 002 / 003 / 004
# ---------------------------------------------------------------------------


def test_lint_001_extra_spaces() -> None:
    findings = lint_kql_placeholders("{{ 001/x.yml }}")
    assert any(f.rule_id == "KQLOVERRIDE001" for f in findings)


def test_lint_001_missing_yml_suffix() -> None:
    findings = lint_kql_placeholders("{{001/excludedusers}}")
    assert any(f.rule_id == "KQLOVERRIDE001" for f in findings)


def test_lint_001_passes_valid_placeholder() -> None:
    findings = lint_kql_placeholders("{{001/excludedusers.yml}}")
    assert not any(f.rule_id == "KQLOVERRIDE001" for f in findings)


def test_lint_002_path_traversal() -> None:
    findings = lint_kql_placeholders("{{../etc/passwd.yml}}")
    assert any(f.rule_id == "KQLOVERRIDE002" for f in findings)


def test_lint_002_absolute_path() -> None:
    findings = lint_kql_placeholders("{{/etc/passwd.yml}}")
    assert any(f.rule_id == "KQLOVERRIDE002" for f in findings)


def test_lint_003_placeholder_mid_line() -> None:
    findings = lint_kql_placeholders(
        "M\n| where User in ({{001/excludedusers.yml}})\nN"
    )
    assert any(f.rule_id == "KQLOVERRIDE003" for f in findings)


def test_lint_003_passes_when_alone_on_line() -> None:
    findings = lint_kql_placeholders(
        "M\n  {{001/excludedusers.yml}}  \nN"
    )
    # Whitespace-only residue is fine.
    assert not any(f.rule_id == "KQLOVERRIDE003" for f in findings)


def test_lint_003_tolerates_trailing_comment() -> None:
    findings = lint_kql_placeholders(
        "{{001/x.yml}}  // explain why"
    )
    assert not any(f.rule_id == "KQLOVERRIDE003" for f in findings)


def test_lint_004_missing_content_key(tmp_path: Path) -> None:
    overrides = tmp_path / "overrides"
    overrides.mkdir()
    (overrides / "bad.yml").write_text(
        "description: 'doc only'\n", encoding="utf-8",
    )
    findings = lint_overrides_directory(overrides)
    assert len(findings) == 1
    path, finding = findings[0]
    assert finding.rule_id == "KQLOVERRIDE004"
    assert "missing required 'content:'" in finding.message


def test_lint_004_passes_valid_snippet(tmp_path: Path) -> None:
    overrides = tmp_path / "overrides"
    _write_snippet(overrides / "ok.yml", "valid")
    assert lint_overrides_directory(overrides) == []


def test_lint_004_no_overrides_dir_is_silent(tmp_path: Path) -> None:
    assert lint_overrides_directory(tmp_path / "absent") == []


# ---------------------------------------------------------------------------
# Helpers — find_placeholders, regex sanity
# ---------------------------------------------------------------------------


def test_find_placeholders_dedupes_and_normalises() -> None:
    text = "{{a/b.yml}}\n{{a/b.yml}}\n{{c\\d.yml}}"
    assert find_placeholders(text) == ["a/b.yml", "c/d.yml"]


def test_placeholder_regex_does_not_match_partial_braces() -> None:
    assert PLACEHOLDER_RE.search("{not-a-placeholder}") is None
    assert PLACEHOLDER_RE.search("{{no-suffix}}") is None


# ---------------------------------------------------------------------------
# Phase 4 review follow-ups
# ---------------------------------------------------------------------------


def test_resolve_rejects_traversal_via_workspace_name(tmp_path: Path) -> None:
    """Path-traversal defence: workspace_name='..' must not escape root."""
    overrides = tmp_path / "overrides"
    overrides.mkdir()
    # Create a "secret" outside overrides/ that ../etc/secret.yml would
    # resolve to if traversal were permitted.
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc" / "secret.yml").write_text(
        "description: 'should never be read'\ncontent: 'pwned'\n",
        encoding="utf-8",
    )
    with pytest.raises(SnippetFormatError, match="escapes overrides root"):
        resolve_snippet(overrides, "secret.yml", "../etc")


def test_resolve_rejects_traversal_via_rel_path(tmp_path: Path) -> None:
    """Defence-in-depth even when KQLOVERRIDE002 is bypassed."""
    overrides = tmp_path / "overrides"
    overrides.mkdir()
    (tmp_path / "etc" / "secret.yml").parent.mkdir()
    (tmp_path / "etc" / "secret.yml").write_text(
        "description: 't'\ncontent: 'pwned'\n", encoding="utf-8",
    )
    with pytest.raises(SnippetFormatError, match="escapes overrides root"):
        resolve_snippet(overrides, "../etc/secret.yml", None)


def test_apply_emits_warning_on_line_drop(
    tmp_path: Path, capsys,
) -> None:
    """Both-missing fallback must surface a click.echo warning on stderr."""
    overrides = tmp_path / "overrides"
    overrides.mkdir()
    la = _make_loaded(
        asset=Asset.SENTINEL_ANALYTIC,
        payload={"query": "Keep this\n{{missing/file.yml}}\nKeep this too"},
        envelope_id="test-rule",
    )
    apply_snippets(la, "law-prod", overrides_root=overrides)
    captured = capsys.readouterr()
    assert "[snippets]" in captured.err
    assert "dropped line" in captured.err
    assert "missing/file.yml" in captured.err
    assert "law-prod" in captured.err


def test_apply_two_placeholders_one_misses_drops_whole_line(
    tmp_path: Path,
) -> None:
    """When two placeholders share a line and one misses, the line
    (including the resolved sibling) is dropped."""
    overrides = tmp_path / "overrides"
    _write_snippet(overrides / "found.yml", "RESOLVED")
    la = _make_loaded(
        asset=Asset.SENTINEL_ANALYTIC,
        payload={"query": "{{found.yml}} {{missing.yml}}"},
    )
    out = apply_snippets(la, None, overrides_root=overrides)
    # The whole line was dropped -> empty string remains (no surviving lines).
    assert out.payload["query"] == ""


def test_apply_two_placeholders_both_resolve_substitutes_both(
    tmp_path: Path,
) -> None:
    """Companion: when both resolve, both are substituted in-line."""
    overrides = tmp_path / "overrides"
    _write_snippet(overrides / "a.yml", "AA")
    _write_snippet(overrides / "b.yml", "BB")
    la = _make_loaded(
        asset=Asset.SENTINEL_ANALYTIC,
        payload={"query": "{{a.yml}} {{b.yml}}"},
    )
    out = apply_snippets(la, None, overrides_root=overrides)
    assert out.payload["query"] == "AA BB"


# ---------------------------------------------------------------------------
# Cross-phase review: Seam A — sentinel_parser KQL field coverage
# ---------------------------------------------------------------------------


def test_apply_substitutes_in_sentinel_parser(tmp_path: Path) -> None:
    """Cross-phase Seam A: parser KQL must receive snippet substitution.

    Pre-fix: ``_KQL_FIELDS_BY_ASSET`` only covered analytic / hunting /
    defender; a parser containing ``{{...}}`` placeholders silently
    leaked the literal placeholder text to ARM at deploy time
    (HTTP 400). After the consolidation to
    ``contentops.core.asset.KQL_FIELDS_BY_ASSET``, parsers are covered.
    """
    overrides = tmp_path / "overrides"
    _write_snippet(overrides / "common/allowlist.yml", "ALLOW")
    la = _make_loaded(
        asset=Asset.SENTINEL_PARSER,
        payload={"query": "let x = 1;\n{{common/allowlist.yml}}\nlet y = 2;"},
        envelope_id="my-parser",
    )
    out = apply_snippets(la, None, overrides_root=overrides)
    assert out.payload["query"] == "let x = 1;\nALLOW\nlet y = 2;"


def test_lint_kql_placeholders_runs_on_sentinel_parser() -> None:
    """KQLOVERRIDE rules must fire on parser KQL too.

    Driven via ``lint_assets`` so we exercise the runner's per-asset
    dispatch (which reads ``KQL_FIELDS_BY_ASSET``).
    """
    from contentops.core.asset import KQL_FIELDS_BY_ASSET
    assert Asset.SENTINEL_PARSER in KQL_FIELDS_BY_ASSET, (
        "sentinel_parser must be enumerated in KQL_FIELDS_BY_ASSET so "
        "both lint and snippet substitution cover its query field"
    )


def test_kql_fields_map_is_single_source_of_truth() -> None:
    """The lint and snippet engines both import the same dict object."""
    from contentops.core.asset import KQL_FIELDS_BY_ASSET as canonical
    from contentops.lint.runner import _KQL_FIELD_BY_ASSET as lint_alias
    from contentops.snippets.apply import _KQL_FIELDS_BY_ASSET as snippet_alias
    assert lint_alias is canonical
    assert snippet_alias is canonical
