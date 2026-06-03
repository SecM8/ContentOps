# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for the code-driven catalog generator (`contentops.catalog`).

Three layers:
* Pure-function tests for ``inspect_all`` and ``render_markdown``.
* Pinning tests against the live codebase: the generator must
  collect every Click command currently registered, every Asset, and
  every lint rule.
* The load-bearing CI gate: the committed
  ``docs/reference/generated-catalog.md`` must match what the
  generator would currently produce. A mismatch here means the
  generator was not re-run after a code change; CI will fail.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from click.testing import CliRunner

from contentops.catalog import (
    GENERATED_FILE,
    Inventory,
    inspect_all,
    render_markdown,
)
from contentops.catalog.inspect import (
    inspect_assets,
    inspect_cli,
    inspect_lint_rules,
)
from contentops.cli import cli
from contentops.config import is_operator_source_repo


REPO_ROOT = Path(__file__).resolve().parents[2]

# The catalog drift gate is a source-repo maintenance check: it compares
# the committed generated-catalog.md against regeneration. The public
# mirror + adopter clones strip operator-only files, so it can't pass
# there and must skip (cloning the mirror should be green out of the box).
source_only = pytest.mark.skipif(
    not is_operator_source_repo(REPO_ROOT),
    reason="source-repo maintenance gate; skipped off-source "
           "(public mirror / adopter clone — no public-sync.yml)",
)


# ---------------------------------------------------------------------------
# Inspection layer
# ---------------------------------------------------------------------------


def test_inspect_collects_every_top_level_cli_command() -> None:
    """The generator must enumerate every command attached to the
    root ``cli`` group. If a new command is added but not enumerated,
    the catalog would silently omit it.
    """
    expected = set(cli.commands.keys())
    spec_top_level = {c.name for c in inspect_cli() if " " not in c.name}
    missing = expected - spec_top_level
    assert not missing, (
        f"Generator missed top-level commands: {sorted(missing)}"
    )


def test_inspect_recurses_into_groups() -> None:
    """Verify the walker recurses — the ``audit`` group has a
    ``verify`` subcommand that must show up as ``audit verify``.
    """
    names = {c.name for c in inspect_cli()}
    assert "audit verify" in names
    assert "catalog regenerate" in names
    assert "catalog check" in names


def test_inspect_assets_matches_enum() -> None:
    from contentops.core.asset import Asset

    spec_kinds = {a.name for a in inspect_assets()}
    enum_values = {a.value for a in Asset}
    assert spec_kinds == enum_values


def test_inspect_lint_rules_matches_expected_severities() -> None:
    """The catalog's rule_id → severity map must agree exactly with
    the canonical pin in test_lint_coverage._EXPECTED_SEVERITIES.
    Collapsing the two maps eliminates a class of "doc says X, code
    does Y" findings.
    """
    from tests.v2.test_lint_coverage import _EXPECTED_SEVERITIES

    catalog_map = {r.rule_id: r.severity for r in inspect_lint_rules()}
    assert catalog_map == _EXPECTED_SEVERITIES


def test_inspect_handlers_only_lists_existing_files() -> None:
    inv = inspect_all(REPO_ROOT)
    for h in inv.handlers:
        assert (REPO_ROOT / h.file).exists(), (
            f"catalog references missing handler file {h.file}"
        )


def test_handlers_cover_every_asset_kind() -> None:
    """Completeness guard (F1 regression catch): the catalog must list
    a handler row for every Asset kind.

    The pre-fix generator pointed ``inspect_handlers`` at the stale
    ``pipeline/handlers`` path (left over from the pipeline -> contentops
    rename) so it emitted ZERO rows; the drift gate passed anyway
    because the committed file was also empty. Asserting against the
    Asset enum — an independent source of truth — makes an empty or
    under-populated handlers table fail loudly instead of silently.
    """
    from contentops.core.asset import Asset

    inv = inspect_all(REPO_ROOT)
    handler_kinds = {h.asset_kind for h in inv.handlers}
    enum_kinds = {a.value for a in Asset}
    assert handler_kinds == enum_kinds, (
        "Handlers table does not cover every asset kind. "
        f"Missing: {sorted(enum_kinds - handler_kinds)}; "
        f"unmapped: {sorted(k for k in handler_kinds - enum_kinds if k)}. "
        "Check contentops/catalog/inspect.py::inspect_handlers."
    )


def test_lint_registry_covers_every_emitted_rule() -> None:
    """Completeness guard (F2 regression catch): every rule id emitted
    by a ``contentops/lint/*.py`` module must appear in the catalog's
    lint registry.

    The pre-fix registry hand-listed 14 rules and silently omitted the
    META001-009, PAYLOAD003/004, and KQL000/008/010 families that the
    lint pipeline actually emits. Scanning the lint source for
    rule-id string literals and requiring them all to be cataloged
    prevents that class of silent under-reporting.
    """
    lint_dir = REPO_ROOT / "contentops" / "lint"
    rule_literal = re.compile(r'"(KQL\d+|KQLOVERRIDE\d+|META\d+|PAYLOAD\d+)"')
    emitted: set[str] = set()
    for py in sorted(lint_dir.glob("*.py")):
        emitted |= set(rule_literal.findall(py.read_text(encoding="utf-8")))
    registry = {r.rule_id for r in inspect_lint_rules()}
    missing = emitted - registry
    assert not missing, (
        "Lint rule(s) emitted in code but absent from the catalog "
        "registry. Add them to contentops/catalog/inspect.py::"
        "_RULE_REGISTRY and tests/v2/test_lint_coverage.py::"
        f"_EXPECTED_SEVERITIES: {sorted(missing)}"
    )


def test_traceability_covers_every_command() -> None:
    """Completeness guard: the Action -> Function -> Script -> Workflow
    matrix must carry exactly one row per registered command/subcommand
    so the 'full view' can never omit a command that exists in code."""
    from contentops.catalog.inspect import inspect_traceability

    trace_cmds = {t.command for t in inspect_traceability(REPO_ROOT)}
    cli_cmds = {c.name for c in inspect_cli()}
    assert trace_cmds == cli_cmds, (
        "Traceability matrix is missing rows for: "
        f"{sorted(cli_cmds - trace_cmds)}"
    )


def test_workflow_texts_warns_on_unreadable_workflow(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An unreadable workflow must surface a warning, not vanish silently
    from the traceability matrix (fail-loud / data-completeness posture —
    the same silent-under-reporting bug class PR #302 was created to kill)."""
    from contentops.catalog.inspect import _workflow_texts

    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "foo.yml").write_text("name: foo\n", encoding="utf-8")

    orig_read_text = Path.read_text

    def boom(self, *args, **kwargs):
        if self.name == "foo.yml":
            raise OSError("simulated unreadable workflow")
        return orig_read_text(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", boom)

    with pytest.warns(UserWarning, match="could not read workflow"):
        out = _workflow_texts(tmp_path)
    # The unreadable workflow is dropped (can't be read) but the drop is
    # now loud, not silent.
    assert out == {}


def test_inspect_workflows_match_disk() -> None:
    """Catalog enumerates every workflow on disk, minus the operator-only
    exclusion set the public mirror also strips out."""
    from contentops.catalog.inspect import _EXCLUDED_WORKFLOWS

    inv = inspect_all(REPO_ROOT)
    on_disk = sorted(
        str(p.relative_to(REPO_ROOT)).replace("\\", "/")
        for p in (REPO_ROOT / ".github" / "workflows").glob("*.yml")
        if p.name not in _EXCLUDED_WORKFLOWS
    )
    catalog_paths = sorted(w.file for w in inv.workflows)
    assert catalog_paths == on_disk


def test_inspect_unit_tests_includes_self() -> None:
    inv = inspect_all(REPO_ROOT)
    paths = {t.file for t in inv.unit_tests}
    assert "tests/v2/test_catalog.py" in paths


# ---------------------------------------------------------------------------
# Rendering layer
# ---------------------------------------------------------------------------


def test_render_is_deterministic() -> None:
    """``render(inv)`` must be a pure function — calling it twice
    against the same Inventory returns byte-identical output.
    """
    inv = inspect_all(REPO_ROOT)
    a = render_markdown(inv)
    b = render_markdown(inv)
    assert a == b


def test_render_emits_section_headers() -> None:
    out = render_markdown(inspect_all(REPO_ROOT))
    for header in (
        "# Generated catalog",
        "## CLI commands",
        "## Command traceability (Action -> Function -> Script -> Workflow)",
        "## Asset taxonomy",
        "## Lint rules",
        "## Handlers",
        "## GitHub Actions workflows",
        "## Tests",
        "## MITRE ATT&CK coverage",
    ):
        assert header in out, f"missing section: {header!r}"


def test_render_mitre_coverage_uses_summary_helper() -> None:
    """MITRE section number must match contentops.coverage.coverage_summary
    against detections/. Catches regressions where the catalog and the
    badge fall out of sync (different aggregations)."""
    from contentops.coverage import coverage_summary

    inv = inspect_all(REPO_ROOT)
    summary = coverage_summary(REPO_ROOT / "detections")
    assert inv.mitre_coverage is not None
    assert inv.mitre_coverage.covered == summary.covered
    assert inv.mitre_coverage.total == summary.total
    assert inv.mitre_coverage.pct == summary.pct

    out = render_markdown(inv)
    assert f"{summary.covered}** / {summary.total} techniques" in out
    assert f"**{summary.pct}%**" in out


def test_render_mitre_coverage_disappears_when_no_detections(tmp_path: Path) -> None:
    """Adopters who haven't seeded `detections/` yet get a clean
    catalog without the MITRE section — the renderer drops the block
    rather than emitting a 0/N row that would look like a problem."""
    inv = inspect_all(tmp_path)
    assert inv.mitre_coverage is None
    out = render_markdown(inv)
    assert "## MITRE ATT&CK coverage" not in out


def test_render_ends_with_single_newline() -> None:
    """Markdown files are committed with a trailing newline; the
    renderer must not emit a double trailing newline that would
    survive ``.rstrip()`` in editors.
    """
    out = render_markdown(inspect_all(REPO_ROOT))
    assert out.endswith("\n")
    assert not out.endswith("\n\n")


# ---------------------------------------------------------------------------
# CI gate (the load-bearing one)
# ---------------------------------------------------------------------------


@source_only
def test_committed_catalog_is_in_sync() -> None:
    """If this fails, the developer made a code change that affects
    the catalog (added a Click command, renamed a workflow, etc.) but
    forgot to run ``contentops catalog regenerate`` and commit the
    updated ``docs/reference/generated-catalog.md``.

    Fix: from the repo root, run

        contentops catalog regenerate

    Commit the resulting diff.
    """
    target = REPO_ROOT / GENERATED_FILE
    assert target.exists(), (
        f"{GENERATED_FILE} is missing — run "
        f"`contentops catalog regenerate` and commit the file."
    )
    expected = render_markdown(inspect_all(REPO_ROOT))
    actual = target.read_bytes().decode("utf-8")
    assert actual == expected, (
        f"{GENERATED_FILE} is out of sync with the codebase. "
        f"Run `contentops catalog regenerate` and commit the diff."
    )


# ---------------------------------------------------------------------------
# CLI surface
# ---------------------------------------------------------------------------


@source_only
def test_cli_catalog_check_passes_against_committed_file() -> None:
    runner = CliRunner()
    # Pass --repo-root explicitly: the v2 conftest chdir's each test into
    # a tmp dir, so the command can't infer the repo root from cwd.
    result = runner.invoke(cli, ["catalog", "check", "--repo-root", str(REPO_ROOT)])
    assert result.exit_code == 0, result.output
    assert "in sync" in result.output


def test_cli_catalog_regenerate_writes_target(tmp_path: Path) -> None:
    runner = CliRunner()
    out = tmp_path / "catalog.md"
    result = runner.invoke(
        cli,
        ["catalog", "regenerate", "--out", str(out), "--repo-root", str(REPO_ROOT)],
    )
    assert result.exit_code == 0, result.output
    assert out.exists()
    body = out.read_bytes().decode("utf-8")
    # Sanity: the generated body must match what render_markdown produces.
    assert body == render_markdown(inspect_all(REPO_ROOT))


def test_cli_catalog_check_detects_drift(tmp_path: Path, monkeypatch) -> None:
    """Synthesise a fake repo root with a stale catalog file and
    verify the CLI flags the drift with exit code 1.
    """
    fake_root = tmp_path
    target = fake_root / GENERATED_FILE
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("# stale catalog\n", encoding="utf-8")
    # Seed the source-repo sentinel so `catalog check` actually runs the
    # drift comparison here — off-source it would skip with exit 0.
    sentinel = fake_root / ".github" / "workflows" / "public-sync.yml"
    sentinel.parent.mkdir(parents=True, exist_ok=True)
    sentinel.write_text("# stub sentinel\n", encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(
        cli, ["catalog", "check", "--repo-root", str(fake_root)]
    )
    assert result.exit_code == 1
    assert "drift" in result.output.lower() or "drift" in (result.stderr or "").lower()


def test_cli_catalog_check_skips_off_source(tmp_path: Path) -> None:
    """Off the operator source repo (no public-sync.yml), `catalog check`
    no-ops with exit 0 — even against a deliberately-stale catalog — so a
    public-mirror / adopter clone is green out of the box (regression guard
    for the chronic mirror-CI failure)."""
    assert is_operator_source_repo(tmp_path) is False
    target = tmp_path / GENERATED_FILE
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("# deliberately stale catalog\n", encoding="utf-8")

    result = CliRunner().invoke(
        cli, ["catalog", "check", "--repo-root", str(tmp_path)]
    )
    assert result.exit_code == 0, result.output
    assert "skipped" in result.output.lower()
