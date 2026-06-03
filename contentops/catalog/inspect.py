# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Pure introspection of the codebase.

Walks Click command tree, the Asset enum, the lint rule registry,
``contentops/handlers/``, ``.github/workflows/``, and ``tests/v2/`` +
``tests/integration/`` to build a structured :class:`Inventory`.

No I/O beyond reading source files. No markdown rendering. The
output of this module is consumed by :mod:`contentops.catalog.render`.

Determinism contract: every collection ordered by a stable key
(typically the name) so two invocations against the same checkout
produce byte-identical structured output.
"""

from __future__ import annotations

import re
import warnings
from dataclasses import dataclass, field
from pathlib import Path

import click


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CommandSpec:
    """One Click command (or subcommand) registered on the root group."""

    name: str             # full path, e.g. "audit verify" or "apply"
    help_summary: str     # first non-empty line of the command's docstring
    is_group: bool        # True if it's a Click group with subcommands


@dataclass(frozen=True)
class AssetSpec:
    name: str             # the enum value, e.g. "sentinel_analytic"
    handler_module: str   # dotted path of the handler module
    has_kql_field: bool   # appears in KQL_FIELDS_BY_ASSET


@dataclass(frozen=True)
class LintRuleSpec:
    rule_id: str          # e.g. "KQL001"
    severity: str         # "error" / "warning" / "info"
    module: str           # dotted module path where it's emitted


@dataclass(frozen=True)
class HandlerSpec:
    module: str           # dotted module name, e.g. "contentops.handlers.sentinel_analytic"
    file: str             # repo-relative path
    asset_kind: str | None  # the Asset value if discoverable, else None


@dataclass(frozen=True)
class WorkflowSpec:
    file: str             # repo-relative path
    name: str             # value of the workflow's ``name:`` field if present, else basename


@dataclass(frozen=True)
class TraceSpec:
    """One Action and the code + automation behind it.

    The 'full view' the operator asked for, one row per registered
    command: Action (CLI command) -> Function (the Click callback) ->
    Script (the module that defines it) -> Workflow (the GitHub Actions
    workflow(s) that invoke it). All four columns are derived from the
    live code + workflow YAML, so the matrix can never silently drift
    from what is actually wired up.
    """

    command: str                  # full command path, e.g. "audit verify"
    callback: str                 # Click callback function name ("" if none)
    module: str                   # dotted module of the callback ("" if none)
    workflows: tuple[str, ...]    # workflow files that invoke this command


@dataclass(frozen=True)
class TestSpec:
    file: str             # repo-relative path
    test_count: int       # number of ``def test_`` lines in the file


@dataclass(frozen=True)
class MitreCoverageSpec:
    """Headline MITRE ATT&CK coverage stats for the catalog.

    Sourced from ``contentops.coverage.coverage_summary`` — same number
    as the README badge and the ``contentops portfolio`` footer.
    """
    covered: int
    total: int
    pct: int
    matrix_label: str


@dataclass(frozen=True)
class Inventory:
    """The full catalog payload.

    Constructed by :func:`inspect_all`; consumed by
    :func:`contentops.catalog.render.render_markdown`.
    """

    commands: tuple[CommandSpec, ...] = field(default_factory=tuple)
    traceability: tuple[TraceSpec, ...] = field(default_factory=tuple)
    assets: tuple[AssetSpec, ...] = field(default_factory=tuple)
    lint_rules: tuple[LintRuleSpec, ...] = field(default_factory=tuple)
    handlers: tuple[HandlerSpec, ...] = field(default_factory=tuple)
    workflows: tuple[WorkflowSpec, ...] = field(default_factory=tuple)
    unit_tests: tuple[TestSpec, ...] = field(default_factory=tuple)
    integration_tests: tuple[TestSpec, ...] = field(default_factory=tuple)
    mitre_coverage: MitreCoverageSpec | None = None


# ---------------------------------------------------------------------------
# Click command tree
# ---------------------------------------------------------------------------


def _summarise_doc(doc: str | None) -> str:
    if not doc:
        return ""
    for line in doc.strip().splitlines():
        line = line.strip()
        if line:
            return line
    return ""


def _walk_click(group: click.Group, prefix: str = "") -> list[CommandSpec]:
    out: list[CommandSpec] = []
    for name in sorted(group.commands.keys()):
        cmd = group.commands[name]
        full = f"{prefix} {name}".strip()
        is_group = isinstance(cmd, click.Group)
        out.append(CommandSpec(
            name=full,
            help_summary=_summarise_doc(cmd.help or cmd.__doc__),
            is_group=is_group,
        ))
        if is_group:
            out.extend(_walk_click(cmd, prefix=full))
    return out


def inspect_cli() -> tuple[CommandSpec, ...]:
    """Walk the root ``cli`` group and return every command + subcommand."""
    from contentops.cli import cli  # local import to avoid circular at module load
    return tuple(_walk_click(cli))


# ---------------------------------------------------------------------------
# Command traceability (Action -> Function -> Script -> Workflow)
# ---------------------------------------------------------------------------


def _resolve_command(root: click.Group, full_name: str) -> click.Command | None:
    """Descend the Click tree to the command named ``full_name``.

    ``full_name`` is the space-joined path produced by ``_walk_click``
    (e.g. ``"audit verify"``). Returns ``None`` if any segment is
    missing.
    """
    cur: click.Command | None = root
    for token in full_name.split(" "):
        if not isinstance(cur, click.Group):
            return None
        cur = cur.commands.get(token)
        if cur is None:
            return None
    return cur


def _workflow_texts(repo_root: Path) -> dict[str, str]:
    """Return ``{repo-relative-workflow-path: full text}`` for every
    workflow except the operator-only exclusions the public mirror
    strips (so the operator and mirror catalogs agree)."""
    workflows_dir = repo_root / ".github" / "workflows"
    out: dict[str, str] = {}
    if not workflows_dir.is_dir():
        return out
    for path in sorted(workflows_dir.glob("*.yml")):
        if path.name in _EXCLUDED_WORKFLOWS:
            continue
        try:
            out[str(path.relative_to(repo_root)).replace("\\", "/")] = (
                path.read_text(encoding="utf-8")
            )
        except OSError as exc:
            # Fail loud rather than silently dropping a workflow from the
            # traceability matrix — a silent drop is the exact
            # under-reporting bug class PR #302 was created to kill, and it
            # contradicts the repo's fail-fast / data-completeness posture.
            # warn (not raise) so the catalog still renders for adopters /
            # the public mirror; the matrix just flags the gap.
            warnings.warn(
                f"catalog: could not read workflow {path}; the command "
                f"traceability matrix may be incomplete ({exc}).",
                stacklevel=2,
            )
            continue
    return out


def inspect_traceability(repo_root: Path) -> tuple[TraceSpec, ...]:
    """Build the Action -> Function -> Script -> Workflow matrix.

    For every registered command (and subcommand) capture its Click
    callback (the Function) and the module that defines it (the
    Script), then scan the workflow YAML for ``contentops <command>``
    / ``python -m contentops <command>`` invocations to find which
    workflow(s) drive it. A command with no matching workflow is
    local-only. Deterministic: commands sorted by ``_walk_click``,
    workflows sorted by path.
    """
    from contentops.cli import cli  # local import to avoid import cycle

    wf_texts = _workflow_texts(repo_root)
    specs: list[TraceSpec] = []
    for c in _walk_click(cli):
        cmd_obj = _resolve_command(cli, c.name)
        callback = getattr(cmd_obj, "callback", None) if cmd_obj else None
        cb_name = callback.__name__ if callback is not None else ""
        cb_module = callback.__module__ if callback is not None else ""
        # Match the full command path at a token boundary so
        # ``contentops apply`` doesn't match a hypothetical
        # ``apply-foo`` and ``state`` doesn't swallow ``state sync``.
        pattern = re.compile(
            r"(?:contentops|python -m contentops)\s+"
            + re.escape(c.name)
            + r"(?=\s|$)"
        )
        workflows = tuple(
            sorted(f for f, text in wf_texts.items() if pattern.search(text))
        )
        specs.append(TraceSpec(
            command=c.name,
            callback=cb_name,
            module=cb_module,
            workflows=workflows,
        ))
    return tuple(specs)


# ---------------------------------------------------------------------------
# Asset taxonomy
# ---------------------------------------------------------------------------


def inspect_assets() -> tuple[AssetSpec, ...]:
    from contentops.core.asset import KQL_FIELDS_BY_ASSET, Asset

    out: list[AssetSpec] = []
    for asset in sorted(Asset, key=lambda a: a.value):
        out.append(AssetSpec(
            name=asset.value,
            handler_module=f"contentops.handlers.{asset.value}",
            has_kql_field=asset in KQL_FIELDS_BY_ASSET,
        ))
    return tuple(out)


# ---------------------------------------------------------------------------
# Lint rules
# ---------------------------------------------------------------------------


# The canonical map of rule_id -> (severity, source-module). Mirrors
# tests/v2/test_lint_coverage.py::_EXPECTED_SEVERITIES (which is the
# pin enforced by the test suite). Kept here so the catalog can render
# rules without importing test code.
_RULE_REGISTRY: tuple[tuple[str, str, str], ...] = (
    # KQL000 is the carrier id strict.py assigns to Kusto.Language
    # wrapper diagnostics + allowlist-parse warnings that have no
    # specific rule id of their own.
    ("KQL000", "warning", "contentops.lint.strict"),
    ("KQL001", "error",   "contentops.lint.kql"),
    ("KQL002", "error",   "contentops.lint.kql"),
    ("KQL003", "error",   "contentops.lint.kql"),
    ("KQL004", "warning", "contentops.lint.kql"),
    ("KQL005", "warning", "contentops.lint.kql"),
    ("KQL006", "warning", "contentops.lint.kql"),
    ("KQL007", "error",   "contentops.lint.kql"),
    ("KQL008", "warning", "contentops.lint.kql"),  # externaldata()
    ("KQL010", "error",   "contentops.lint.kql"),  # cluster()/workspace() cross-scope
    ("KQL101", "error",   "contentops.lint.strict_rules"),
    ("KQLOVERRIDE001", "error", "contentops.lint.snippets"),
    ("KQLOVERRIDE002", "error", "contentops.lint.snippets"),
    ("KQLOVERRIDE003", "error", "contentops.lint.snippets"),
    ("KQLOVERRIDE004", "error", "contentops.lint.snippets"),
    # Envelope-metadata rules in contentops.lint.metadata_rules. The
    # severity here is the *baseline* each rule emits (META002-005 are
    # escalated to error under policy.scaffoldStrict=true; META001
    # escalates to error on an unparseable date or strict+stale). The
    # baseline mirrors the non-strict default path so the catalog table
    # matches what an out-of-the-box `contentops lint` reports.
    ("META001", "warning", "contentops.lint.metadata_rules"),
    ("META002", "warning", "contentops.lint.metadata_rules"),
    ("META003", "warning", "contentops.lint.metadata_rules"),
    ("META004", "warning", "contentops.lint.metadata_rules"),
    ("META005", "warning", "contentops.lint.metadata_rules"),
    ("META006", "info",    "contentops.lint.metadata_rules"),
    ("META007", "info",    "contentops.lint.metadata_rules"),
    ("META008", "error",   "contentops.lint.metadata_rules"),
    ("META009", "info",    "contentops.lint.metadata_rules"),
    ("PAYLOAD001", "error",   "contentops.lint.payload"),
    ("PAYLOAD002", "warning", "contentops.lint.payload"),
    ("PAYLOAD003", "warning", "contentops.lint.payload"),
    ("PAYLOAD004", "warning", "contentops.lint.payload"),
    ("PAYLOAD005", "warning", "contentops.lint.payload"),
    ("PAYLOAD006", "warning", "contentops.lint.payload"),
)


def inspect_lint_rules() -> tuple[LintRuleSpec, ...]:
    return tuple(
        LintRuleSpec(rule_id=rid, severity=sev, module=mod)
        for rid, sev, mod in sorted(_RULE_REGISTRY, key=lambda r: r[0])
    )


# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------


def inspect_handlers(repo_root: Path) -> tuple[HandlerSpec, ...]:
    from contentops.core.asset import Asset

    asset_values = {a.value for a in Asset}
    handlers_dir = repo_root / "contentops" / "handlers"
    out: list[HandlerSpec] = []
    if not handlers_dir.is_dir():
        return tuple(out)
    for path in sorted(handlers_dir.glob("*.py")):
        # Skip private helpers (_delete / _readonly / _verify), the
        # package __init__, and the Pydantic ``*_models.py`` modules —
        # none of those is a per-asset handler.
        if (
            path.name.startswith("_")
            or path.name == "__init__.py"
            or path.name.endswith("_models.py")
        ):
            continue
        stem = path.stem
        asset_kind = stem if stem in asset_values else None
        out.append(HandlerSpec(
            module=f"contentops.handlers.{stem}",
            file=str(path.relative_to(repo_root)).replace("\\", "/"),
            asset_kind=asset_kind,
        ))
    return tuple(out)


# ---------------------------------------------------------------------------
# Workflows
# ---------------------------------------------------------------------------


def _read_workflow_name(path: Path) -> str:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return path.stem
    for line in text.splitlines():
        # Match a top-level ``name:`` line (no leading whitespace).
        if line.startswith("name:"):
            value = line.split(":", 1)[1].strip()
            # Strip surrounding quotes if present.
            if value and value[0] in ("'", '"') and value[-1] == value[0]:
                value = value[1:-1]
            return value or path.stem
    return path.stem


# Operator-only workflows that the public mirror strips out (see
# `.github/workflows/public-sync.yml` for the strip). Excluding them
# from catalog enumeration so the operator-regenerated catalog and a
# hypothetical mirror-regenerated catalog produce the same output —
# otherwise the mirror's `contentops catalog check` always fails with
# drift on workflows it intentionally doesn't have.
_EXCLUDED_WORKFLOWS: frozenset[str] = frozenset({
    "public-sync.yml",
})


def inspect_workflows(repo_root: Path) -> tuple[WorkflowSpec, ...]:
    workflows_dir = repo_root / ".github" / "workflows"
    out: list[WorkflowSpec] = []
    if not workflows_dir.is_dir():
        return tuple(out)
    for path in sorted(workflows_dir.glob("*.yml")):
        if path.name in _EXCLUDED_WORKFLOWS:
            continue
        out.append(WorkflowSpec(
            file=str(path.relative_to(repo_root)).replace("\\", "/"),
            name=_read_workflow_name(path),
        ))
    return tuple(out)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def _count_test_funcs(path: Path) -> int:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return 0
    count = 0
    for line in text.splitlines():
        # Match ``def test_`` and ``async def test_`` at any indent.
        stripped = line.lstrip()
        if stripped.startswith("def test_") or stripped.startswith("async def test_"):
            count += 1
    return count


def _inspect_tests_dir(root: Path, subdir: str) -> tuple[TestSpec, ...]:
    target = root / "tests" / subdir
    out: list[TestSpec] = []
    if not target.is_dir():
        return tuple(out)
    for path in sorted(target.glob("test_*.py")):
        out.append(TestSpec(
            file=str(path.relative_to(root)).replace("\\", "/"),
            test_count=_count_test_funcs(path),
        ))
    return tuple(out)


def inspect_unit_tests(repo_root: Path) -> tuple[TestSpec, ...]:
    return _inspect_tests_dir(repo_root, "v2")


def inspect_integration_tests(repo_root: Path) -> tuple[TestSpec, ...]:
    return _inspect_tests_dir(repo_root, "integration")


# ---------------------------------------------------------------------------
# MITRE ATT&CK coverage
# ---------------------------------------------------------------------------


def inspect_mitre_coverage(repo_root: Path) -> MitreCoverageSpec | None:
    """Headline MITRE coverage from the repo's ``detections/`` tree.

    Returns ``None`` if ``detections/`` is missing, so the catalog
    section disappears cleanly for adopters who haven't seeded the
    tree yet. Sub-techniques roll up to their parent ID before
    matching against the curated matrix — see
    ``contentops.coverage.report.coverage_summary``.
    """
    detections = repo_root / "detections"
    if not detections.is_dir():
        return None
    from contentops.coverage import coverage_summary  # local import: cycle-safe
    summary = coverage_summary(detections)
    return MitreCoverageSpec(
        covered=summary.covered,
        total=summary.total,
        pct=summary.pct,
        matrix_label=summary.matrix_label,
    )


# ---------------------------------------------------------------------------
# Top level
# ---------------------------------------------------------------------------


def inspect_all(repo_root: Path) -> Inventory:
    """Build the full :class:`Inventory` for the checkout at ``repo_root``."""
    return Inventory(
        commands=inspect_cli(),
        traceability=inspect_traceability(repo_root),
        assets=inspect_assets(),
        lint_rules=inspect_lint_rules(),
        handlers=inspect_handlers(repo_root),
        workflows=inspect_workflows(repo_root),
        unit_tests=inspect_unit_tests(repo_root),
        integration_tests=inspect_integration_tests(repo_root),
        mitre_coverage=inspect_mitre_coverage(repo_root),
    )


__all__ = [
    "AssetSpec",
    "CommandSpec",
    "HandlerSpec",
    "Inventory",
    "LintRuleSpec",
    "MitreCoverageSpec",
    "TestSpec",
    "TraceSpec",
    "WorkflowSpec",
    "inspect_all",
    "inspect_assets",
    "inspect_cli",
    "inspect_handlers",
    "inspect_integration_tests",
    "inspect_lint_rules",
    "inspect_mitre_coverage",
    "inspect_traceability",
    "inspect_unit_tests",
    "inspect_workflows",
]
