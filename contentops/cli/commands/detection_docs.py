# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""``contentops detection-docs`` Click group.

Two subcommands:

* ``regenerate`` — write one markdown file per envelope under
  ``docs/detections/`` plus an index.
* ``check`` — exit 1 if any rendered file disagrees with disk, or if
  there are orphan files in ``docs/detections/`` that the generator
  doesn't own. CI gate.

Pattern mirrors ``contentops catalog`` (see
``contentops/cli/commands/catalog.py``). Both share the principle:
pure renderer + byte-identical diff.
"""

from __future__ import annotations

import sys
from pathlib import Path

import click

from contentops.config import is_operator_source_repo
from contentops.core.discovery import iter_loaded_assets
from contentops.docs import DETECTION_DOCS_DIR, render_all


def _resolve_repo_root() -> Path:
    here = Path.cwd().resolve()
    for parent in (here, *here.parents):
        if (parent / "pyproject.toml").exists():
            return parent
    return here


def _load_all_envelopes(root: Path) -> list:
    """Walk detections/ and parse every envelope, skipping bad ones quietly.

    Bad envelopes will be caught by ``contentops lint`` — we don't
    double-report here; we just exclude them from the docs.
    """
    return list(iter_loaded_assets(root / "detections"))


def _expected_paths(rendered: dict[str, str], root: Path) -> set[Path]:
    return {root / rel for rel in rendered}


@click.group("detection-docs")
def detection_docs_group() -> None:
    """Per-detection markdown documentation (NVISO Part 4)."""


@detection_docs_group.command("regenerate")
@click.option(
    "--repo-root",
    type=click.Path(path_type=Path, exists=True, file_okay=False),
    default=None,
    help="Repo root override. Defaults to walking up from cwd for pyproject.toml.",
)
@click.option(
    "--prune-orphans/--no-prune-orphans", default=True, show_default=True,
    help="Delete files in docs/detections/ that the generator doesn't own.",
)
def detection_docs_regenerate(repo_root: Path | None, prune_orphans: bool) -> None:
    """Regenerate per-detection markdown from the live envelopes."""
    root = (repo_root or _resolve_repo_root()).resolve()
    rendered = render_all(_load_all_envelopes(root), repo_root=root)
    docs_dir = root / DETECTION_DOCS_DIR
    docs_dir.mkdir(parents=True, exist_ok=True)

    written = 0
    for rel, body in sorted(rendered.items()):
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        # UTF-8 + LF newlines so Windows checkouts match Linux bytes.
        target.write_bytes(body.encode("utf-8"))
        written += 1

    pruned = 0
    if prune_orphans and docs_dir.exists():
        keepers = {p.resolve() for p in _expected_paths(rendered, root)}
        for existing in docs_dir.rglob("*.md"):
            if existing.resolve() not in keepers:
                existing.unlink()
                pruned += 1

    click.echo(f"wrote {written} file(s) under {DETECTION_DOCS_DIR}/")
    if prune_orphans:
        click.echo(f"pruned {pruned} orphan file(s)")


@detection_docs_group.command("check")
@click.option(
    "--repo-root",
    type=click.Path(path_type=Path, exists=True, file_okay=False),
    default=None,
    help="Repo root override.",
)
def detection_docs_check(repo_root: Path | None) -> None:
    """Exit 1 if the committed detection docs drift from the renderer.

    Two failure modes:
      * A committed file disagrees with the renderer output.
      * An orphan .md file exists under docs/detections/ that the
        generator doesn't own (probably from a deleted envelope).

    Fix: run ``contentops detection-docs regenerate`` and commit the diff.
    """
    root = (repo_root or _resolve_repo_root()).resolve()
    if not is_operator_source_repo(root):
        click.echo(
            "detection-docs check: skipped — not the operator source repo "
            "(no .github/workflows/public-sync.yml). This drift gate only "
            "runs in the source-of-truth repo; a public-mirror or adopter "
            "clone strips docs/detections/."
        )
        return
    rendered = render_all(_load_all_envelopes(root), repo_root=root)
    docs_dir = root / DETECTION_DOCS_DIR

    drifted: list[str] = []
    missing: list[str] = []
    for rel, expected in sorted(rendered.items()):
        target = root / rel
        if not target.exists():
            missing.append(rel)
            continue
        actual = target.read_bytes().decode("utf-8")
        if actual != expected:
            drifted.append(rel)

    orphans: list[str] = []
    if docs_dir.exists():
        expected_paths = {(root / rel).resolve() for rel in rendered}
        for existing in docs_dir.rglob("*.md"):
            if existing.resolve() not in expected_paths:
                orphans.append(str(existing.relative_to(root)).replace("\\", "/"))

    if missing or drifted or orphans:
        if missing:
            click.echo(f"missing: {len(missing)} file(s)", err=True)
            for m in missing[:5]:
                click.echo(f"  {m}", err=True)
        if drifted:
            click.echo(f"drifted: {len(drifted)} file(s)", err=True)
            for d in drifted[:5]:
                click.echo(f"  {d}", err=True)
        if orphans:
            click.echo(f"orphans: {len(orphans)} file(s)", err=True)
            for o in orphans[:5]:
                click.echo(f"  {o}", err=True)
        click.echo(
            "fix: run `contentops detection-docs regenerate` and commit the diff.",
            err=True,
        )
        sys.exit(1)
    click.echo(f"{DETECTION_DOCS_DIR}/ is in sync with detections/.")


__all__ = ["detection_docs_group"]
