# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""``contentops catalog`` Click group.

Two subcommands:

* ``regenerate`` — write the canonical catalog markdown to
  ``docs/reference/generated-catalog.md`` (or to the path given by
  ``--out``).
* ``check`` — exit 1 when the on-disk catalog disagrees with what the
  introspection module would produce. CI gate.

Both commands share the same renderer
(:func:`contentops.catalog.render.render_markdown`); ``check`` is just
``regenerate --dry-run`` with an exit-code contract.
"""

from __future__ import annotations

import sys
from pathlib import Path

import click

from contentops.catalog import GENERATED_FILE, inspect_all, render_markdown
from contentops.config import is_operator_source_repo


def _resolve_repo_root() -> Path:
    """Walk upward from cwd looking for a ``pyproject.toml`` marker.

    The catalog lives at the repository root, so this lets the CLI
    work whether the caller is at the repo root or in a sub-directory.
    Falls back to cwd if no marker is found.
    """
    here = Path.cwd().resolve()
    for parent in (here, *here.parents):
        if (parent / "pyproject.toml").exists():
            return parent
    return here


@click.group("catalog")
def catalog_group() -> None:
    """Code-driven catalog of CLI commands, assets, lint rules,
    handlers, workflows, and tests.
    """


@catalog_group.command("regenerate")
@click.option(
    "--out", "out_path",
    type=click.Path(path_type=Path),
    default=None,
    help=(
        "Where to write the generated markdown. Defaults to "
        f"`{GENERATED_FILE}` under the repo root."
    ),
)
@click.option(
    "--repo-root",
    type=click.Path(path_type=Path, exists=True, file_okay=False),
    default=None,
    help="Repo root override. Defaults to walking up from cwd for pyproject.toml.",
)
def catalog_regenerate(out_path: Path | None, repo_root: Path | None) -> None:
    """Regenerate the catalog markdown from the live codebase."""
    root = (repo_root or _resolve_repo_root()).resolve()
    target = (out_path if out_path is not None else root / GENERATED_FILE)
    inv = inspect_all(root)
    body = render_markdown(inv)
    target.parent.mkdir(parents=True, exist_ok=True)
    # Use UTF-8 + LF newlines so Windows checkouts produce the same
    # bytes as Linux / macOS. The CI gate compares byte-for-byte.
    target.write_bytes(body.encode("utf-8"))
    click.echo(f"wrote {target}")


@catalog_group.command("check")
@click.option(
    "--repo-root",
    type=click.Path(path_type=Path, exists=True, file_okay=False),
    default=None,
    help="Repo root override. Defaults to walking up from cwd for pyproject.toml.",
)
def catalog_check(repo_root: Path | None) -> None:
    """Exit 1 if the committed catalog drifts from the regenerated catalog.

    CI gate. When this fires, the operator runs
    ``contentops catalog regenerate`` and commits the diff.
    """
    root = (repo_root or _resolve_repo_root()).resolve()
    if not is_operator_source_repo(root):
        click.echo(
            "catalog check: skipped — not the operator source repo "
            "(no .github/workflows/public-sync.yml). This drift gate only "
            "runs in the source-of-truth repo; a public-mirror or adopter "
            "clone has a reduced file set."
        )
        return
    target = root / GENERATED_FILE
    inv = inspect_all(root)
    expected = render_markdown(inv)
    if not target.exists():
        click.echo(
            f"catalog drift: {GENERATED_FILE} does not exist; "
            f"run `contentops catalog regenerate` and commit it.",
            err=True,
        )
        sys.exit(1)
    actual = target.read_bytes().decode("utf-8")
    if actual != expected:
        click.echo(
            f"catalog drift: committed {GENERATED_FILE} disagrees with "
            f"the regenerated output. Run `contentops catalog regenerate` "
            f"and commit the diff.",
            err=True,
        )
        sys.exit(1)
    click.echo(f"{GENERATED_FILE} is in sync with the codebase.")


__all__ = ["catalog_group"]
