# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Archive-based commands: ``restore`` and ``snapshot-diff``."""

from __future__ import annotations

import sys
from pathlib import Path

import click

from contentops.core.asset import Asset


@click.command("restore")
@click.argument("archive", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--out", "target",
    type=click.Path(path_type=Path),
    default=Path("detections"),
    help="Destination directory (default: detections/).",
)
@click.option(
    "--force", is_flag=True, default=False,
    help="Allow restoring into a non-empty target. Without this "
         "flag, restore refuses to overlay a populated detections/.",
)
def restore_cmd(archive: Path, target: Path, force: bool) -> None:
    """Restore detections/ from a `contentops collect` archive (DR / inverse).

    \b
    Designed for:
      * Disaster recovery after a destructive `contentops prune --no-dry-run --yes`.
      * Restoring from a snapshot before a catastrophic git-history rewrite.
      * Bringing a fresh clone up to a known-good state quickly.

    The archive is expected to be a .tar.gz / .tgz with detections/
    at its root (matching what `contentops collect` produces).
    """
    from contentops.restore import RestoreError, restore_from_archive
    try:
        report = restore_from_archive(archive, target=target, force=force)
    except RestoreError as exc:
        click.echo(f"error: {exc}", err=True)
        sys.exit(1)
    click.echo(
        f"Restored {len(report.written)} file(s) from {report.archive} -> {report.target}"
    )
    if report.manifest_present:
        click.echo(f"  manifest: present, asset_count={report.manifest_assets}")
    if report.skipped:
        click.echo(
            f"  skipped {len(report.skipped)} non-YAML/non-MANIFEST entry/entries"
        )


@click.command("snapshot-diff")
@click.argument("archive_a", type=click.Path(exists=True, path_type=Path))
@click.argument("archive_b", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--asset",
    type=click.Choice([a.value for a in Asset]),
    default=None,
    help="Restrict the rendered diff to one asset kind (totals "
         "still reflect the full archive).",
)
@click.option(
    "--format", "output_format",
    type=click.Choice(["markdown", "json"]),
    default="markdown",
)
@click.option(
    "--out", type=click.Path(path_type=Path), default=None,
    help="Write rendered diff to this file instead of stdout.",
)
def snapshot_diff_cmd(
    archive_a: Path, archive_b: Path,
    asset: str | None, output_format: str, out: Path | None,
) -> None:
    """Content-aware diff between two `contentops collect` archives.

    Compares envelopes by ``(asset_kind, envelope_id)`` rather
    than by file path, so a renamed file with unchanged content
    reports as `unchanged`. Closes G23. Pairs with F10 (`pipeline
    restore`).

    Useful for prod <-> integration parity checks before promoting
    content between environments. Exit 2 when changes are found.
    """
    from contentops.snapshot_diff import (
        SnapshotDiffError,
        diff_archives, render_json, render_markdown,
    )

    try:
        report = diff_archives(archive_a, archive_b)
    except SnapshotDiffError as exc:
        click.echo(f"error: {exc}", err=True)
        sys.exit(1)

    if output_format == "json":
        rendered = render_json(report)
    else:
        rendered = render_markdown(report, asset=asset)

    if out is not None:
        out.write_text(rendered, encoding="utf-8")
        click.echo(f"wrote {out}", err=True)
    else:
        sys.stdout.write(rendered)
        sys.stdout.flush()

    if report.has_changes():
        sys.exit(2)
