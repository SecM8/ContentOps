# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""``contentops undeployed-rules`` — repo rules with no apply record in state."""

from __future__ import annotations

import sys
from pathlib import Path

import click


@click.command("undeployed-rules")
@click.option(
    "--path", "detections_path",
    type=click.Path(path_type=Path),
    default=Path("detections"),
    help="Root detections directory (default ``detections/``).",
)
@click.option(
    "--env", default=None,
    help="State env to reconcile against (``state/<env>/state.json``). "
         "Default: the single-env ``state/state.json``.",
)
@click.option(
    "--format", "output_format",
    type=click.Choice(["md", "json"]),
    default="md",
)
@click.option(
    "--out", type=click.Path(path_type=Path), default=None,
    help="Write the report to this path instead of stdout.",
)
def undeployed_rules_cmd(
    detections_path: Path,
    env: str | None,
    output_format: str,
    out: Path | None,
) -> None:
    """List detections in the repo with no apply record in state.

    \b
    The blind spot that ``coverage`` and ``silent-rules`` both miss: a
    ``status: production`` rule authored in ``detections/`` that was never
    deployed to the tenant; it should be protecting prod but isn't. An
    undeployed ``experimental`` rule is expected (experimental doesn't
    deploy) and is listed but not flagged.

    Offline + read-only: reconciles git-tracked envelopes against the
    applied-state file. Run ``contentops state sync pull`` first so the
    state is present (without it every rule looks undeployed).
    """
    from contentops.state import load_state
    from contentops.undeployed import (
        find_undeployed, render_json, render_markdown,
    )

    if not detections_path.is_dir():
        click.echo(f"error: {detections_path} is not a directory", err=True)
        sys.exit(2)

    state = load_state(env)
    report = find_undeployed(detections_path, state)
    rendered = (
        render_json(report) if output_format == "json"
        else render_markdown(report)
    )
    if out is not None:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(rendered, encoding="utf-8")
        click.echo(f"wrote {out}", err=True)
    else:
        sys.stdout.write(rendered)
        sys.stdout.flush()


__all__ = ["undeployed_rules_cmd"]
