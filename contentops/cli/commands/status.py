# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""``contentops status`` -- generate dashboard markdown files.

Thin CLI wrapper over :mod:`contentops.status`. Two subcommands plus
an ``all`` convenience that runs both -- what the daily cron workflow
invokes.

The subcommands are read-only against tenant infra: ``configuration``
runs :func:`contentops.devex.conformance.run_conformance` for layers
L1 + L2 (local install + tenant.yml shape -- no Azure creds needed);
``deployments`` reads the local ``state/state.json`` and
``audit/*.jsonl`` chain plus walks ``detections/``.

Output paths default to ``docs/status/<page>.md``; pass ``--out`` to
write elsewhere or ``-`` for stdout.
"""

from __future__ import annotations

import sys
from pathlib import Path

import click

from contentops.devex.conformance import load_config, run_conformance
from contentops.state import load_state
from contentops.status import render_configuration, render_deployments

_DEFAULT_CONFIGURATION_OUT = Path("docs/status/configuration.md")
_DEFAULT_DEPLOYMENTS_OUT = Path("docs/status/deployments.md")
_DEFAULT_DETECTIONS = Path("detections")
_DEFAULT_AUDIT_DIR = Path("audit")


def _write(rendered: str, out: Path) -> None:
    if str(out) == "-":
        sys.stdout.write(rendered)
        sys.stdout.flush()
        return
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(rendered, encoding="utf-8")
    click.echo(f"wrote {out}", err=True)


@click.group("status")
def status_group() -> None:
    """Generate dashboard markdown for the docs/status/ tree."""


@status_group.command("configuration")
@click.option(
    "--scope",
    default="L1,L2",
    help=(
        "Layers to include. Default L1,L2 -- local install + tenant.yml "
        "shape only; no Azure creds required. Pass 'all' or a wider "
        "range (e.g. L1-L7) to include token / RBAC / Graph / GitHub "
        "checks (requires the same OIDC creds as the apply workflow)."
    ),
)
@click.option(
    "--out",
    type=click.Path(path_type=Path),
    default=_DEFAULT_CONFIGURATION_OUT,
    help="Output path (default docs/status/configuration.md). '-' for stdout.",
)
@click.option(
    "--config",
    "config_path",
    type=click.Path(path_type=Path, exists=True),
    default=None,
    help="Override conformance expectations from this YAML file.",
)
def status_configuration_cmd(
    scope: str,
    out: Path,
    config_path: Path | None,
) -> None:
    """Render configuration health to docs/status/configuration.md."""
    # Reuse the conformance command's scope parser so 'L1,L2', 'L1-L4',
    # and 'all' all work identically.
    from contentops.cli.commands.conformance import _parse_scope

    scope_tuple = _parse_scope(scope)
    cfg = load_config(config_path)
    report = run_conformance(scope=scope_tuple, config=cfg)
    _write(render_configuration(report), out)


@status_group.command("deployments")
@click.option(
    "--detections",
    "detections_root",
    type=click.Path(path_type=Path),
    default=_DEFAULT_DETECTIONS,
    help="Root of the detections tree (default detections/).",
)
@click.option(
    "--audit",
    "audit_dir",
    type=click.Path(path_type=Path),
    default=_DEFAULT_AUDIT_DIR,
    help="Audit chain directory (default audit/).",
)
@click.option(
    "--env",
    default=None,
    help="State env (loads state/<env>/state.json); default loads state/state.json.",
)
@click.option(
    "--failures-only",
    is_flag=True,
    default=False,
    help=(
        "Collapse rendered rows to just 'failed' + 'orphan'. The "
        "Totals summary still reflects the full counts."
    ),
)
@click.option(
    "--out",
    type=click.Path(path_type=Path),
    default=_DEFAULT_DEPLOYMENTS_OUT,
    help="Output path (default docs/status/deployments.md). '-' for stdout.",
)
def status_deployments_cmd(
    detections_root: Path,
    audit_dir: Path,
    env: str | None,
    failures_only: bool,
    out: Path,
) -> None:
    """Render deployment status to docs/status/deployments.md."""
    state = load_state(env)
    rendered = render_deployments(
        detections_root=detections_root,
        state=state,
        audit_dir=audit_dir,
        failures_only=failures_only,
    )
    _write(rendered, out)


@status_group.command("all")
@click.option(
    "--scope",
    default="L1,L2",
    help="Conformance scope for the configuration page. See `status configuration --help`.",
)
@click.option(
    "--env",
    default=None,
    help="State env for the deployments page.",
)
@click.option(
    "--failures-only",
    is_flag=True,
    default=False,
    help="Forward `--failures-only` to the deployments page.",
)
@click.pass_context
def status_all_cmd(
    ctx: click.Context,
    scope: str,
    env: str | None,
    failures_only: bool,
) -> None:
    """Generate both pages with their default output paths.

    Invokes ``status configuration`` then ``status deployments`` with
    defaults. This is what the daily cron workflow calls.
    """
    ctx.invoke(status_configuration_cmd, scope=scope, out=_DEFAULT_CONFIGURATION_OUT, config_path=None)
    ctx.invoke(
        status_deployments_cmd,
        detections_root=_DEFAULT_DETECTIONS,
        audit_dir=_DEFAULT_AUDIT_DIR,
        env=env,
        failures_only=failures_only,
        out=_DEFAULT_DEPLOYMENTS_OUT,
    )


__all__ = ["status_group"]
