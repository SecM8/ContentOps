# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""``contentops conformance`` — deployment conformance check.

Read-only verification that the local install, tenant config, OIDC /
token acquisition, Microsoft Graph permissions, Azure RBAC, functional
reachability, and (optionally) the GitHub repo are all wired correctly.

Single command, structured output, actionable remediation. Safe to run
against production tenants — every probe is a read-only ``GET`` /
``POST /query``; no PUT / PATCH / DELETE is issued.

Quick start:

    contentops conformance                  # full report, every layer
    contentops conformance --scope L1,L2,L3 # local + tenant config + token only
    contentops conformance --format json    # machine-readable sidecar
    contentops conformance --out report.txt # write report to a file
"""

from __future__ import annotations

import sys
from pathlib import Path

import click

from contentops.devex.conformance import (
    ConformanceConfig,
    apply_identity_profile,
    load_config,
    render_json,
    render_text,
    run_conformance,
)


_ALL_LAYERS = ("L1", "L2", "L3", "L4", "L5", "L6", "L7")


def _parse_scope(scope: str) -> tuple[str, ...]:
    """Accept ``L1,L2`` or ``L1-L4`` or ``all`` (case-insensitive)."""
    if not scope or scope.strip().lower() == "all":
        return _ALL_LAYERS
    tokens = [t.strip().upper() for t in scope.split(",") if t.strip()]
    expanded: list[str] = []
    for token in tokens:
        if "-" in token:
            start, end = token.split("-", 1)
            if start in _ALL_LAYERS and end in _ALL_LAYERS:
                i, j = _ALL_LAYERS.index(start), _ALL_LAYERS.index(end)
                expanded.extend(_ALL_LAYERS[i: j + 1])
            else:
                raise click.UsageError(f"unknown layer range: {token}")
        else:
            if token not in _ALL_LAYERS:
                raise click.UsageError(
                    f"unknown layer: {token} (valid: {', '.join(_ALL_LAYERS)})",
                )
            expanded.append(token)
    # Preserve canonical order, deduplicate.
    return tuple(sorted(set(expanded), key=_ALL_LAYERS.index))


@click.command("conformance")
@click.option(
    "--scope",
    default="all",
    help=(
        "Which layers to run. Comma-separated list (L1,L2,L3), a range "
        "(L1-L4), or 'all' (default). L1 install, L2 tenant config, "
        "L3 token, L4 Graph perms, L5 Azure RBAC, L6 functional reach, "
        "L7 GitHub."
    ),
)
@click.option(
    "--format", "output_format",
    type=click.Choice(["text", "json"]),
    default="text",
    help="Output format. Text is the human table; JSON is the sidecar.",
)
@click.option(
    "--out",
    type=click.Path(path_type=Path),
    default=None,
    help="Write the report to this path instead of stdout.",
)
@click.option(
    "--config",
    "config_path",
    type=click.Path(path_type=Path, exists=True),
    default=None,
    help=(
        "Override conformance expectations from this YAML file. Defaults "
        "to .contentops-conformance.yml at the repo root if present."
    ),
)
@click.option(
    "--identity",
    type=click.Choice(["write", "read"]),
    default="write",
    show_default=True,
    help=(
        "Which App Registration this run verifies. 'write' (deploy "
        "identity): expects Sentinel Contributor + CustomDetection."
        "ReadWrite.All. 'read' (automation identity): expects "
        "Sentinel/Log-Analytics Reader + CustomDetection.Read.All AND "
        "asserts the write grants are ABSENT (separation of duties). Run "
        "the command as the matching OIDC identity (e.g. the automation "
        "environment for --identity read)."
    ),
)
@click.option(
    "--exit-zero", is_flag=True, default=False,
    help=(
        "Always exit 0, even if checks FAIL. Useful when the conformance "
        "command is wired into a wrapper that reads the JSON sidecar."
    ),
)
def conformance_cmd(
    scope: str,
    output_format: str,
    out: Path | None,
    config_path: Path | None,
    identity: str,
    exit_zero: bool,
) -> None:
    """Verify the ContentOps deployment is wired correctly (read-only)."""
    scope_tuple = _parse_scope(scope)
    cfg = apply_identity_profile(load_config(config_path), identity)
    report = run_conformance(scope=scope_tuple, config=cfg)

    rendered = (
        render_json(report) if output_format == "json"
        else render_text(report)
    )
    if out is not None:
        out.write_text(rendered, encoding="utf-8")
        click.echo(f"wrote {out}", err=True)
    else:
        sys.stdout.write(rendered)
        sys.stdout.flush()

    if not exit_zero and not report.passed:
        sys.exit(1)


__all__ = ["conformance_cmd"]
