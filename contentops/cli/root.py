# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Root Click ``cli`` group for the detection pipeline.

This module defines only the top-level ``cli`` group plus its global
options (``-v / --verbose`` and ``--env``). The command set lives in
``contentops.cli.commands`` and is attached onto this group by
``contentops.cli.__init__`` after the empty group is imported.
"""

from __future__ import annotations

import logging
import os

import click


@click.group()
@click.version_option(
    # Read version from the installed distribution metadata. Resolves
    # lazily when ``--version`` is actually invoked, so an uninstalled
    # source checkout still imports cleanly.
    package_name="contentops",
    message="ContentOps powered by SecM8 v%(version)s",
)
@click.option(
    "-v", "--verbose",
    count=True,
    help="Bump log verbosity. By default the noisy SDK loggers "
         "(azure.identity / httpx / urllib3) are WARNING and the "
         "per-rule 'metadata fell back to loose parse' lines are "
         "suppressed, so command output stays readable. -v shows the "
         "loose-parse lines and promotes the SDK loggers to INFO; -vv "
         "promotes everything to DEBUG.",
)
@click.option(
    "--env",
    "tenant_env",
    default=None,
    help="Tenant environment slug; loads config/tenant.<env>.yml. "
         "Overrides $PIPELINE_ENV.",
)
def cli(verbose: int, tenant_env: str | None) -> None:
    """ContentOps powered by SecM8 - manage Microsoft Sentinel and Defender XDR content.

    \b
    Workspace targeting on multi-workspace tenants:
      --role <role>      Iterate every Sentinel workspace tagged with
                         that role (prod / integration / dev).
      --workspace <name> Target one workspace by exact name.

    The two are mutually exclusive and supported by apply, plan, drift,
    prune, rollback, collect, doctor, and other workspace-scoped
    commands. On a single-workspace tenant, both default to that
    workspace.
    """
    from contentops.utils.env import load_env_file
    load_env_file()

    # Top-level logger is INFO so per-asset progress / warnings still
    # surface; the noisy SDKs default to WARNING (overridden by -v / -vv).
    # _apply_log_levels lives in contentops.cli.commands so the
    # subcommand layer also calls it idempotently.
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    from contentops.cli.commands import _apply_log_levels, _emit_loose_parse_summary
    _apply_log_levels(verbosity=verbose)

    # Collapse the per-rule "metadata fell back to loose parse" WARNINGs
    # (one per collected rule missing strict authoring fields) into a
    # single trailing note. Reset the tally now, emit it once when the
    # command's context closes. See contentops.core.envelope and
    # _VERBOSE_ONLY_LOGGERS.
    from contentops.core.envelope import reset_loose_parse_fallbacks
    reset_loose_parse_fallbacks()
    ctx = click.get_current_context()
    # `contentops lint` already prints the per-rule metadata findings, so
    # the aggregated note (which says "run contentops lint") would just
    # point back at the command you're running. Skip it there; every
    # other detection-loading command (doctor / drift / plan / collect /
    # coverage / …) still gets the one-liner. This matters for adopters
    # too: once they clone the mirror, `collect` their tenant, and run
    # `lint` on their own filled repo, the self-referential note would
    # read as a bug.
    if ctx.invoked_subcommand != "lint":
        ctx.call_on_close(lambda: _emit_loose_parse_summary(verbose))
    if tenant_env is not None:
        # Subcommands resolve config via contentops.config.load_tenant_config(),
        # which honours PIPELINE_ENV. Setting it here is the simplest way to
        # propagate the choice without threading kwargs through every command.
        os.environ["PIPELINE_ENV"] = tenant_env


__all__ = ["cli"]
