# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Wire up handler factories on the default registry.

Imported for side effects from `contentops.cli.commands`.
Constructing a handler must NOT trigger network or auth — providers/
clients are created lazily inside the handler when first needed.

Multi-workspace selection (DESIGN §6, v3 schema):
    The CLI orchestrator picks the active workspace and exports
    ``PIPELINE_WORKSPACE_NAME`` before running operations. The
    factories below resolve that env var to a ``SentinelWorkspaceConfig``
    via :func:`contentops.config.select_workspaces`. When unset and the
    tenant has exactly one workspace, that one is used implicitly;
    otherwise the factory raises (the CLI should have set the env var).
"""

from __future__ import annotations

import os

from contentops.config import (
    SentinelWorkspaceConfig,
    load_tenant_config,
    select_workspaces,
)
from contentops.core.asset import Asset
from contentops.core.registry import default_registry
from contentops.defender.client import DefenderClient
from contentops.handlers.defender_custom_detection import DefenderCustomDetectionHandler
from contentops.handlers.sentinel_analytic import SentinelAnalyticHandler
from contentops.handlers.sentinel_data_connector import SentinelDataConnectorHandler
from contentops.handlers.sentinel_hunting import SentinelHuntingHandler
from contentops.handlers.sentinel_parser import SentinelParserHandler
from contentops.handlers.sentinel_watchlist import SentinelWatchlistHandler
from contentops.providers.sentinel_arm import SentinelArmProvider


def _active_workspace() -> SentinelWorkspaceConfig:
    """Resolve the active Sentinel workspace from env / single-workspace fallback.

    Reads ``PIPELINE_WORKSPACE_NAME`` (set by the CLI orchestrator) and
    looks it up in ``tenant.yml``. When the env var is unset and the
    tenant has exactly one workspace, that one is returned implicitly
    (single-workspace tenants don't need to set the env var).
    """
    cfg = load_tenant_config()
    name = os.environ.get("PIPELINE_WORKSPACE_NAME")
    if name:
        return cfg.workspace_by_name(name)
    selected = select_workspaces(cfg, role=None, workspace=None)
    if len(selected) != 1:
        raise RuntimeError(
            "PIPELINE_WORKSPACE_NAME is unset and the tenant has "
            f"{len(selected)} Sentinel workspaces. The CLI orchestrator "
            "should set PIPELINE_WORKSPACE_NAME per iteration; if you're "
            "calling a handler factory directly, pass --workspace or --role."
        )
    return selected[0]


def _defender_client() -> DefenderClient:
    from contentops.utils.auth import get_credential
    return DefenderClient(credential=get_credential())


def _sentinel_arm_provider() -> SentinelArmProvider:
    from contentops.utils.auth import get_credential
    return SentinelArmProvider(_active_workspace(), credential=get_credential())


def register_default_handlers() -> None:
    """Idempotent — safe to call from multiple entry points.

    Engine gating:
    * Sentinel handlers (analytic, hunting, watchlist, parser,
      data_connector) only register when ``cfg.sentinelWorkspaces`` is
      non-empty. Skipping these in a Defender-only tenant prevents
      ``_active_workspace()`` from raising at handler-construction time.
    * Defender handler only registers when ``cfg.defender`` is set
      AND ``cfg.defender.enabled`` is True. Omitting the ``defender:``
      block or setting ``enabled: false`` produces a Sentinel-only
      runtime.

    A tenant with both engines disabled leaves the registry empty —
    legal but operationally degenerate (``config validate`` warns
    on this state; ``config validate --strict`` exits 1).
    """
    # Load tenant config once at the top. ``load_tenant_config`` is a
    # cheap file read; ``FileNotFoundError`` (no tenant.yml present)
    # falls through to the "register everything" legacy path so unit
    # tests that inject handlers via the registry directly without a
    # tenant.yml file keep working.
    #
    # Other exceptions (Pydantic ``ValidationError``, ``ValueError``,
    # ``KeyError`` from a malformed config) are NOT swallowed: a real
    # schema bug should fail loud at startup with a clear parse error,
    # not silently fall through to "both engines enabled" and surface
    # later as an obscure ARM 400.
    try:
        cfg = load_tenant_config()
        sentinel_enabled = bool(cfg.sentinelWorkspaces)
        defender_enabled = cfg.defender is not None and cfg.defender.enabled
    except FileNotFoundError:
        sentinel_enabled = True
        defender_enabled = True

    if sentinel_enabled and not default_registry.has(Asset.SENTINEL_ANALYTIC):
        default_registry.register(
            Asset.SENTINEL_ANALYTIC,
            lambda: SentinelAnalyticHandler(_sentinel_arm_provider),
        )
    if defender_enabled and not default_registry.has(Asset.DEFENDER_CUSTOM_DETECTION):
        default_registry.register(
            Asset.DEFENDER_CUSTOM_DETECTION,
            lambda: DefenderCustomDetectionHandler(_defender_client),
        )
    if sentinel_enabled and not default_registry.has(Asset.SENTINEL_HUNTING):
        default_registry.register(
            Asset.SENTINEL_HUNTING,
            lambda: SentinelHuntingHandler(_sentinel_arm_provider),
        )
    if sentinel_enabled and not default_registry.has(Asset.SENTINEL_WATCHLIST):
        default_registry.register(
            Asset.SENTINEL_WATCHLIST,
            lambda: SentinelWatchlistHandler(_sentinel_arm_provider),
        )
    if sentinel_enabled and not default_registry.has(Asset.SENTINEL_PARSER):
        default_registry.register(
            Asset.SENTINEL_PARSER,
            lambda: SentinelParserHandler(_sentinel_arm_provider),
        )
    if sentinel_enabled and not default_registry.has(Asset.SENTINEL_DATA_CONNECTOR):
        default_registry.register(
            Asset.SENTINEL_DATA_CONNECTOR,
            lambda: SentinelDataConnectorHandler(_sentinel_arm_provider),
        )
