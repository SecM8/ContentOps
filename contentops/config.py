# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tenant configuration loader.

Schema (v3 — single tenant, multi workspace):

    tenant:
      name: production-tenant      # human label, for logging
      tenantId: <AAD-tenant-GUID>  # bound by federated credential / .env

      defender:                    # optional; omit for "no Defender XDR"
        enabled: true

      sentinelWorkspaces:          # 0 to N
        - role: prod | integration | dev
          subscriptionId: ...
          resourceGroup: ...
          workspaceName: ...       # also the CLI ``--workspace`` selector
          location: westeurope

Selection of the active workspace happens at CLI invocation time via
``--role`` or ``--workspace``. Inside the pipeline, factories read the
``PIPELINE_WORKSPACE_NAME`` environment variable to pick the right
workspace; the outer orchestration loop sets it per iteration.

Identity (clientId / tenantId / clientSecret) is **not** in this file —
it always comes from environment variables (DefaultAzureCredential's
chain). The tenant file only declares the AAD tenant the identity must
belong to.

Multi-environment resolution order, when neither ``env`` nor ``path``
is given to :func:`load_tenant_config`:

  1. ``PIPELINE_ENV`` environment variable -> ``config/tenant.<env>.yml``
  2. fall back to ``config/tenant.yml``

DESIGN §6 (env model) and §13 (state) cover the rationale for the
v2→v3 schema migration; older single-workspace ``sentinel:`` blocks
will fail to load loudly with a pointer to ``scripts/migrate_tenant_config.py``.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Literal

log = logging.getLogger(__name__)

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator


# `test` is a DEDICATED test workspace role (DESIGN §6, closes G21).
# An envelope marked `status: test` deploys ONLY to workspaces with
# `role: test`; conversely, a `role: test` workspace accepts only
# `status: test` (+ `deprecated`) -- it is NOT a fallback for prod
# content. Operators who don't want a separate test workspace can
# continue to use `role: integration`, which accepts both TEST and
# PRODUCTION as a shared-lower-env pattern. The semantic distinction
# is enforced by `contentops.core.env_status.allowed_statuses_for_env`.
WorkspaceRole = Literal["prod", "integration", "dev", "test"]


class WorkspaceSafeguards(BaseModel):
    """Per-workspace write/purge gates honoured by destructive CLI paths.

    Three knobs, each independently scoped:

    * ``writeAllowed`` — gates ``contentops apply`` / ``deploy`` / any
      write to the tenant. Default ``True`` so the pipeline works
      out-of-the-box for adopters (lenient public default per
      ``feedback_internal_fail_fast_public_smooth``).
    * ``purgeAllowed`` — gates ``contentops prune``. Default ``False``
      so accidental dispatches against a "wrong env" workspace
      fail-closed even with ``--no-dry-run --yes --confirm CONFIRM``.
    * ``maxDelete`` — hard upper bound on deletions per prune run.
      Acts as an additional clamp on top of the CLI's
      ``--max-deletes`` and the workflow's ``max_deletes`` input —
      the *minimum* of the three is the effective ceiling.

    Operator flow to actually purge a workspace:

    1. Edit ``config/tenant.yml`` (or the ``TENANT_CONFIG_YAML``
       GitHub Secret in CI) to set ``purgeAllowed: true`` and a
       sufficient ``maxDelete`` on the target workspace.
    2. Run the prune (CLI or workflow).
    3. Revert the secret back to the locked defaults.

    This is the fourth physical brake on destructive ops — after
    ``workflow_dispatch``, the ``CONFIRM`` input, and the GitHub
    Environment reviewer gate. The first three live in CI; this one
    lives in the config that CI reads, so even a CI compromise
    cannot bypass it without rotating the tenant secret.
    """

    model_config = ConfigDict(extra="forbid")

    writeAllowed: bool = True
    purgeAllowed: bool = False
    maxDelete: int = Field(default=25, ge=0, le=9999)


class SentinelWorkspaceConfig(WorkspaceSafeguards):
    """One Sentinel (Log Analytics) workspace within a tenant.

    The ``workspaceName`` field doubles as the CLI ``--workspace``
    selector — it must be unique within a tenant file. Azure also
    enforces uniqueness at the (subscriptionId, resourceGroup,
    workspaceName) level; we mirror that constraint in
    :meth:`TenantConfig._validate_workspace_uniqueness`.

    Inherits the three workspace safeguard fields
    (``writeAllowed`` / ``purgeAllowed`` / ``maxDelete``) from
    :class:`WorkspaceSafeguards` — see its docstring for the gate
    semantics.
    """

    model_config = ConfigDict(extra="forbid")

    # ``role`` defaults to ``prod`` so direct ``SentinelConfig(...)``
    # construction (e.g. in unit tests) keeps working without
    # boilerplate. Real tenant YAML files should always set it
    # explicitly — that's what the CLI ``--role`` selector matches on.
    role: WorkspaceRole = "prod"
    primary: bool = False
    subscriptionId: str
    resourceGroup: str
    workspaceName: str
    location: str = "westeurope"


# Backward-compat alias. Sentinel client / provider code still references
# ``SentinelConfig`` as a structural type; the new SentinelWorkspaceConfig
# carries the same fields plus ``role``, so it's a drop-in.
SentinelConfig = SentinelWorkspaceConfig


class DefenderConfig(WorkspaceSafeguards):
    """Tenant-level Defender XDR config.

    Defender XDR is a *tenant-level* service — one copy of every
    custom detection / saved query / suppression rule exists per
    tenant. It is therefore NOT env-scoped: a single
    ``defender:`` block governs every Defender op the pipeline does.

    Inherits the three safeguard fields from
    :class:`WorkspaceSafeguards`. Their semantics are identical to
    the Sentinel-workspace case; the only difference is scope
    (tenant-wide instead of one-workspace).
    """

    model_config = ConfigDict(extra="forbid")
    enabled: bool = True


class TenantPolicy(BaseModel):
    """Project-level policy toggles for this tenant (Section T).

    Currently a single setting; the block exists as a forward-looking
    namespace so future policy decisions (e.g. ``requireSignoffOnPromote``,
    ``maxOpenWarnings``, ``allowExperimentalToProd``) can land here
    without polluting top-level tenant identity fields.

    ``scaffoldStrict`` controls whether the META002–META005 lint rules
    (description / attackDescription / references / falsePositives)
    surface as **errors** (CI-blocking) or **warnings** (informational
    backlog meter). Default ``False`` -- lenient-by-default matches
    the operational reality that the G24 authoring backlog still
    exists on collected envelopes, so an out-of-the-box tenant.yml
    should not fail CI on metadata gaps the operator hasn't authored
    yet. Set to ``True`` once the backlog is drained (or for a new
    tenant authored strict-first) to flip META002-005 from warnings
    to CI-blocking errors.

    Lifecycle: a missing ``policy:`` block (or a missing
    ``scaffoldStrict`` key inside it) is treated as ``False`` --
    META002-005 surface as warnings, never block CI. Explicit
    ``true`` is the only way to upgrade to strict mode.
    """

    model_config = ConfigDict(extra="forbid")

    scaffoldStrict: bool | None = None


class AlertsConfig(BaseModel):
    """Alert ledger sync configuration.

    Controls the ``contentops alerts sync`` command and the daily
    alerts-report workflow. When absent from ``tenant.yml``, alert
    sync is disabled (opt-in). When present with ``enabled: false``,
    alert sync is explicitly disabled.
    """

    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    defenderLookbackDays: int = Field(default=30, ge=1, le=365)
    sentinelLookbackDays: int = Field(default=90, ge=1, le=365)
    ledgerRetentionDays: int = Field(default=90, ge=7, le=365)
    rollupRetentionDays: int = Field(default=365, ge=30, le=730)
    armOverlayDays: int = Field(default=30, ge=0, le=90)
    reexportDays: int = Field(default=30, ge=0, le=90)
    reconcile: bool = True


class ReportsConfig(BaseModel):
    """Committed-report history retention.

    The detection inventory report (``contentops report`` / the
    ``report.yml`` workflow) writes a rolling ``reports/latest.*`` plus
    dated snapshots ``reports/<YYYY-MM-DD>.{html,json}`` so adopters can
    diff week-over-week. ``reports/`` is normal versioned content (NOT
    gitignored), so on push-to-main ``report.yml`` commits it — a deployment
    gets a durable, diffable posture history out of the box. The dated
    snapshots then accumulate one per run.

    ``retentionDays`` caps that history: on each ``contentops report`` run,
    dated snapshots older than the window are pruned. Default ``365`` (≈ 52
    weekly snapshots). Set to ``0`` to disable pruning and keep everything.

    The whole block is optional — a missing ``reports:`` block means "no
    pruning" (keep every dated snapshot). (Per-detection telemetry is kept
    off the PUBLIC mirror by the sync allowlist, not by gitignore — see
    docs/operations/durable-reports.md.)
    """

    model_config = ConfigDict(extra="forbid")

    retentionDays: int = Field(default=365, ge=0, le=3650)


class TenantConfig(BaseModel):
    """One Entra ID tenant, with 0–1 Defender XDR, 0–N Sentinel workspaces,
    and an optional policy block."""

    model_config = ConfigDict(extra="forbid")

    name: str
    tenantId: str
    defender: DefenderConfig | None = None
    sentinelWorkspaces: list[SentinelWorkspaceConfig] = []
    policy: TenantPolicy | None = None
    alerts: AlertsConfig | None = None
    reports: ReportsConfig | None = None

    def is_scaffold_strict(self) -> bool:
        """Resolve the effective scaffold-strict policy for the lint runner.

        Lenient-by-default: a missing ``policy:`` block, or a present
        block with ``scaffoldStrict`` unset (None), returns False.
        Only an explicit ``scaffoldStrict: true`` upgrades the rules to
        errors. Centralised so callers (lint runner, future
        promotion gates, dashboards) don't reinvent the None-vs-False
        branching.
        """
        if self.policy is None:
            return False
        if self.policy.scaffoldStrict is None:
            return False
        return self.policy.scaffoldStrict

    def is_alerts_enabled(self) -> bool:
        """Whether alert sync is enabled for this tenant.

        Opt-in: a missing ``alerts:`` block returns False. A present
        block with ``enabled: false`` also returns False. Only an
        explicit ``alerts: { enabled: true }`` enables alert sync.
        """
        if self.alerts is None:
            return False
        return self.alerts.enabled

    @model_validator(mode="after")
    def _validate_workspace_uniqueness(self) -> "TenantConfig":
        # Case-insensitive duplicate detection: ``workspace_by_name``
        # below matches with ``casefold()``, so two entries that differ
        # only by case would silently shadow one another at lookup
        # time. Reject at config-load time with a clear message.
        # ``casefold()`` is the Unicode-aware variant of ``lower()`` —
        # safe for ASCII workspace names and correct for any future
        # tenants that use non-ASCII identifiers.
        folded_names = [w.workspaceName.casefold() for w in self.sentinelWorkspaces]
        if len(folded_names) != len(set(folded_names)):
            dupes = sorted({
                w.workspaceName for w in self.sentinelWorkspaces
                if folded_names.count(w.workspaceName.casefold()) > 1
            })
            raise ValueError(
                f"Duplicate workspaceName in sentinelWorkspaces "
                f"(case-insensitive): {dupes}. "
                "Each workspaceName must be unique within a tenant file; "
                "names that differ only by case are not allowed because "
                "workspace lookup is case-insensitive."
            )
        triplets = [
            (w.subscriptionId, w.resourceGroup, w.workspaceName)
            for w in self.sentinelWorkspaces
        ]
        if len(triplets) != len(set(triplets)):
            raise ValueError(
                "Duplicate (subscriptionId, resourceGroup, workspaceName) "
                "in sentinelWorkspaces — Azure does not allow this triplet "
                "to repeat within a tenant."
            )
        primaries = [w for w in self.sentinelWorkspaces if w.primary]
        if len(primaries) > 1:
            names = [w.workspaceName for w in primaries]
            raise ValueError(
                f"At most one workspace can be primary, got: {names}"
            )
        return self

    # --- Selection helpers ---------------------------------------------

    def workspaces_for_role(self, role: WorkspaceRole) -> list[SentinelWorkspaceConfig]:
        """Return every workspace with the given ``role``. May be empty."""
        return [w for w in self.sentinelWorkspaces if w.role == role]

    # --- Safeguard lookups --------------------------------------------

    def safeguards_for_workspace(
        self, workspace_name: str,
    ) -> WorkspaceSafeguards:
        """Return the per-workspace safeguard triple for a Sentinel workspace.

        Wraps :meth:`workspace_by_name` so prune / apply paths can ask
        "is this workspace allowed to be written / purged?" without
        threading the full workspace config through. Inherits the
        case-insensitive matching + clear-error behaviour from
        :meth:`workspace_by_name`.
        """
        return self.workspace_by_name(workspace_name)

    def defender_safeguards(self) -> WorkspaceSafeguards:
        """Return the Defender-XDR safeguard triple.

        Falls back to the locked-down defaults (``writeAllowed=True``,
        ``purgeAllowed=False``, ``maxDelete=25`` per
        :class:`WorkspaceSafeguards`) when no ``defender:`` block is
        present in the tenant config — the Defender handler treats a
        missing block as "tenant has no Defender XDR," and the
        safeguard lookup must not crash in that branch.
        """
        if self.defender is None:
            return WorkspaceSafeguards()
        return self.defender

    def workspace_by_name(self, name: str) -> SentinelWorkspaceConfig:
        """Return the workspace whose ``workspaceName`` matches.

        Comparison is **case-insensitive** via ``casefold()`` so
        operators typing ``SIT-Workspace`` resolve a config entry
        named ``sit-workspace``. Ambiguity is prevented at
        config-load time by ``_validate_workspace_uniqueness``,
        which rejects entries whose names differ only by case.

        Raises :class:`KeyError` with the available names listed when
        no match is found — easier to fix typos than a bare KeyError.
        """
        needle = name.casefold()
        for w in self.sentinelWorkspaces:
            if w.workspaceName.casefold() == needle:
                return w
        available = ", ".join(w.workspaceName for w in self.sentinelWorkspaces)
        raise KeyError(
            f"No Sentinel workspace named {name!r} in tenant {self.name!r}. "
            f"Available: [{available}]"
        )


CONFIG_DIR = Path(__file__).resolve().parent.parent / "config"
CONFIG_PATH = CONFIG_DIR / "tenant.yml"


def is_operator_source_repo(repo_root: Path | None = None) -> bool:
    """True only in the private operator source-of-truth repo.

    Source-repo *maintenance* gates — the catalog drift gate, the
    detection-docs drift gate, and the internal doc-link checker — need
    the full operator file set to pass. The public mirror
    (``SecM8/ContentOps``) and any adopter clone deliberately strip
    operator-only files (``docs/detections/``, ``config/lifecycle.yml``,
    etc.), so those gates cannot — and should not — run there: cloning
    the mirror must give a green suite out of the box.

    ``.github/workflows/public-sync.yml`` is the workflow that performs
    the mirror sync; it exists ONLY in the source repo (it is stripped
    from the mirror, and is already ``catalog/inspect.py``'s lone
    excluded workflow). Its presence is therefore a stable "am I the
    source of truth" sentinel.
    """
    root = repo_root if repo_root is not None else CONFIG_DIR.parent
    return (root / ".github" / "workflows" / "public-sync.yml").is_file()


def resolve_config_path(env: str | None = None) -> Path:
    """Return the tenant.yml path that load_tenant_config() would read.

    Honours an explicit ``env`` argument, then ``PIPELINE_ENV``, and
    falls back to the default ``config/tenant.yml``. Does not check
    that the file exists — callers handle ``FileNotFoundError``.
    """
    import re as _re
    chosen = env or os.getenv("PIPELINE_ENV") or None
    if chosen:
        if not _re.fullmatch(r"[a-zA-Z0-9_-]{1,64}", chosen):
            raise ValueError(
                f"PIPELINE_ENV value {chosen!r} contains path-unsafe characters. "
                "Expected a simple slug like 'prod', 'integration', or 'dev'."
            )
        return CONFIG_DIR / f"tenant.{chosen}.yml"
    return CONFIG_PATH


def load_tenant_config(
    path: Path | None = None,
    *,
    env: str | None = None,
) -> TenantConfig:
    """Load and validate the tenant configuration file."""
    config_path = path or resolve_config_path(env)
    # Single-tenant.yml model: an env slug (``--env`` / ``PIPELINE_ENV``)
    # selects ``config/tenant.<env>.yml``, but operators who keep ONE
    # ``tenant.yml`` with role-tagged workspaces have no per-env file.
    # Fall back to the base ``config/tenant.yml`` (workspaces are still
    # selected by ``--role``) instead of failing. Only triggers when the
    # caller passed no explicit ``path``, the env-specific file is absent,
    # and the base file exists — so setups that DO ship per-env files are
    # unaffected. Closes the prune / rollback "tenant.<env>.yml not found"
    # failures (and the prune blind-spot) on single-file tenants.
    if (
        path is None
        and config_path != CONFIG_PATH
        and not config_path.exists()
        and CONFIG_PATH.is_file()
    ):
        log.info(
            "tenant config %s not found; using %s (single-file model — "
            "workspaces resolved by role).",
            config_path.name, CONFIG_PATH.name,
        )
        config_path = CONFIG_PATH
    try:
        raw_text = config_path.read_text()
    except FileNotFoundError as exc:
        example = config_path.with_name(config_path.stem + ".yml.example") \
            if config_path.suffix == ".yml" else CONFIG_DIR / "tenant.yml.example"
        raise FileNotFoundError(
            f"Tenant config not found at {config_path}.\n"
            f"  Copy the template and fill in your tenant + workspace values:\n"
            f"    cp {example} {config_path}\n"
            f"  In CI, the workflow materialises this file from the\n"
            f"  TENANT_CONFIG_YAML GitHub Actions secret — see\n"
            f"  .github/actions/pipeline-setup/action.yml."
        ) from exc
    raw = yaml.safe_load(raw_text)
    if not isinstance(raw, dict) or "tenant" not in raw:
        raise ValueError(
            f"{config_path}: expected a YAML mapping with a top-level 'tenant:' key. "
            "Check that TENANT_CONFIG_YAML contains the full tenant config, "
            "not a partial blob."
        )
    tenant_block = raw["tenant"]
    if "sentinel" in tenant_block and "sentinelWorkspaces" not in tenant_block:
        raise ValueError(
            f"{config_path}: legacy single-workspace schema detected "
            "(`sentinel:` block). Run `python scripts/migrate_tenant_config.py "
            f"{config_path}` to upgrade. See DESIGN §6 for the "
            "multi-workspace schema."
        )
    return TenantConfig(**tenant_block)


# --- CLI selection helper -------------------------------------------------


def select_primary_workspace(
    cfg: TenantConfig,
    role: str = "prod",
) -> SentinelWorkspaceConfig:
    """Return the primary workspace for a role, or the first if none marked.

    With Unified SOC, alerts flow only to the primary workspace. Reports
    and alert-sync commands use this to pick the right workspace when
    multiple share the same role.
    """
    candidates = cfg.workspaces_for_role(role)
    if not candidates:
        raise ValueError(f"No workspace with role={role!r}")
    primaries = [w for w in candidates if w.primary]
    if primaries:
        return primaries[0]
    if len(candidates) > 1:
        log.info(
            "No workspace marked primary for role %r — using %s. "
            "Set primary: true in tenant.yml to make this explicit.",
            role, candidates[0].workspaceName,
        )
    return candidates[0]


def select_workspaces(
    cfg: TenantConfig,
    *,
    role: str | None = None,
    workspace: str | None = None,
) -> list[SentinelWorkspaceConfig]:
    """Resolve CLI ``--role`` / ``--workspace`` selectors to a workspace list.

    Rules:
      * ``--workspace foo`` — the named workspace, or KeyError.
      * ``--role prod`` — every workspace with role=prod (may be empty).
      * Neither and exactly one Sentinel workspace exists — that one (implicit).
      * Neither and N>1 workspaces exist — :class:`ValueError` ("be explicit").
      * Neither and zero workspaces — empty list (Sentinel ops are no-ops).

    Mutually exclusive: passing both raises ValueError.
    """
    if role is not None and workspace is not None:
        raise ValueError("--role and --workspace are mutually exclusive")
    if workspace is not None:
        return [cfg.workspace_by_name(workspace)]
    if role is not None:
        return cfg.workspaces_for_role(role)
    if len(cfg.sentinelWorkspaces) == 1:
        return cfg.sentinelWorkspaces[:]
    if not cfg.sentinelWorkspaces:
        return []
    available = ", ".join(
        f"{w.workspaceName} ({w.role})" for w in cfg.sentinelWorkspaces
    )
    raise ValueError(
        f"Tenant has {len(cfg.sentinelWorkspaces)} Sentinel workspaces; "
        f"specify --role or --workspace. Available: [{available}]"
    )
