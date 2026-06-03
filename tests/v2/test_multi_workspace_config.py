# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for the v3 multi-workspace tenant schema (DESIGN §6)."""

from __future__ import annotations

from pathlib import Path
from textwrap import dedent

import pytest
import yaml

from contentops.config import (
    DefenderConfig,
    SentinelWorkspaceConfig,
    TenantConfig,
    load_tenant_config,
    select_workspaces,
)


def _ws(name: str, *, role: str = "prod", sub: str | None = None) -> SentinelWorkspaceConfig:
    return SentinelWorkspaceConfig(
        role=role,
        subscriptionId=sub or f"sub-{name}",
        resourceGroup=f"rg-{name}",
        workspaceName=name,
    )


# ---------------------------------------------------------------------------
# Schema validation
# ---------------------------------------------------------------------------


def test_workspace_role_defaults_to_prod() -> None:
    """Direct construction without role gets prod (test-friendly default)."""
    ws = SentinelWorkspaceConfig(
        subscriptionId="s", resourceGroup="r", workspaceName="w",
    )
    assert ws.role == "prod"


def test_workspace_role_must_be_known_value() -> None:
    with pytest.raises(Exception):
        SentinelWorkspaceConfig(
            role="staging-but-not-an-alias",  # type: ignore[arg-type]
            subscriptionId="s", resourceGroup="r", workspaceName="w",
        )


def test_tenant_accepts_zero_sentinel_workspaces() -> None:
    """A Defender-only tenant is valid."""
    cfg = TenantConfig(
        name="t", tenantId="aad-guid",
        defender=DefenderConfig(enabled=True),
    )
    assert cfg.sentinelWorkspaces == []


def test_tenant_accepts_no_defender() -> None:
    """A Sentinel-only tenant is valid."""
    cfg = TenantConfig(
        name="t", tenantId="aad-guid",
        sentinelWorkspaces=[_ws("law")],
    )
    assert cfg.defender is None


def test_tenant_rejects_duplicate_workspace_names() -> None:
    with pytest.raises(Exception, match="Duplicate workspaceName"):
        TenantConfig(
            name="t", tenantId="aad-guid",
            sentinelWorkspaces=[_ws("law"), _ws("law", role="integration")],
        )


def test_tenant_rejects_duplicate_triplet() -> None:
    """Same (sub, rg, name) triplet repeated is rejected.

    Workspace names already need to be unique, so to hit this branch we
    have to use different names but the same (sub, rg, name) triplet —
    which is a contradiction. We construct it with the same name in
    flight and verify the validator path explicitly via Pydantic
    skipping the per-name check (different role, same triplet keys
    impossible without name match). This test documents intent.
    """
    # The triplet check is dominated by the name check; both fire here.
    with pytest.raises(Exception):
        TenantConfig(
            name="t", tenantId="aad-guid",
            sentinelWorkspaces=[
                _ws("law"),
                SentinelWorkspaceConfig(
                    role="integration",
                    subscriptionId="sub-law",
                    resourceGroup="rg-law",
                    workspaceName="law",
                ),
            ],
        )


# ---------------------------------------------------------------------------
# select_workspaces
# ---------------------------------------------------------------------------


def _tenant(*workspaces: SentinelWorkspaceConfig) -> TenantConfig:
    return TenantConfig(
        name="t", tenantId="aad-guid",
        sentinelWorkspaces=list(workspaces),
    )


def test_select_implicit_single_workspace() -> None:
    cfg = _tenant(_ws("law"))
    assert select_workspaces(cfg) == cfg.sentinelWorkspaces


def test_select_zero_workspaces_returns_empty() -> None:
    cfg = TenantConfig(name="t", tenantId="aad-guid")
    assert select_workspaces(cfg) == []


def test_select_role_returns_matching_workspaces() -> None:
    cfg = _tenant(
        _ws("prod-a"), _ws("prod-b"),
        _ws("int", role="integration"),
    )
    selected = select_workspaces(cfg, role="prod")
    assert {w.workspaceName for w in selected} == {"prod-a", "prod-b"}


def test_select_role_returns_empty_when_no_match() -> None:
    cfg = _tenant(_ws("prod-a"))
    assert select_workspaces(cfg, role="dev") == []


def test_select_workspace_by_name() -> None:
    cfg = _tenant(_ws("a"), _ws("b", role="integration"))
    selected = select_workspaces(cfg, workspace="b")
    assert [w.workspaceName for w in selected] == ["b"]


def test_select_workspace_unknown_name_raises() -> None:
    cfg = _tenant(_ws("a"))
    with pytest.raises(KeyError, match="No Sentinel workspace named"):
        select_workspaces(cfg, workspace="missing")


def test_select_role_and_workspace_mutually_exclusive() -> None:
    cfg = _tenant(_ws("a"))
    with pytest.raises(ValueError, match="mutually exclusive"):
        select_workspaces(cfg, role="prod", workspace="a")


def test_select_multiple_workspaces_no_selector_raises() -> None:
    cfg = _tenant(_ws("a"), _ws("b", role="integration"))
    with pytest.raises(ValueError, match="specify --role or --workspace"):
        select_workspaces(cfg)


# ---------------------------------------------------------------------------
# Loader: legacy schema rejected with a pointer to the migrator
# ---------------------------------------------------------------------------


def test_loader_rejects_legacy_sentinel_block(tmp_path: Path) -> None:
    legacy = tmp_path / "tenant.yml"
    legacy.write_text(dedent("""
        tenant:
          name: legacy
          tenantId: aad
          sentinel:
            subscriptionId: s
            resourceGroup: r
            workspaceName: w
            location: westeurope
          defender:
            enabled: true
    """).lstrip())
    with pytest.raises(ValueError, match="legacy single-workspace schema"):
        load_tenant_config(path=legacy)


def test_loader_accepts_v3_schema(tmp_path: Path) -> None:
    p = tmp_path / "tenant.yml"
    p.write_text(yaml.safe_dump({"tenant": {
        "name": "prod",
        "tenantId": "aad",
        "defender": {"enabled": True},
        "sentinelWorkspaces": [
            {"role": "prod", "subscriptionId": "s",
             "resourceGroup": "r", "workspaceName": "w"},
        ],
    }}))
    cfg = load_tenant_config(path=p)
    assert len(cfg.sentinelWorkspaces) == 1
    assert cfg.sentinelWorkspaces[0].role == "prod"


# ---------------------------------------------------------------------------
# Case-insensitive workspace name selection
# ---------------------------------------------------------------------------


def test_workspace_by_name_exact_case_still_works() -> None:
    """The pre-casefold contract: exact-case lookup keeps resolving."""
    cfg = _tenant(_ws("sit-workspace", role="integration"))
    found = cfg.workspace_by_name("sit-workspace")
    assert found.workspaceName == "sit-workspace"


def test_workspace_by_name_is_case_insensitive() -> None:
    """Operators routinely type workspace names with inconsistent
    casing in env files; lookup normalises via ``casefold()``."""
    cfg = _tenant(_ws("sit-workspace", role="integration"))
    found = cfg.workspace_by_name("SIT-Workspace")
    assert found.workspaceName == "sit-workspace"


def test_select_workspace_by_name_is_case_insensitive() -> None:
    """The CLI's ``--workspace`` selector flows through
    ``select_workspaces`` → ``workspace_by_name``; same normalisation
    applies."""
    cfg = _tenant(_ws("sit-workspace", role="integration"))
    selected = select_workspaces(cfg, workspace="SIT-Workspace")
    assert [w.workspaceName for w in selected] == ["sit-workspace"]


def test_workspace_by_name_unknown_still_raises_keyerror() -> None:
    """Typo-style misses still surface as ``KeyError`` with the
    available names listed (the error message contract is unchanged
    by the casefold normalisation)."""
    cfg = _tenant(_ws("sit-workspace", role="integration"))
    with pytest.raises(KeyError, match="No Sentinel workspace named"):
        cfg.workspace_by_name("nope-not-here")


def test_tenant_rejects_workspace_names_that_differ_only_by_case() -> None:
    """If lookup is case-insensitive, two configured entries that
    differ only by case would silently shadow one another. The
    validator must reject them at config-load time."""
    with pytest.raises(Exception, match="Duplicate workspaceName"):
        TenantConfig(
            name="t", tenantId="aad-guid",
            sentinelWorkspaces=[
                _ws("sit-workspace"),
                _ws("SIT-Workspace", role="integration"),
            ],
        )


def test_tenant_still_rejects_exact_duplicate_workspace_names() -> None:
    """The casefold-based check is a strict superset of exact-match
    duplicate detection; exact duplicates remain rejected with a
    clear error."""
    with pytest.raises(Exception, match="Duplicate workspaceName"):
        TenantConfig(
            name="t", tenantId="aad-guid",
            sentinelWorkspaces=[
                _ws("sit-workspace"),
                # Same casefolded name; legal SentinelWorkspaceConfig in
                # isolation because the uniqueness check is at the
                # TenantConfig level.
                SentinelWorkspaceConfig(
                    role="integration",
                    subscriptionId="sub-other",
                    resourceGroup="rg-other",
                    workspaceName="sit-workspace",
                ),
            ],
        )


# ---------------------------------------------------------------------------
# Workspace safeguards — writeAllowed / purgeAllowed / maxDelete
# ---------------------------------------------------------------------------


def test_workspace_safeguard_defaults() -> None:
    """A workspace declared without safeguard fields gets the locked-down
    triple: writeAllowed=True (lenient default — pipeline works out of
    the box for adopters), purgeAllowed=False (irreversible op needs
    explicit opt-in), maxDelete=25 (matches the existing workflow cap)."""
    ws = SentinelWorkspaceConfig(
        subscriptionId="s", resourceGroup="r", workspaceName="w",
    )
    assert ws.writeAllowed is True
    assert ws.purgeAllowed is False
    assert ws.maxDelete == 25


def test_workspace_safeguard_max_delete_range() -> None:
    """maxDelete is clamped to [0, 9999]. Outside that range fails at
    schema validation — surfaces typos like 5000000 as a config error
    instead of a wide-open prune cap."""
    # Lower edge
    SentinelWorkspaceConfig(
        subscriptionId="s", resourceGroup="r", workspaceName="w",
        maxDelete=0,
    )
    SentinelWorkspaceConfig(
        subscriptionId="s", resourceGroup="r", workspaceName="w",
        maxDelete=9999,
    )
    # Outside range
    with pytest.raises(Exception):
        SentinelWorkspaceConfig(
            subscriptionId="s", resourceGroup="r", workspaceName="w",
            maxDelete=-1,
        )
    with pytest.raises(Exception):
        SentinelWorkspaceConfig(
            subscriptionId="s", resourceGroup="r", workspaceName="w",
            maxDelete=10000,
        )


def test_defender_safeguards_inherit() -> None:
    """DefenderConfig carries the same three safeguard fields as
    SentinelWorkspaceConfig. Tenant-level scope (one Defender XDR per
    tenant) so the gate is single, not per-workspace."""
    d = DefenderConfig()
    assert d.writeAllowed is True
    assert d.purgeAllowed is False
    assert d.maxDelete == 25
    assert d.enabled is True

    d2 = DefenderConfig(purgeAllowed=True, maxDelete=500)
    assert d2.purgeAllowed is True
    assert d2.maxDelete == 500


def test_defender_safeguards_helper_returns_default_for_missing_block() -> None:
    """A tenant with no `defender:` block returns the locked-down
    defaults from .defender_safeguards() rather than raising. Lets
    safeguard-aware code branch on "is purge allowed?" without
    threading a None check through every caller."""
    cfg = TenantConfig(
        name="t", tenantId="aad-guid",
        sentinelWorkspaces=[_ws("w1")],
        defender=None,
    )
    sg = cfg.defender_safeguards()
    assert sg.purgeAllowed is False
    assert sg.writeAllowed is True
    assert sg.maxDelete == 25


def test_safeguards_for_workspace_returns_the_workspace() -> None:
    """The helper returns the workspace itself (which inherits from
    WorkspaceSafeguards). Lookup is case-insensitive — same contract
    as workspace_by_name."""
    cfg = TenantConfig(
        name="t", tenantId="aad-guid",
        sentinelWorkspaces=[
            SentinelWorkspaceConfig(
                role="prod",
                subscriptionId="s", resourceGroup="r",
                workspaceName="law-sentinel",
                purgeAllowed=True, maxDelete=500,
            ),
        ],
    )
    sg = cfg.safeguards_for_workspace("LAW-SENTINEL")
    assert sg.purgeAllowed is True
    assert sg.maxDelete == 500


def test_yaml_load_with_safeguard_fields(tmp_path: Path) -> None:
    """YAML load surfaces the three fields end-to-end. Pin against
    silent regressions to the field names — anything renamed here
    needs lockstep updates in .github/workflows/prune.yml's secret
    docs and the operator runbook."""
    p = tmp_path / "tenant.yml"
    p.write_text(dedent("""
        tenant:
          name: my-tenant
          tenantId: aad-guid
          defender:
            enabled: true
            writeAllowed: true
            purgeAllowed: false
            maxDelete: 0
          sentinelWorkspaces:
            - role: prod
              subscriptionId: sub-1
              resourceGroup: rg-1
              workspaceName: law-prod
              writeAllowed: true
              purgeAllowed: false
              maxDelete: 0
            - role: integration
              subscriptionId: sub-1
              resourceGroup: rg-1
              workspaceName: law-int
              writeAllowed: true
              purgeAllowed: true
              maxDelete: 500
    """).lstrip(), encoding="utf-8")
    cfg = load_tenant_config(p)
    prod = cfg.workspace_by_name("law-prod")
    integ = cfg.workspace_by_name("law-int")
    assert prod.purgeAllowed is False
    assert prod.maxDelete == 0
    assert integ.purgeAllowed is True
    assert integ.maxDelete == 500
    assert cfg.defender is not None
    assert cfg.defender.purgeAllowed is False
