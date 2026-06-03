# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for the T.3b ``TenantPolicy`` submodel and its
``is_scaffold_strict()`` resolver.

The policy block in tenant.yml is the single source of truth for the
"should the META rules block CI or just warn" decision. This file
pins the three-way resolution (missing block / present block with no
scaffoldStrict / explicit value) so the lint runner doesn't have to
re-invent the None-vs-False branching.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from contentops.config import TenantConfig, TenantPolicy


def _tenant(policy: TenantPolicy | None = None) -> TenantConfig:
    return TenantConfig(
        name="test",
        tenantId="00000000-0000-0000-0000-000000000000",
        policy=policy,
    )


def test_missing_policy_block_defaults_to_lenient() -> None:
    """Pre-T tenants and any tenant.yml without the new policy block
    must be treated as lenient -- lenient-by-default matches the
    G24 authoring-backlog reality. Operators opt INTO strict once
    the backlog is drained."""
    assert _tenant(policy=None).is_scaffold_strict() is False


def test_present_policy_without_scaffold_strict_is_lenient() -> None:
    """An operator who has only set OTHER (future) policy fields and
    omitted scaffoldStrict still gets lenient -- same default."""
    assert _tenant(policy=TenantPolicy()).is_scaffold_strict() is False


def test_explicit_true_is_strict() -> None:
    """The only path to CI-blocking META rules: an explicit ``true``
    in the YAML. Anything else is lenient."""
    assert _tenant(policy=TenantPolicy(scaffoldStrict=True)).is_scaffold_strict() is True


def test_explicit_false_is_lenient() -> None:
    assert _tenant(policy=TenantPolicy(scaffoldStrict=False)).is_scaffold_strict() is False


def test_policy_block_rejects_unknown_keys() -> None:
    """``extra='forbid'`` on TenantPolicy must catch typos in field
    names — a misspelled ``scafoldStrict`` shouldn't silently get
    dropped and leave the tenant in strict mode without anyone
    noticing."""
    with pytest.raises(ValidationError):
        TenantPolicy(scafoldStrict=False)  # type: ignore[call-arg]


def test_policy_block_yaml_round_trip() -> None:
    """A YAML-style raw dict with the policy block must construct the
    full tenant config cleanly. The lint runner reads tenant.yml via
    load_tenant_config which goes through this path."""
    raw_tenant = {
        "name": "test",
        "tenantId": "00000000-0000-0000-0000-000000000000",
        "policy": {"scaffoldStrict": False},
    }
    cfg = TenantConfig(**raw_tenant)
    assert cfg.policy is not None
    assert cfg.policy.scaffoldStrict is False
    assert cfg.is_scaffold_strict() is False
