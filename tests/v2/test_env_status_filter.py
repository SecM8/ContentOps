# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for env-aware status gating (DESIGN §6)."""

from __future__ import annotations

from contentops.core.env_status import allowed_statuses_for_env
from contentops.models import Status


def test_prod_allows_production_and_deprecated() -> None:
    for name in ("prod", "production", "PROD", "Production"):
        assert allowed_statuses_for_env(name) == frozenset(
            {Status.PRODUCTION, Status.DEPRECATED}
        )


def test_dedicated_test_workspace_only_accepts_test_and_deprecated() -> None:
    """Closes G21. `role: test` is a DEDICATED test workspace --
    production envelopes do NOT spill into it. Operators who want a
    shared lower env (test + prod coexist) use `role: integration`."""
    assert allowed_statuses_for_env("test") == frozenset(
        {Status.TEST, Status.DEPRECATED}
    )
    # Case-insensitive matching.
    assert allowed_statuses_for_env("TEST") == frozenset(
        {Status.TEST, Status.DEPRECATED}
    )


def test_integration_envs_allow_test_production_and_deprecated() -> None:
    """`role: integration` / staging / stage are SHARED lower envs
    that accept both TEST and PRODUCTION envelopes (and deprecated).
    Distinct from `role: test` which is dedicated and prod-exclusive."""
    for name in ("integration", "staging", "stage"):
        assert allowed_statuses_for_env(name) == frozenset(
            {Status.TEST, Status.PRODUCTION, Status.DEPRECATED}
        )


def test_dev_allows_experimental_test_production_and_deprecated() -> None:
    for name in ("dev", "development", "sandbox", "local"):
        assert allowed_statuses_for_env(name) == frozenset(
            {Status.EXPERIMENTAL, Status.TEST, Status.PRODUCTION, Status.DEPRECATED}
        )


def test_unknown_env_fails_closed_to_production_plus_deprecated() -> None:
    # Fail-closed: unknown env name → only `production` is deployable
    # (plus `deprecated` so the handler can disable a rule). We must
    # never silently push a `test` rule into a tenant whose role we
    # cannot identify.
    assert allowed_statuses_for_env("mystery") == frozenset(
        {Status.PRODUCTION, Status.DEPRECATED}
    )
    assert allowed_statuses_for_env(None) == frozenset(
        {Status.PRODUCTION, Status.DEPRECATED}
    )
    assert allowed_statuses_for_env("") == frozenset(
        {Status.PRODUCTION, Status.DEPRECATED}
    )


def test_deprecated_allowed_in_every_env() -> None:
    # Deprecated must reach the handler so it can push enabled=false
    # to the tenant. Previously this gate dropped deprecated rules
    # silently, leaving them enabled in prod forever (R2).
    for name in ("dev", "test", "prod", "anything"):
        assert Status.DEPRECATED in allowed_statuses_for_env(name)
