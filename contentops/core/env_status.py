# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Env-aware status gating for ``apply``.

DESIGN §6 specifies that each environment only accepts a subset of
detection statuses:

  * dev / sandbox → ``experimental`` + ``test`` + ``production`` + ``deprecated``
  * test / integration → ``test`` + ``production`` + ``deprecated``
  * prod / production → ``production`` + ``deprecated``

Without this gate, an envelope with ``status: test`` merged to ``main``
deploys straight into the production tenant — which is precisely the
contradiction the design doc forbids. This module returns the allowed
status set for the active env name (from ``TenantConfig.name``); the
``apply`` command filters the load set through it before dispatching to
handlers.

``deprecated`` is allowed in every env so the handler can plan
``PlanAction.DISABLE`` and push the ``enabled: false`` flag to the
tenant. Previously deprecated rules were silently dropped by this
gate before reaching the handler — which meant a rule moved to
``status: deprecated`` in YAML quietly stayed enabled in prod
forever. The handler's deprecate path (set enabled=false) is the
authoritative way to turn a rule off; the explicit ``pipeline
prune`` workflow then removes it when fully retired.
"""

from __future__ import annotations

from contentops.models import Status

_PROD_ALIASES = frozenset({"prod", "production"})
# `role: test` is a DEDICATED test workspace (closes G21). Distinct
# from `role: integration` (a shared lower env): a dedicated test
# workspace accepts ONLY rules under test, never the production
# corpus, so cross-contamination of a test workload with live prod
# rules cannot happen. `integration` keeps the historical
# accepts-both behaviour for shared lower envs.
_DEDICATED_TEST_ALIASES = frozenset({"test"})
_INTEGRATION_ALIASES = frozenset({"integration", "staging", "stage"})
_DEV_ALIASES = frozenset({"dev", "development", "sandbox", "local"})


def allowed_statuses_for_env(env_name: str | None) -> frozenset[Status]:
    """Return the set of envelope statuses ``apply`` may deploy in env_name.

    An unknown env name is treated as production (fail-closed): better to
    refuse to deploy a non-production rule than to silently push it into
    a tenant whose role we cannot identify. ``DEPRECATED`` is included
    everywhere so the handler can disable the rule (the deprecate
    workflow is itself a deploy action -- the rule's ``enabled`` flag
    needs to reach the tenant).

    Four buckets:

      * dev / development / sandbox / local: all four statuses
        (experimental, test, production, deprecated).
      * test (dedicated): ONLY test + deprecated. Production envelopes
        do NOT spill into a dedicated test workspace (closes G21).
      * integration / staging / stage (shared lower env): test +
        production + deprecated.
      * prod / production (and unknown): production + deprecated.
    """
    key = (env_name or "").strip().lower()
    if key in _DEV_ALIASES:
        return frozenset({
            Status.EXPERIMENTAL, Status.TEST, Status.PRODUCTION, Status.DEPRECATED,
        })
    if key in _DEDICATED_TEST_ALIASES:
        return frozenset({Status.TEST, Status.DEPRECATED})
    if key in _INTEGRATION_ALIASES:
        return frozenset({Status.TEST, Status.PRODUCTION, Status.DEPRECATED})
    return frozenset({Status.PRODUCTION, Status.DEPRECATED})


# Backward-compat: keep the old aggregate frozenset name in case any
# external caller pinned to it. `dedicated test` and `integration-like`
# combined matches the historical TEST + integration behaviour.
_TEST_ALIASES = _DEDICATED_TEST_ALIASES | _INTEGRATION_ALIASES
