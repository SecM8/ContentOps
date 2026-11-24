# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Sweep-only entry point for the live suite.

Deletes every Defender rule whose display name starts with ``zz_itest_``
and every Sentinel rule and saved search (parser, hunting query) whose
name starts with ``zz-itest-``, and creates nothing. Graph can keep serving a deleted rule for minutes, so a normal
run may leave its own rule behind; ``integration.yml`` with
``sweep-only=true`` runs just this module (``-k sweep_leftover``) to
clean up.

Only a count is printed, never a rule name.
"""

from __future__ import annotations

import time

from tests.integration.conftest import (
    RESOURCE_PREFIX_HYPHEN,
    RESOURCE_PREFIX_UNDERSCORE,
    _sweep_defender,
    _sweep_sentinel,
    _test_saved_searches,
)
from tests.integration.defender_shape_probe import require_confirmation

# Kinds this module writes; the kind kill switch skips it when one is switched off
# (tests/integration/kill_switch.py). None: a sweep only deletes the suite's own
# zz-itest- / zz_itest_ leftovers, and must run when a kind is switched off too
# (a probe run with ignore-kill-switch leaves Defender test rules behind).
LIVE_KINDS = {
    "test_sweep_leftover_defender_rules": (),
    "test_sweep_leftover_sentinel_rules": (),
    "test_sweep_leftover_saved_searches": (),
}

_TIMEOUT_S = 180
_POLL_S = 10


def _leftover_count(client) -> int:
    return sum(
        1 for rule in client.list_rules()
        if str(rule.get("displayName", "")).startswith(RESOURCE_PREFIX_UNDERSCORE)
    )


def test_sweep_leftover_defender_rules(confirmed_defender_client) -> None:
    """Defender is tenant-wide, so even a sweep writes to the production
    tenant: it runs only after the operator confirmed that."""
    require_confirmation()
    client = confirmed_defender_client
    deadline = time.monotonic() + _TIMEOUT_S
    _sweep_defender(client)
    count = _leftover_count(client)
    while count and time.monotonic() < deadline:
        time.sleep(_POLL_S)
        _sweep_defender(client)
        count = _leftover_count(client)
    print(f"zz_itest_ Defender rules still listed after the sweep: {count}")
    clean = count == 0
    assert clean, "test rules are still listed after the sweep; run it again in a few minutes"


def _sentinel_leftover_count(client) -> int:
    # Not through _sweep_sentinel's listing: an error here must fail the
    # test, not read as "nothing left".
    return sum(
        1 for rule in client.list_resource("alertRules")
        if str(rule.get("name", "")).startswith(RESOURCE_PREFIX_HYPHEN)
    )


def test_sweep_leftover_sentinel_rules(sentinel_client) -> None:
    """Deletes ``zz-itest-`` analytic rules and checks none is listed after.

    It only asserted that the fixture existed, so ``sweep-only`` reported
    success whatever the workspace still held. Skips with 'missing env'
    when no integration workspace is wired."""
    deadline = time.monotonic() + _TIMEOUT_S
    _sweep_sentinel(sentinel_client)
    count = _sentinel_leftover_count(sentinel_client)
    while count and time.monotonic() < deadline:
        time.sleep(_POLL_S)
        _sweep_sentinel(sentinel_client)
        count = _sentinel_leftover_count(sentinel_client)
    print(f"zz-itest- Sentinel rules still listed after the sweep: {count}")
    clean = count == 0
    assert clean, "test rules are still listed after the sweep; run it again in a few minutes"


def test_sweep_leftover_saved_searches(sentinel_client) -> None:
    """Deletes ``zz-itest-`` saved searches (parsers, hunting queries) a
    failed live test left in the workspace, and checks none is listed
    after. A listing error fails the test."""
    deadline = time.monotonic() + _TIMEOUT_S
    _sweep_sentinel(sentinel_client)
    count = len(_test_saved_searches(sentinel_client))
    while count and time.monotonic() < deadline:
        time.sleep(_POLL_S)
        _sweep_sentinel(sentinel_client)
        count = len(_test_saved_searches(sentinel_client))
    print(f"zz-itest- saved searches still listed after the sweep: {count}")
    clean = count == 0
    assert clean, "test saved searches are still listed after the sweep; run it again in a few minutes"
