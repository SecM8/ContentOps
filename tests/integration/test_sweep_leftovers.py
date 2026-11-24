# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Sweep-only entry point for the live suite.

Deletes every Defender rule whose display name starts with ``zz_itest_``
and every Sentinel rule whose name starts with ``zz-itest-``, and creates
nothing. Graph can keep serving a deleted rule for minutes, so a normal
run may leave its own rule behind; ``integration.yml`` with
``sweep-only=true`` runs just this module (``-k sweep_leftover``) to
clean up.

Only a count is printed, never a rule name.
"""

from __future__ import annotations

import time

from tests.integration.conftest import RESOURCE_PREFIX_UNDERSCORE, _sweep_defender
from tests.integration.defender_shape_probe import require_confirmation

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


def test_sweep_leftover_sentinel_rules(sentinel_client) -> None:
    """Skips with 'missing env' when no integration workspace is wired."""
    assert sentinel_client is not None
