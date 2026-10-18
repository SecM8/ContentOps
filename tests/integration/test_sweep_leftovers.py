# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Sweep-only entry point for the live suite.

Requesting the session clients runs their start-of-session sweeps
(``_sweep_defender`` / ``_sweep_sentinel`` in conftest), which delete
every resource whose name carries the ``zz-itest-`` / ``zz_itest_``
prefix. Graph can take a long time to converge a DELETE, so a normal
run may leave its own rule behind; ``integration.yml`` with
``sweep-only=true`` runs just this module (``-k sweep_leftover``) to
clean up without creating anything new.
"""

from __future__ import annotations

from tests.integration.conftest import RESOURCE_PREFIX_UNDERSCORE


def test_sweep_leftover_defender_rules(defender_client) -> None:
    """The session sweep has run; report what is still visible (Graph
    read-after-delete lag) without failing on it."""
    leftovers = [
        r.get("displayName") for r in defender_client.list_rules()
        if str(r.get("displayName", "")).startswith(RESOURCE_PREFIX_UNDERSCORE)
    ]
    print(f"zz_itest_ Defender rules still served after sweep: {leftovers or 'none'}")


def test_sweep_leftover_sentinel_rules(sentinel_client) -> None:
    """Skips with 'missing env' when no integration workspace is wired."""
    assert sentinel_client is not None
