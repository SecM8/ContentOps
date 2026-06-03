# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Top-level pytest fixtures shared by every test module.

Currently scoped to one job: prevent handler-registry state leakage
between tests (Q6).

The default ``HandlerRegistry`` instance at
``contentops.core.registry.default_registry`` is a process-wide
singleton. CLI commands populate it via ``register_default_handlers()``
and cache constructed handler instances inside it; tests that mock
the registry (e.g. ``_register_only(Asset.SENTINEL_ANALYTIC, fake)``)
mutate the same global. Without a reset between tests, a fake
handler from one test stays registered for the next — surfacing as
flaky failures whose root cause is non-obvious (e.g. a test asserting
"no handler for X" passes in isolation and fails after some other
test runs first).

The autouse fixture below drops cached instances AND the factory
table before each test, so every test starts from a known-empty
registry.
"""

from __future__ import annotations

import os

import pytest

from contentops.core.registry import default_registry


_LEAKABLE_ENV_VARS = (
    # Workspace selector — set by ``_resolve_single_workspace_or_exit``
    # and the new Phase 2 ``--role`` / ``--workspace`` flags. A test that
    # exits between the env-var write and an assert will leak the value
    # into every subsequent test that constructs a Sentinel handler,
    # silently changing which workspace is targeted.
    "PIPELINE_WORKSPACE_NAME",
)


@pytest.fixture(autouse=True)
def _reset_default_registry_between_tests():
    """Clear ``default_registry`` AND process-global state before AND
    after each test.

    Uses the public :meth:`HandlerRegistry.reset_all` API, which
    closes constructed handlers AND drops factory registrations.
    Plain ``reset()`` would only clear cached instances — that's not
    enough, because ``register_default_handlers`` is idempotent and
    no-ops when a factory is already registered (so a fake factory
    set up by an earlier test would survive into the next one).

    Also unsets ``PIPELINE_WORKSPACE_NAME`` (and any other env var
    that the CLI sets during normal operation) so a test that calls
    ``--role`` / ``--workspace`` doesn't bleed the env var into the
    next test in the same worker.
    """
    for name in _LEAKABLE_ENV_VARS:
        os.environ.pop(name, None)
    default_registry.reset_all()
    yield
    for name in _LEAKABLE_ENV_VARS:
        os.environ.pop(name, None)
    default_registry.reset_all()
