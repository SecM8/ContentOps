# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Autouse isolation for the v2 unit suite.

Makes the unit tests behave like a clean CI checkout regardless of the
developer's machine. Two operator-local, gitignored inputs would
otherwise leak into tests that invoke the CLI without supplying their
own config:

* ``config/tenant.yml`` — gitignored (CLAUDE.md invariant 3) and absent
  in CI, but present on an operator's machine. A command that loads it
  without ``--role`` on a multi-workspace tenant exits 2 ("specify
  --role"), so tests expecting exit 0 fail locally while passing in CI.
* ``.env`` — re-loaded at every CLI invocation by
  ``contentops.cli.root.cli`` via ``load_env_file()``; it repopulates
  ``AZURE_*`` auth vars that tests ``monkeypatch.delenv`` to assert the
  unset path, undoing the test's intent.

This fixture pins the clean-checkout baseline: no ``.env`` discovery, the
default tenant-config path points at a non-existent file, and the auth
env vars are cleared. Tests that need a config still pass ``--path`` or
``monkeypatch.setattr("contentops.config.CONFIG_PATH", ...)`` — their
setattr runs after this one and wins.

Scoped to ``tests/v2/`` (unit tests) ONLY. Integration and e2e tests
under ``tests/integration`` / ``tests/e2e`` legitimately need the real
config + credentials and have their own conftest; this file does not
apply to them.
"""

from __future__ import annotations

import pytest

# Auth/selection env vars an operator's `.env` or shell would set. Cleared
# per-test so the suite matches CI (where none are set for the unit job).
_LEAKABLE_AUTH_ENV_VARS = (
    "AZURE_CLIENT_ID",
    "AZURE_TENANT_ID",
    "AZURE_CLIENT_SECRET",
    "AZURE_SUBSCRIPTION_ID",
    "PIPELINE_ENV",
)


@pytest.fixture(autouse=True)
def _isolate_from_local_config_and_env(monkeypatch, tmp_path):
    """Isolate each v2 test from operator-local config/tenant.yml + .env,
    and run it from its own tmp CWD."""
    # 1) Never auto-discover the developer's .env at CLI invoke time
    #    (CI has none). load_env_file() calls this module-global, so a
    #    None return makes it a no-op.
    monkeypatch.setattr(
        "contentops.utils.env.find_dotenv", lambda *args, **kwargs: None
    )
    # 2) Point the default tenant-config path at a file that does not
    #    exist, so the gitignored config/tenant.yml is never picked up.
    #    load_tenant_config() then raises FileNotFoundError exactly as it
    #    does in a clean CI checkout.
    monkeypatch.setattr(
        "contentops.config.CONFIG_PATH", tmp_path / "no-such-tenant.yml"
    )
    # 3) Clear auth vars a developer .env / shell would otherwise leak.
    for var in _LEAKABLE_AUTH_ENV_VARS:
        monkeypatch.delenv(var, raising=False)
    # 4) Run each test from its own tmp directory so CWD-relative writes
    #    land in the test's tmp tree, not the operator's real working
    #    tree. The load-bearing case is the audit chain: the lifecycle
    #    commands (disable/enable/lock/unlock/retry) write via
    #    ``write_records(Path.cwd(), ...)``, which targets
    #    ``<cwd>/audit/<date>.jsonl`` using a FIXED ``.tmp`` name. Without
    #    an isolated CWD, those tests all write to the *same* real
    #    ``audit/<date>.jsonl`` and race on its single ``.tmp`` under
    #    ``pytest -n auto`` (CI's invocation) — intermittent
    #    FileNotFoundError / PermissionError on ``os.replace``, plus
    #    corruption of the operator's local hash-chained log. Tests that
    #    need a specific CWD just ``monkeypatch.chdir(...)`` again; theirs
    #    runs after this and wins.
    monkeypatch.chdir(tmp_path)
    yield
