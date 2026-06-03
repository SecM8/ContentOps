# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Integration test harness — gated by RUN_LIVE_TESTS=1.

These tests hit a real Azure tenant. They:
  * read credentials via DefaultAzureCredential (driven by .env locally),
  * target a workspace defined by INTEGRATION_* env vars,
  * name every artefact with a sentinel prefix and sweep stragglers
    on session teardown,
  * are skipped silently when the opt-in flag is off.

Hardening against accidental production hits:
  * Sentinel rules are created with ``enabled: False``.
  * If INTEGRATION_WORKSPACE_NAME matches the workspace declared in
    config/tenant.yml, the suite refuses to run unless
    I_UNDERSTAND_THIS_IS_PRODUCTION=yes is set.
"""

from __future__ import annotations

import os
import time
import uuid
from pathlib import Path
from typing import Iterator

import pytest

from contentops.config import SentinelConfig
from contentops.utils.env import load_env_file

# .env loader normally runs from the CLI; pytest is a different entry point.
load_env_file()


# All test artefacts get this prefix so a session-end sweep can find and
# delete anything a crashed test may have left behind. Hyphenated form
# (Sentinel rule name path segment) and underscore form (Defender display
# name) — both must start with the same recognisable token.
RESOURCE_PREFIX_HYPHEN = "zz-itest-"
RESOURCE_PREFIX_UNDERSCORE = "zz_itest_"


def _live_enabled() -> bool:
    return os.getenv("RUN_LIVE_TESTS") == "1"


_INTEGRATION_DIR = Path(__file__).parent.resolve()


def pytest_collection_modifyitems(config, items):
    """Skip integration tests unless RUN_LIVE_TESTS=1.

    This conftest lives in tests/integration/ but pytest applies the
    hook to *every* collected item, so we must filter by path or we
    silently skip the entire unit-test suite as well.
    """
    if _live_enabled():
        return
    skip = pytest.mark.skip(reason="RUN_LIVE_TESTS!=1; integration tests skipped")
    for item in items:
        try:
            item_path = Path(str(item.fspath)).resolve()
        except Exception:
            continue
        if _INTEGRATION_DIR in item_path.parents or item_path == _INTEGRATION_DIR:
            item.add_marker(skip)


def _is_production_workspace(cfg, workspace: str) -> tuple[bool, str | None]:
    """Return ``(matches_prod, matched_workspace_name)``.

    Pure decision helper extracted so it can be unit-tested without
    live Azure (see ``tests/v2/test_integration_guard.py``).

    Walks the tenant's prod-role workspaces (``cfg.workspaces_for_role
    ("prod")``) and reports a case-insensitive match against
    ``workspace``. Returns the matched name so the guard error message
    can quote the prod workspace verbatim instead of paraphrasing.

    Conservative on missing data: if the tenant has zero prod-role
    workspaces, returns ``(False, None)`` — no false positives.
    """
    try:
        prod_workspaces = cfg.workspaces_for_role("prod")
    except Exception:
        return (False, None)
    needle = workspace.lower()
    for w in prod_workspaces:
        if w.workspaceName.lower() == needle:
            return (True, w.workspaceName)
    return (False, None)


def _confirm_not_production(workspace: str) -> None:
    """Refuse to run if INTEGRATION_WORKSPACE_NAME is a production
    Sentinel workspace from the tenant config, unless explicitly
    confirmed via I_UNDERSTAND_THIS_IS_PRODUCTION=yes.

    Reads the tenant config the same way the v2 CLI does
    (``load_tenant_config`` honours ``PIPELINE_ENV``). Compares
    ``workspace`` against the **prod-role** workspaces in
    ``cfg.sentinelWorkspaces`` rather than the obsolete
    ``cfg.sentinel.workspaceName`` (the latter no longer exists post-
    multi-workspace migration).
    """
    try:
        from contentops.config import load_tenant_config
        cfg = load_tenant_config()
    except Exception:
        return  # No tenant.yml to compare against — nothing to guard.
    matches_prod, matched_name = _is_production_workspace(cfg, workspace)
    if not matches_prod:
        return
    if os.getenv("I_UNDERSTAND_THIS_IS_PRODUCTION") == "yes":
        return
    pytest.exit(
        f"INTEGRATION_WORKSPACE_NAME={workspace!r} matches a prod-role "
        f"Sentinel workspace in config/tenant.yml "
        f"(workspace={matched_name}, tenant={cfg.name}). "
        "Set I_UNDERSTAND_THIS_IS_PRODUCTION=yes in your .env to confirm "
        "you really intend to run live CRUD tests against it.",
        returncode=2,
    )


@pytest.fixture(scope="session")
def integration_sentinel_config() -> SentinelConfig:
    """Workspace config sourced from INTEGRATION_* env vars."""
    required = (
        "INTEGRATION_SUBSCRIPTION_ID",
        "INTEGRATION_RESOURCE_GROUP",
        "INTEGRATION_WORKSPACE_NAME",
    )
    missing = [k for k in required if not os.getenv(k)]
    if missing:
        pytest.skip(f"missing env: {', '.join(missing)}")
    workspace = os.environ["INTEGRATION_WORKSPACE_NAME"]
    _confirm_not_production(workspace)
    return SentinelConfig(
        subscriptionId=os.environ["INTEGRATION_SUBSCRIPTION_ID"],
        resourceGroup=os.environ["INTEGRATION_RESOURCE_GROUP"],
        workspaceName=workspace,
        location=os.getenv("INTEGRATION_WORKSPACE_LOCATION", "westeurope"),
    )


@pytest.fixture(scope="session")
def integration_credential():
    from contentops.utils.auth import get_credential
    return get_credential()


@pytest.fixture(scope="session")
def sentinel_client(integration_sentinel_config, integration_credential):
    """Sentinel ARM session fixture.

    The fixture name is kept for backwards compatibility with the
    downstream integration tests that already depend on it, but the
    object yielded is now a
    :class:`contentops.providers.sentinel_arm.SentinelArmProvider`
    constructed with ``credential=`` (proactive-refresh path) rather
    than the v1 ``SentinelClient`` shim with a pre-fetched static
    token. Method calls in downstream tests were updated in the same
    PR to use the provider's generic
    ``list_resource`` / ``get_resource`` / ``put_resource`` /
    ``delete_resource`` API against ``"alertRules"``.
    """
    from contentops.providers.sentinel_arm import SentinelArmProvider
    client = SentinelArmProvider(
        integration_sentinel_config, credential=integration_credential,
    )
    yield client
    _sweep_sentinel(client)
    client.close()


@pytest.fixture(scope="session")
def defender_client(integration_credential):
    from contentops.defender.client import DefenderClient
    from contentops.utils.auth import get_graph_token
    client = DefenderClient(get_graph_token(integration_credential))
    yield client
    _sweep_defender(client)
    client.close()


def _sweep_sentinel(client) -> None:
    """Delete any Sentinel rule whose name starts with the test prefix."""
    try:
        rules = client.list_resource("alertRules")
    except Exception:
        return
    for rule in rules:
        name = rule.get("name", "")
        if name.startswith(RESOURCE_PREFIX_HYPHEN):
            try:
                client.delete_resource("alertRules", name)
            except Exception:
                pass


def _sweep_defender(client) -> None:
    """Delete any Defender detection whose displayName starts with the prefix."""
    try:
        rules = client.list_rules()
    except Exception:
        return
    for rule in rules:
        if str(rule.get("displayName", "")).startswith(RESOURCE_PREFIX_UNDERSCORE):
            try:
                client.delete_rule(rule["id"])
            except Exception:
                pass


@pytest.fixture
def integration_id() -> str:
    """Per-test unique slug, prefixed so the sweep can find leaks."""
    return f"{RESOURCE_PREFIX_HYPHEN}{int(time.time())}-{uuid.uuid4().hex[:6]}"


@pytest.fixture
def created_sentinel_rules(sentinel_client) -> Iterator[list[str]]:
    """Track rule IDs the test created, delete them on teardown."""
    ids: list[str] = []
    try:
        yield ids
    finally:
        for rid in ids:
            try:
                sentinel_client.delete_resource("alertRules", rid)
            except Exception:
                pass


@pytest.fixture
def created_defender_rules(defender_client) -> Iterator[list[str]]:
    """Track Defender rule IDs the test created, delete them on teardown."""
    ids: list[str] = []
    try:
        yield ids
    finally:
        for rid in ids:
            try:
                defender_client.delete_rule(rid)
            except Exception:
                pass
