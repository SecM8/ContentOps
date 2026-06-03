# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Handler-coverage parity test (CI-4 / T-1).

Every value of the ``Asset`` enum should resolve to a handler in the
default registry, and every registered handler should expose the
Handler protocol surface (validate / plan / apply / delete) that the
CLI dispatcher calls. Without this guard, adding a new ``Asset``
member can ship with no handler — or a handler missing a method —
and only surface during a live apply against the tenant.

This test runs without tenant.yml (the `register_default_handlers`
no-tenant.yml fallback path), so it stays a pure unit test.
"""

from __future__ import annotations

from contentops.cli.handler_factories import register_default_handlers
from contentops.core.asset import Asset
from contentops.core.drift import DriftCapable
from contentops.core.registry import default_registry


# Handlers we expect to expose drift capability. All six in the
# current taxonomy implement it; if a future kind genuinely cannot
# (e.g. a write-only API), explicitly exclude it here AND document
# why next to the exclusion.
_DRIFT_CAPABLE_ASSETS: frozenset[Asset] = frozenset(Asset)


def test_every_asset_has_a_registered_handler() -> None:
    register_default_handlers()
    try:
        registered = set(default_registry.assets())
    finally:
        default_registry.close_all()
    missing = set(Asset) - registered
    assert not missing, (
        f"Asset enum members without a registered handler: {sorted(m.value for m in missing)}. "
        "Add a factory in contentops/cli/handler_factories.py or document the exclusion."
    )


def test_every_registered_handler_exposes_the_protocol_methods() -> None:
    """Each handler must define validate/plan/apply/delete as callables.

    Missing methods would only surface during a live apply; this test
    catches them at unit-test time."""
    register_default_handlers()
    try:
        for asset in default_registry.assets():
            handler = default_registry.get(asset)
            for method in ("validate", "plan", "apply", "delete"):
                attr = getattr(handler, method, None)
                assert callable(attr), (
                    f"{type(handler).__name__} (asset={asset.value}) "
                    f"is missing required method {method!r}"
                )
    finally:
        default_registry.close_all()


def test_every_drift_capable_asset_implements_drift_protocol() -> None:
    """Drift-capable handlers must satisfy the ``DriftCapable`` protocol —
    ``list_remote()`` + ``to_envelope()``. Without this, ``contentops
    drift`` silently skips the asset kind."""
    register_default_handlers()
    try:
        for asset in _DRIFT_CAPABLE_ASSETS:
            handler = default_registry.get(asset)
            assert isinstance(handler, DriftCapable), (
                f"{type(handler).__name__} (asset={asset.value}) is "
                "expected to satisfy DriftCapable; either implement "
                "list_remote / to_envelope or update "
                "_DRIFT_CAPABLE_ASSETS in this test with a comment."
            )
    finally:
        default_registry.close_all()
