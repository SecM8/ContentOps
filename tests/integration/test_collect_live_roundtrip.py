# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Live collect-roundtrip contract.

The contract: two consecutive ``contentops collect --full`` runs against
the same target directory must produce zero NEW + zero CHANGED entries
on the second run. Every item must report ``in-sync``.

Skipped unless RUN_LIVE_TESTS=1. Reads .env credentials, hits the
production tenant, writes to a tmp_path scratch dir, asserts the
second-pass drift report is clean.
"""

from __future__ import annotations

from pathlib import Path

import pytest

# Kinds this module writes; the kind kill switch skips it when one is switched off
# (tests/integration/kill_switch.py).
LIVE_KINDS: tuple[str, ...] = ()  # collect reads the tenant, writes to a temp folder


def test_live_collect_roundtrip_zero_drift(tmp_path: Path) -> None:
    """First collect snapshots the tenant; second collect must be 100%
    in-sync (no NEW, no CHANGED). Failures here mean a handler's
    to_envelope is non-deterministic or the envelope parses
    differently than it was written.
    """
    import concurrent.futures

    from contentops.cli import handler_factories
    from contentops.cli.commands.collect_support import _classify_collected_drift
    from contentops.core.drift import DriftCapable, DriftReport, write_drift
    from contentops.core.registry import default_registry

    target = tmp_path / "snapshot"
    target.mkdir(parents=True, exist_ok=True)
    # References (`analytic:`, `playbook:`) resolve against the snapshot,
    # as collect's do against its --path.
    handler_factories.register_default_handlers(detections_root=target)

    def _drift_handlers() -> list[DriftCapable]:
        return [
            default_registry.get(a) for a in default_registry.assets()
            if isinstance(default_registry.get(a), DriftCapable)
        ]

    def _list_one(handler):
        try:
            return handler.asset.value, handler.list_remote()
        except Exception as exc:  # noqa: BLE001 — reported below
            return handler.asset.value, exc

    def _do_collect_pass() -> DriftReport:
        handlers = _drift_handlers()
        results: dict[str, list[dict]] = {}
        failures: dict[str, Exception] = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            for value, res in pool.map(_list_one, handlers):
                if isinstance(res, Exception):
                    failures[value] = res
                else:
                    results[value] = res
        if failures:
            # A kind the tenant could not list was never round-tripped.
            pytest.fail("list_remote failed, so these kinds were not round-tripped: " + "; ".join(
                f"{kind}: {exc}" for kind, exc in sorted(failures.items())
            ))
        # Collect's own classifier: remote-name matching, slug
        # disambiguation, per-kind comparison and same-run references.
        return _classify_collected_drift(handlers, results, target)

    try:
        # Pass 1: write everything.
        first = _do_collect_pass()
        write_drift(first, target)
        assert first.entries, "live tenant returned zero items — credentials wrong?"

        # Pass 2: must be 100% in-sync.
        second = _do_collect_pass()
        new = [e for e in second.entries if e.kind == "new"]
        changed = [e for e in second.entries if e.kind == "changed"]
        in_sync = [e for e in second.entries if e.kind == "in-sync"]

        assert not new, (
            f"second collect reports {len(new)} NEW item(s) — "
            f"to_envelope is not deterministic; first 5: "
            + ", ".join(f"{e.asset.value}/{e.asset_id}" for e in new[:5])
        )
        assert not changed, (
            f"second collect reports {len(changed)} CHANGED item(s) — "
            f"to_envelope yields non-stable payloads; first 5: "
            + ", ".join(f"{e.asset.value}/{e.asset_id}" for e in changed[:5])
        )
        assert in_sync, "second collect saw zero items — fixture issue"
    finally:
        default_registry.close_all()
