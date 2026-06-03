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


def test_live_collect_roundtrip_zero_drift(tmp_path: Path) -> None:
    """First collect snapshots the tenant; second collect must be 100%
    in-sync (no NEW, no CHANGED). Failures here mean a handler's
    to_envelope is non-deterministic or the envelope parses
    differently than it was written.
    """
    import concurrent.futures

    from contentops.cli.handler_factories import register_default_handlers
    from contentops.core.drift import (
        DriftCapable, DriftEntry, DriftReport, _local_index, _payloads_match,
    )
    from contentops.core.registry import default_registry

    target = tmp_path / "snapshot"
    target.mkdir(parents=True, exist_ok=True)
    register_default_handlers()

    # All 6 surviving asset kinds run by default; the per-handler skip
    # list is empty after the asset-taxonomy reduction (the kinds that
    # required permissions our SP doesn't hold — playbook, defender TI —
    # were removed entirely).
    skip_handlers: set[str] = set()

    # Fan-out handlers respect --full (we want full).
    drift_handlers: list[DriftCapable] = [
        default_registry.get(a) for a in default_registry.assets()
        if a.value not in skip_handlers
        and isinstance(default_registry.get(a), DriftCapable)
    ]

    def _list_one(handler):
        try:
            return handler.asset.value, handler.list_remote()
        except Exception as exc:  # noqa: BLE001
            return handler.asset.value, exc

    def _do_collect_pass() -> DriftReport:
        results: dict[str, list[dict]] = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            for value, res in pool.map(_list_one, drift_handlers):
                if isinstance(res, Exception):
                    results[value] = []
                else:
                    results[value] = res
        report = DriftReport()
        for handler in drift_handlers:
            asset_value = handler.asset.value
            local = _local_index(target, handler.asset)
            for remote in results.get(asset_value, []):
                envelope = handler.to_envelope(remote)
                if envelope is None:
                    continue
                rid = envelope.get("id")
                if not rid:
                    continue
                payload = envelope.get("payload", {})
                if rid not in local:
                    report.entries.append(DriftEntry(
                        asset=handler.asset, asset_id=rid, kind="new",
                        envelope=envelope,
                    ))
                    continue
                _, local_payload = local[rid]
                if _payloads_match(local_payload, payload):
                    report.entries.append(DriftEntry(
                        asset=handler.asset, asset_id=rid, kind="in-sync",
                    ))
                else:
                    report.entries.append(DriftEntry(
                        asset=handler.asset, asset_id=rid, kind="changed",
                        envelope=envelope,
                    ))
        return report

    try:
        # Pass 1: write everything.
        first = _do_collect_pass()
        from contentops.core.drift import write_drift
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
