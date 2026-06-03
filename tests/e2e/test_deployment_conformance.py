# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Pytest wrapper for ``contentops conformance``.

Runs the full layered conformance check (L1–L7) and fails the test
only if any check is FAIL. SKIPs and INFOs do not gate.

The wrapper invokes the underlying conformance module directly rather
than shelling out to the CLI so the per-check rows are inspectable
from pytest's failure output.

Layer coverage depends on environment:

* **offline mode**: only L1 (install) + L2 (tenant config) run with
  meaningful output; L3-L7 SKIP because no Azure credentials or
  network. PASS criterion: every L1/L2 check is PASS (or INFO/SKIP).
* **mocked mode**: same as offline — respx isn't wired into the
  conformance probes (they speak to real ARM/Graph). Conformance is
  inherently a live concept.
* **live mode**: L3-L7 run against the configured tenant. Read-only
  by construction; the matrix's ``non_destructive_guard`` also blocks
  any accidental write.

Gated by the same ``RUN_E2E=1`` / ``--mode`` opt-in as the matrix.
"""

from __future__ import annotations

import pytest


def test_deployment_conformance(mode: str, sandbox, scoped_env, results_collector) -> None:
    """Run the layered conformance check and assert no FAILs."""
    # Imported lazily so the conftest's CONFIG_PATH monkeypatch is in
    # place before the conformance module reads tenant.yml.
    from contentops.devex.conformance import (
        ConformanceReport,
        run_conformance,
    )

    if mode == "offline":
        # In offline mode the conformance check would surface every
        # L3+ probe as "no creds available". Run only L1+L2 so the
        # PASS condition is meaningful in this mode.
        scope = ("L1", "L2")
    elif mode == "mocked":
        # Same rationale — conformance probes real Azure, not respx.
        scope = ("L1", "L2")
    else:
        scope = ("L1", "L2", "L3", "L4", "L5", "L6", "L7")

    report: ConformanceReport = run_conformance(scope=scope)

    # Record one row per check on the shared results collector so the
    # session-end table shows conformance findings alongside matrix rows.
    for c in report.checks:
        results_collector.record(
            f"conformance.{c.layer}.{c.name}",
            c.status,
            0.0,
            c.detail if c.status != "FAIL"
            else f"{c.detail} — fix: {c.remediation}",
        )

    if report.failed:
        lines = [f"conformance failed ({len(report.failed)} check(s)):"]
        for c in report.failed:
            lines.append(f"  [{c.layer}] {c.name}: {c.detail}")
            if c.remediation:
                lines.append(f"      remediation: {c.remediation}")
        pytest.fail("\n".join(lines))
