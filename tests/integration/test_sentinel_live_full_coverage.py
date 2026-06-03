# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Live CRUD round-trips for the handlers not covered by the
asset-specific integration test files.

After the asset-taxonomy reduction (Phase 1C), this file's only
remaining surface is the doctor-matrix test — the per-handler
CRUD round-trips it carried (automation, metadata, summary_rule)
went with the handlers themselves. Per-asset CRUD lives in the
dedicated ``test_*_crud.py`` files.

Skipped unless RUN_LIVE_TESTS=1.
"""

from __future__ import annotations

import os

import pytest


# ---------------------------------------------------------------------------
# Doctor matrix — runs as part of the live suite
# ---------------------------------------------------------------------------


def test_doctor_matrix_no_failures(monkeypatch):
    """`contentops doctor --matrix` against the integration tenant must
    report at least the core handlers as PASS. WARN is tolerated for
    Defender Graph endpoints that need elevated permissions.

    The v2 CLI normally sets ``PIPELINE_WORKSPACE_NAME`` upstream of
    handler construction (via `--role` / `--workspace` resolution in
    ``contentops doctor``), so the handler matrix knows which Sentinel
    workspace to target. ``run_checks(...)`` is called directly here,
    bypassing that resolution; on a multi-workspace tenant it
    therefore fails closed with "specify --role or --workspace."
    Mirror what the CLI would do by pinning the env var to
    ``INTEGRATION_WORKSPACE_NAME`` for the duration of this test —
    matches v2 CLI semantics and is the same pattern
    ``tests/v2/test_multi_workspace_targeting.py`` uses for
    multi-workspace assertions.
    """
    from contentops.devex.doctor import (
        aggregate_exit_code, run_checks,
    )

    monkeypatch.setenv(
        "PIPELINE_WORKSPACE_NAME",
        os.environ["INTEGRATION_WORKSPACE_NAME"],
    )

    results = run_checks(with_auth=True, with_matrix=True)
    fail_results = [r for r in results if r.status == "FAIL"]
    assert not fail_results, (
        "doctor reported FAILs against the integration tenant: "
        + ", ".join(f"{r.name}={r.detail}" for r in fail_results)
    )
    # Expect at least 5 PASSed handler:* rows (analytic, watchlist,
    # incident, metadata, settings — all known to exist on this tenant).
    handler_rows = [r for r in results if r.name.startswith("handler:")]
    pass_handlers = [r for r in handler_rows if r.status == "PASS"]
    assert len(pass_handlers) >= 5, (
        f"only {len(pass_handlers)} handler(s) PASSed; expected >= 5"
    )
    # exit_code must be 0 (FAILs would have asserted above).
    assert aggregate_exit_code(results) == 0
