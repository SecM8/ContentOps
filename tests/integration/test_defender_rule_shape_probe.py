# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Live probe of the Defender XDR custom detection API.

Skipped unless RUN_LIVE_TESTS=1 and the credential has the
CustomDetection.ReadWrite.All Graph application permission.

It creates DISABLED rules whose display name starts with ``zz_itest_``
and whose query cannot return a row, updates them, and deletes them. It
never writes to any other rule. What it asks, and the safety rules it
keeps, are in ``defender_shape_probe.py``; those rules are unit-tested in
``tests/v2/test_defender_shape_probe.py``.

The answers go to ``defender-shape-report.md`` and to the job summary.
They contain made-up values and yes/no facts only, never a value read
from the tenant.
"""

from __future__ import annotations

import os
from pathlib import Path

from tests.integration import defender_shape_probe as probe

# Kinds this module writes; the kind kill switch skips it when one is switched off
# (tests/integration/kill_switch.py).
LIVE_KINDS = ("defender_custom_detection",)

REPORT_FILE = "defender-shape-report.md"


def test_defender_rule_shape_probe(confirmed_defender_client, integration_id) -> None:
    probe.require_confirmation()
    run_id = integration_id.removeprefix("zz-itest-").replace("-", "_")
    report = probe.run_probe(
        confirmed_defender_client, run_id=run_id,
        device_group=os.environ.get(probe.DEVICE_GROUP_ENV) or None,
    )

    text = probe.render_report(report)
    Path(REPORT_FILE).write_text(text, encoding="utf-8")
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as handle:
            handle.write(text)
    print(text)

    aborted = report.aborted is not None
    leftovers = report.leftovers
    stops = len(report.stops())
    assert not aborted, "the probe aborted on a safety rule; read the report"
    assert leftovers == 0, "test rules are still listed; run this workflow with sweep-only"
    assert stops == 0, "the report has answers marked STOP; read the report before going on"
