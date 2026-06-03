# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for scripts/remediate_payload001.py.

The remediation helper deletes a single line from each affected
detection envelope. It must be surgical (no other bytes change),
idempotent, and correct on every shape the lint rule may flag.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest
import yaml


SCRIPT_PATH = Path(__file__).resolve().parents[2] / "scripts" / "remediate_payload001.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("remediate_payload001", SCRIPT_PATH)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["remediate_payload001"] = mod
    spec.loader.exec_module(mod)
    return mod


remediate = _load_module()


# ---- fixture (a): dangling templateVersion -- must be removed -------------
NEEDS_REMOVAL = """\
id: sentinel-needs-removal
version: 0.0.0
platform: sentinel
status: production
sentinel:
  kind: Scheduled
  queryFrequency: PT5M
  queryPeriod: PT5M
  triggerOperator: GreaterThan
  triggerThreshold: 0
  severity: Medium
  query: |-
    SecurityEvent
    | where TimeGenerated > ago(1h)
    | take 10
  templateVersion: 1.0.0
  eventGroupingSettings:
    aggregationKind: SingleAlert
  displayName: Needs Removal
  enabled: true
"""


# ---- fixture (b): templateVersion + alertRuleTemplateName -- no-op --------
NAME_PRESENT = """\
id: sentinel-name-present
version: 0.0.0
platform: sentinel
status: production
sentinel:
  kind: Scheduled
  queryFrequency: PT5M
  queryPeriod: PT5M
  triggerOperator: GreaterThan
  triggerThreshold: 0
  severity: Medium
  query: |-
    SecurityEvent
    | where TimeGenerated > ago(1h)
    | take 10
  alertRuleTemplateName: 11111111-2222-3333-4444-555555555555
  templateVersion: 1.0.0
  displayName: Name Present
  enabled: true
"""


# ---- fixture (c): templateVersion absent -- no-op -------------------------
ABSENT = """\
id: sentinel-absent
version: 0.0.0
platform: sentinel
status: production
sentinel:
  kind: Scheduled
  queryFrequency: PT5M
  queryPeriod: PT5M
  triggerOperator: GreaterThan
  triggerThreshold: 0
  severity: Medium
  query: |-
    SecurityEvent
    | where TimeGenerated > ago(1h)
    | take 10
  displayName: Absent
  enabled: true
"""


def test_a_dangling_template_version_is_removed() -> None:
    new_text, status, _detail = remediate.remediate_text(NEEDS_REMOVAL)

    assert status == remediate.STATUS_REMOVED
    assert new_text != NEEDS_REMOVAL
    assert new_text.count("\n") == NEEDS_REMOVAL.count("\n") - 1
    assert "templateVersion" not in new_text

    parsed = yaml.safe_load(new_text)
    assert "templateVersion" not in parsed["sentinel"]
    # Other content survived intact.
    assert parsed["sentinel"]["query"].startswith("SecurityEvent")
    assert parsed["sentinel"]["displayName"] == "Needs Removal"


def test_b_name_present_is_not_modified() -> None:
    new_text, status, _detail = remediate.remediate_text(NAME_PRESENT)

    assert status == remediate.STATUS_NAME_PRESENT
    assert new_text == NAME_PRESENT


def test_c_template_version_absent_is_noop() -> None:
    new_text, status, _detail = remediate.remediate_text(ABSENT)

    assert status == remediate.STATUS_NO_TEMPLATE_VERSION
    assert new_text == ABSENT


def test_idempotent_second_pass_is_noop() -> None:
    once, status1, _ = remediate.remediate_text(NEEDS_REMOVAL)
    assert status1 == remediate.STATUS_REMOVED

    twice, status2, _ = remediate.remediate_text(once)
    assert status2 == remediate.STATUS_NO_TEMPLATE_VERSION
    assert twice == once


def test_byte_level_surgery_only_removes_target_line() -> None:
    """Every line except the templateVersion line must survive byte-for-byte."""
    new_text, status, _ = remediate.remediate_text(NEEDS_REMOVAL)
    assert status == remediate.STATUS_REMOVED

    expected = NEEDS_REMOVAL.replace("  templateVersion: 1.0.0\n", "", 1)
    assert new_text == expected


def test_run_against_workspace(tmp_path: Path) -> None:
    base = tmp_path / "detections"
    (base / "sentinel").mkdir(parents=True)
    a = base / "sentinel" / "needs.yml"
    b = base / "sentinel" / "name.yml"
    c = base / "sentinel" / "absent.yml"
    a.write_text(NEEDS_REMOVAL, encoding="utf-8")
    b.write_text(NAME_PRESENT, encoding="utf-8")
    c.write_text(ABSENT, encoding="utf-8")

    report = remediate.run(base, write=True)

    assert report.scanned == 3
    assert len(report.changed) == 1
    assert "needs.yml" in report.changed[0]
    assert len(report.unchanged) == 2
    assert report.skipped == []

    # The two no-op files are byte-identical to their inputs.
    assert b.read_text(encoding="utf-8") == NAME_PRESENT
    assert c.read_text(encoding="utf-8") == ABSENT
    # The remediated file dropped the line.
    assert "templateVersion" not in a.read_text(encoding="utf-8")


def test_run_dry_run_writes_nothing(tmp_path: Path) -> None:
    base = tmp_path / "detections"
    (base / "sentinel").mkdir(parents=True)
    a = base / "sentinel" / "needs.yml"
    a.write_text(NEEDS_REMOVAL, encoding="utf-8")

    report = remediate.run(base, write=False)

    assert len(report.changed) == 1
    # Dry-run still classifies the file as "would change" but leaves bytes alone.
    assert a.read_text(encoding="utf-8") == NEEDS_REMOVAL


@pytest.mark.parametrize(
    "platform_key,asset_value",
    [("sentinel", None), ("payload", "sentinel_analytic")],
)
def test_works_against_v1_and_v2_envelopes(
    platform_key: str, asset_value: str | None,
) -> None:
    """Both legacy ``platform: sentinel`` and v2 ``asset: sentinel_analytic``
    envelopes must be remediable."""
    if asset_value is None:
        text = NEEDS_REMOVAL
    else:
        text = NEEDS_REMOVAL.replace(
            "platform: sentinel", f"asset: {asset_value}",
        ).replace("sentinel:", "payload:")
    new_text, status, _ = remediate.remediate_text(text)
    assert status == remediate.STATUS_REMOVED
    assert "templateVersion" not in new_text
