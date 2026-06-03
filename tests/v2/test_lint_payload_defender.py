# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for the Defender save-validator payload rules (PAYLOAD005/006).

Both are warning-severity heuristics for the documented beta
detectionRules save-validator 400s (see
docs/operations/defender-fileprofile-detections.md):

* PAYLOAD005 — a FileProfile() output column referenced without a
  defensive ``column_ifexists`` redeclaration.
* PAYLOAD006 — an entity-mapping column not re-projected after the
  FileProfile ``invoke`` (the schema-less boundary).

They are scoped to defender_custom_detection AND to queries that invoke
FileProfile, so non-FileProfile reshaping queries (whose columns the
validator can resolve from real table schemas) are NOT flagged.
"""

from __future__ import annotations

from contentops.core.asset import Asset
from contentops.lint.payload import lint_payload

D = Asset.DEFENDER_CUSTOM_DETECTION


def _defender(query: str, identifiers: list[str] | None = None) -> dict:
    payload: dict = {"queryCondition": {"queryText": query}}
    if identifiers is not None:
        payload["detectionAction"] = {"alertTemplate": {
            "impactedAssets": [{"identifier": i} for i in identifiers],
        }}
    return payload


def _ids(payload: dict) -> list[str]:
    return [f.rule_id for f in lint_payload(payload, asset=D)]


# ---------------------------------------------------------------------------
# PAYLOAD005 — FileProfile output filter without column_ifexists
# ---------------------------------------------------------------------------


def test_payload005_fires_on_bare_fileprofile_output_filter() -> None:
    payload = _defender(
        "DeviceImageLoadEvents\n| distinct SHA1\n"
        "| invoke FileProfile(SHA1,1000)\n| where GlobalPrevalence >= 50"
    )
    assert "PAYLOAD005" in _ids(payload)


def test_payload005_quiet_when_column_ifexists_redeclares() -> None:
    payload = _defender(
        "DeviceImageLoadEvents\n| invoke FileProfile(SHA1,1000)\n"
        '| extend GP = column_ifexists("GlobalPrevalence", long(null))\n'
        "| where GP >= 50"
    )
    assert "PAYLOAD005" not in _ids(payload)


def test_payload005_quiet_without_fileprofile() -> None:
    # GlobalPrevalence-shaped name but no FileProfile invoke → not our case.
    payload = _defender("DeviceEvents | where GlobalPrevalence >= 50")
    assert "PAYLOAD005" not in _ids(payload)


def test_payload005_flags_each_distinct_output_column() -> None:
    payload = _defender(
        "T | invoke FileProfile(SHA1,1000)\n"
        "| where SignatureState == 'Valid' and GlobalPrevalence > 10"
    )
    msgs = [f.message for f in lint_payload(payload, asset=D) if f.rule_id == "PAYLOAD005"]
    joined = " ".join(msgs)
    assert "SignatureState" in joined and "GlobalPrevalence" in joined


def test_payload005_not_emitted_for_sentinel() -> None:
    payload = _defender(
        "T | invoke FileProfile(SHA1,1000) | where GlobalPrevalence > 1"
    )
    assert "PAYLOAD005" not in [
        f.rule_id for f in lint_payload(payload, asset=Asset.SENTINEL_ANALYTIC)
    ]


# ---------------------------------------------------------------------------
# PAYLOAD006 — entity column not re-projected after FileProfile
# ---------------------------------------------------------------------------


def test_payload006_fires_when_entity_column_dropped_after_invoke() -> None:
    payload = _defender(
        "DeviceEvents\n| invoke FileProfile(SHA1,1000)\n| distinct SHA1",
        identifiers=["deviceId"],
    )
    assert "PAYLOAD006" in _ids(payload)


def test_payload006_quiet_when_reprojected_after_invoke() -> None:
    payload = _defender(
        "DeviceEvents\n| invoke FileProfile(SHA1,1000)\n"
        '| extend DeviceId = column_ifexists("DeviceId", "")',
        identifiers=["deviceId"],
    )
    assert "PAYLOAD006" not in _ids(payload)


def test_payload006_quiet_without_fileprofile() -> None:
    # Non-FileProfile reshaping query: the validator resolves columns from
    # the real table schema, so dropping DeviceId is not our failure mode.
    payload = _defender(
        "DeviceEvents | summarize c=count() by RemoteUrl",
        identifiers=["deviceId"],
    )
    assert "PAYLOAD006" not in _ids(payload)


def test_payload006_column_only_before_invoke_still_flags() -> None:
    # DeviceId appears BEFORE the invoke but is lost across FileProfile and
    # not re-projected after → still a 400.
    payload = _defender(
        "DeviceEvents | project DeviceId, SHA1\n"
        "| invoke FileProfile(SHA1,1000)\n| distinct SHA1",
        identifiers=["deviceId"],
    )
    assert "PAYLOAD006" in _ids(payload)


def test_payload006_acronym_identifier_override() -> None:
    # sha256 -> SHA256 (override), not "Sha256" (naive PascalCase). Use
    # sha256 (not the FileProfile key SHA1) so the column is genuinely
    # absent unless re-projected.
    missing = _defender(
        "T | invoke FileProfile(SHA1,1000) | distinct DeviceName",
        identifiers=["sha256"],
    )
    assert "PAYLOAD006" in _ids(missing)
    # Re-projecting the override-cased column (SHA256, not Sha256) clears it.
    present = _defender(
        'T | invoke FileProfile(SHA1,1000) | extend SHA256 = column_ifexists("SHA256", "")',
        identifiers=["sha256"],
    )
    assert "PAYLOAD006" not in _ids(present)
