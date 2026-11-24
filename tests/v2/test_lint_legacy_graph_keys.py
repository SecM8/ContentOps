# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""PAYLOAD015: a Defender rule still carries a deprecated Graph property.

One warning per rule, never an error: an old key must not be able to fail
validation for the whole repository. The message says, per key, whether
it is ignored (its new key has content) or still sent (it is the only
filled one), and calls out an ignored key whose value differs from the
new key, because that edit will not be deployed.
"""

from __future__ import annotations

from contentops.core.asset import Asset
from contentops.lint.payload import lint_payload
from tests.v2.defender_shapes import current_payload, legacy_only_payload, two_shape_payload

D = Asset.DEFENDER_CUSTOM_DETECTION


def _p015(payload: dict, asset: Asset = D) -> list:
    return [f for f in lint_payload(payload, asset=asset) if f.rule_id == "PAYLOAD015"]


def test_new_keys_only_is_silent() -> None:
    assert _p015(current_payload()) == []


def test_two_shape_payload_gets_one_warning_naming_every_old_key() -> None:
    findings = _p015(two_shape_payload())
    assert len(findings) == 1
    assert findings[0].severity == "warning"
    message = findings[0].message
    for key in (
        "schedule.period", "alertTemplate.category", "alertTemplate.mitreTechniques",
        "alertTemplate.impactedAssets", "detectionAction.responseActions",
        "organizationalScope.scopeType", "organizationalScope.scopeNames",
    ):
        assert key in message
    assert "ignored" in message
    assert "still sent" not in message
    assert "differs" not in message


def test_old_keys_only_are_reported_as_still_sent() -> None:
    findings = _p015(legacy_only_payload())
    assert len(findings) == 1
    assert findings[0].severity == "warning"
    assert "still sent" in findings[0].message
    assert "schedule.frequency" in findings[0].message  # names the key to use


def test_an_ignored_old_value_that_differs_is_called_out() -> None:
    payload = two_shape_payload()
    payload["schedule"]["period"] = "3H"
    message = _p015(payload)[0].message
    assert "differs" in message
    assert message.index("schedule.period") < message.index("differs")


def test_is_enabled_next_to_status_is_reported() -> None:
    findings = _p015(current_payload(isEnabled=True))
    assert len(findings) == 1 and "isEnabled" in findings[0].message


def test_not_emitted_for_other_asset_kinds() -> None:
    assert _p015(two_shape_payload(), asset=Asset.SENTINEL_ANALYTIC) == []


def test_never_an_error() -> None:
    for payload in (two_shape_payload(), legacy_only_payload()):
        assert {f.severity for f in _p015(payload)} == {"warning"}
