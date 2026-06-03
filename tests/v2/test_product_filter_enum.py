# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for MicrosoftSecurityProductName enum completeness.

Background: an adopter test on 2026-05-18 collected two
production-deployed MicrosoftSecurityIncidentCreation rules whose
`productFilter` values ('Office 365 Advanced Threat Protection' and
'Microsoft Defender Advanced Threat Protection') tripped a `value
is not a valid enumeration member` error. Both products ARE valid
sources for these rules per Microsoft's ARM API — the enum just
hadn't been updated when ContentOps was built. The deployed rules
in the tenant proved the API accepts them.

This test pins the canonical legacy product names so a future
refactor / enum rename can't silently re-drop them.
"""

from __future__ import annotations

import pytest

from contentops.models import (
    MicrosoftSecurityProductName,
    SentinelMicrosoftSecurityIncidentCreationPayload,
)


# The canonical legacy names accepted by Sentinel's ARM productFilter
# field (still required even at api-version 2025-09-01, see the enum
# docstring). Microsoft "rebranded" each but the API rejects post-
# rebrand display names.
_EXPECTED_PRODUCT_NAMES: tuple[str, ...] = (
    "Azure Active Directory Identity Protection",
    "Azure Advanced Threat Protection",
    "Azure Security Center",
    "Azure Security Center for IoT",
    "Microsoft Cloud App Security",
    "Office 365 Advanced Threat Protection",
    "Microsoft Defender Advanced Threat Protection",
)


@pytest.mark.parametrize("product_name", _EXPECTED_PRODUCT_NAMES)
def test_enum_accepts_canonical_product_name(product_name: str) -> None:
    """Each canonical legacy product name parses cleanly into the
    enum and into a MicrosoftSecurityIncidentCreation payload."""
    # Direct enum coercion.
    assert MicrosoftSecurityProductName(product_name).value == product_name

    # End-to-end via the payload model — this is the path that the
    # `validate_sentinel_payload` helper exercises during collect.
    p = SentinelMicrosoftSecurityIncidentCreationPayload(
        kind="MicrosoftSecurityIncidentCreation",
        displayName="t",
        productFilter=product_name,
    )
    assert p.productFilter.value == product_name


def test_enum_rejects_unknown_product_name() -> None:
    """A non-enum value still raises — the fix expands the set, not
    relaxes type checking."""
    with pytest.raises(ValueError):
        SentinelMicrosoftSecurityIncidentCreationPayload(
            kind="MicrosoftSecurityIncidentCreation",
            displayName="t",
            productFilter="Not A Real Product",
        )


def test_enum_rejects_rebranded_display_name() -> None:
    """Microsoft rebranded several products but the ARM API still
    requires the legacy names. Submitting the rebranded form would
    yield HTTP 400 at apply-time. Pin that the validator catches
    this before the wire."""
    rebranded_examples = (
        "Microsoft Defender for Office 365",
        "Microsoft Defender for Endpoint",
        "Microsoft Defender for Cloud",
        "Microsoft Defender for Identity",
        "Microsoft Defender for Cloud Apps",
    )
    for rebranded in rebranded_examples:
        with pytest.raises(ValueError):
            SentinelMicrosoftSecurityIncidentCreationPayload(
                kind="MicrosoftSecurityIncidentCreation",
                displayName="t",
                productFilter=rebranded,
            )
