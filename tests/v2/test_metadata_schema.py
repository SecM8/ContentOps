# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for the T.1 schema expansion of ``RuleMetadata``.

The six new fields (description, attackDescription, references,
falsePositives, blindSpots, responseActions) are all optional with
sensible defaults so existing envelopes parse unchanged. This file
pins:

* Defaults — every new field has the expected empty default.
* Backwards compatibility — a minimal-but-complete metadata block
  (the existing required-field set) still parses fine without any
  of the new fields.
* Validation — ``references`` must contain http(s):// URLs; a typo'd
  scheme surfaces at parse time.
* Strict extra-fields — ``extra='forbid'`` still rejects unknown
  keys (so a typo on a new field name doesn't silently get dropped).
* Frozen model — assignment to an existing field after construction
  still raises (regression guard for the model_config posture).
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from contentops.core.metadata import RuleMetadata


def _full_metadata(**overrides) -> RuleMetadata:
    base = dict(
        owner="secops@example.com",
        runbookUrl="https://runbooks.example.com/x",
        severity="low",
        tactics=["Execution"],
        techniques=["T1059"],
        expectedAlertsPerDay=1,
        fpHandling="Triage manually.",
    )
    base.update(overrides)
    return RuleMetadata(**base)


# ---------------------------------------------------------------------------
# Defaults & backwards compat
# ---------------------------------------------------------------------------


def test_new_fields_default_to_empty() -> None:
    md = _full_metadata()
    assert md.description is None
    assert md.attackDescription is None
    assert md.references == []
    assert md.falsePositives == []
    assert md.blindSpots == []
    assert md.responseActions == []


def test_pre_expansion_metadata_blocks_still_parse() -> None:
    """A metadata block authored before T.1 (no new fields at all)
    must continue to parse cleanly — backwards compatibility for the
    ~150 already-collected envelopes."""
    md = RuleMetadata(
        owner="secops@example.com",
        runbookUrl="https://runbooks.example.com/x",
        severity="medium",
        tactics=["InitialAccess"],
        techniques=["T1078"],
        expectedAlertsPerDay=2,
        fpHandling="Investigate via SIEM portal.",
    )
    assert md.severity == "medium"


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def test_references_accepts_https_urls() -> None:
    md = _full_metadata(references=[
        "https://attack.mitre.org/techniques/T1059/",
        "https://nvd.nist.gov/vuln/detail/CVE-2024-0001",
    ])
    assert len(md.references) == 2


def test_references_accepts_http_urls() -> None:
    md = _full_metadata(references=["http://example.com/legacy-link"])
    assert md.references == ["http://example.com/legacy-link"]


def test_references_rejects_bare_word() -> None:
    with pytest.raises(ValidationError, match="http://"):
        _full_metadata(references=["CVE-2024-0001"])


def test_references_rejects_file_scheme() -> None:
    with pytest.raises(ValidationError, match="http://"):
        _full_metadata(references=["file:///tmp/local.html"])


def test_references_empty_list_is_valid() -> None:
    """Empty references is fine at the model layer — the META004 lint
    rule is where 'you should add references' is surfaced."""
    md = _full_metadata(references=[])
    assert md.references == []


# ---------------------------------------------------------------------------
# Free-text fields accept any non-typo'd string
# ---------------------------------------------------------------------------


def test_description_accepts_paragraph() -> None:
    md = _full_metadata(description="Detects suspicious LSASS access patterns.")
    assert md.description.startswith("Detects")


def test_attack_description_accepts_paragraph() -> None:
    md = _full_metadata(attackDescription=(
        "Attackers inject into LSASS to extract NTLM hashes for "
        "lateral movement via pass-the-hash."
    ))
    assert "lateral movement" in md.attackDescription


# ---------------------------------------------------------------------------
# List-type fields accept any string entries (no per-item format yet)
# ---------------------------------------------------------------------------


def test_false_positives_accept_any_strings() -> None:
    md = _full_metadata(falsePositives=[
        "Domain controllers running scheduled Kerberos hygiene scripts.",
        "Citrix VDA agent issuing internal LDAP probes during user logon.",
    ])
    assert len(md.falsePositives) == 2


def test_blind_spots_accept_any_strings() -> None:
    md = _full_metadata(blindSpots=[
        "Misses inline reflection — see T1620.",
        "Cannot detect when attackers proxy through legit ADWS sessions.",
    ])
    assert len(md.blindSpots) == 2


def test_response_actions_accept_any_strings() -> None:
    md = _full_metadata(responseActions=[
        "Disable the affected user account.",
        "Force device wipe via Intune.",
        "Snapshot the host for forensic review.",
    ])
    assert len(md.responseActions) == 3


# ---------------------------------------------------------------------------
# Model posture: extra=forbid and frozen still hold
# ---------------------------------------------------------------------------


def test_extra_field_typo_is_rejected() -> None:
    """If an author misspells ``falsePositives`` as ``falsePositiv``,
    Pydantic must catch it rather than silently dropping the data."""
    with pytest.raises(ValidationError):
        RuleMetadata(
            owner="secops@example.com",
            runbookUrl="https://runbooks.example.com/x",
            severity="low",
            tactics=["Execution"],
            techniques=[],
            expectedAlertsPerDay=1,
            fpHandling="x",
            falsePositiv=["typo"],  # intentional misspelling  # type: ignore[arg-type]
        )


def test_frozen_model_rejects_post_construction_mutation() -> None:
    md = _full_metadata()
    with pytest.raises(ValidationError):
        md.description = "trying to mutate after the fact"  # type: ignore[misc]
