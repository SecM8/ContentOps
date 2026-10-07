# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for ``contentops.coverage.extract`` -- the per-asset
payload-derived MITRE extractor.

Three layers:
* Per-asset payload reader unit tests (Defender / Sentinel analytic /
  Sentinel hunting).
* Top-level ``extract_mitre`` tests covering the metadata + payload
  merge semantics.
* Edge cases: case-normalisation, unknown severity, technique without
  curated tactic mapping, non-detection asset.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from contentops.core.asset import Asset
from contentops.core.envelope import EnvelopeV2, parse_envelope
from contentops.core.metadata import RuleMetadata
from contentops.coverage.extract import ExtractedCoverage, extract_mitre


REPO_ROOT = Path(__file__).resolve().parents[2]


def _envelope(asset: Asset, *, metadata: RuleMetadata | None = None) -> EnvelopeV2:
    return EnvelopeV2(
        id="rule-x",
        version="1.0.0",
        asset=asset,
        status="production",
        metadata=metadata,
    )


def _meta(**overrides) -> RuleMetadata:
    base = {
        "owner": "blue@contoso.com",
        "runbookUrl": "https://wiki/runbook",
        "severity": "high",
        "tactics": ["InitialAccess"],
        "techniques": ["T1059"],
        "expectedAlertsPerDay": 1,
        "fpHandling": "n/a",
    }
    base.update(overrides)
    return RuleMetadata(**base)


# ---------------------------------------------------------------------------
# Defender payload reader
# ---------------------------------------------------------------------------


def test_defender_extracts_techniques_severity_and_derives_tactics() -> None:
    """The bundled curated MITRE map covers T1018 -> Discovery, so a
    Defender envelope carrying T1018 must produce that tactic."""
    payload = {
        "detectionAction": {
            "alertTemplate": {
                "mitreTechniques": ["T1018"],
                "severity": "medium",
                "category": "Discovery",
            }
        }
    }
    cov = extract_mitre(_envelope(Asset.DEFENDER_CUSTOM_DETECTION), payload)
    assert "T1018" in cov.techniques
    assert "Discovery" in cov.tactics
    assert cov.severity == "medium"


def test_defender_falls_back_to_category_when_techniques_unmapped() -> None:
    """A technique outside the curated list contributes nothing to
    tactic counts via the map; if ``alertTemplate.category`` happens to
    be a canonical tactic name, the extractor uses it as a fallback."""
    payload = {
        "detectionAction": {
            "alertTemplate": {
                "mitreTechniques": ["T9999"],   # not in curated map
                "severity": "low",
                "category": "Persistence",       # canonical tactic
            }
        }
    }
    cov = extract_mitre(_envelope(Asset.DEFENDER_CUSTOM_DETECTION), payload)
    assert "T9999" in cov.techniques
    assert cov.tactics == ("Persistence",)
    # The category supplies the tactic, but T9999 is not an ATT&CK id: it
    # is reported (review finding C7) and never counted.
    assert cov.techniques_without_tactic == ("T9999",)
    assert cov.unknown_ids == ("T9999",)
    assert cov.counted_techniques == ()


def test_defender_orphan_technique_is_surfaced() -> None:
    """When the technique is not in the curated map AND the category
    is not a canonical tactic, the technique is surfaced as an orphan
    so the operator can extend the curated list."""
    payload = {
        "detectionAction": {
            "alertTemplate": {
                "mitreTechniques": ["T9999"],
                "severity": "high",
                "category": "Suspicious Activity",  # not a tactic
            }
        }
    }
    cov = extract_mitre(_envelope(Asset.DEFENDER_CUSTOM_DETECTION), payload)
    assert cov.techniques_without_tactic == ("T9999",)
    assert cov.tactics == ()


def test_defender_handles_missing_alert_template_gracefully() -> None:
    """A malformed / partial payload must not raise; returns an empty triple."""
    cov = extract_mitre(_envelope(Asset.DEFENDER_CUSTOM_DETECTION), {})
    assert cov.tactics == ()
    assert cov.techniques == ()
    assert cov.severity == "informational"  # default


# ---------------------------------------------------------------------------
# Sentinel analytic payload reader
# ---------------------------------------------------------------------------


def test_sentinel_analytic_extracts_native_payload_fields() -> None:
    payload = {
        "tactics": ["Execution", "Persistence"],
        "techniques": ["T1059", "T1547"],
        "severity": "Medium",  # TitleCase from Sentinel API
    }
    cov = extract_mitre(_envelope(Asset.SENTINEL_ANALYTIC), payload)
    assert "Execution" in cov.tactics
    assert "Persistence" in cov.tactics
    assert "T1059" in cov.techniques
    assert "T1547" in cov.techniques
    # TitleCase normalised to lowercase canonical.
    assert cov.severity == "medium"


def test_sentinel_analytic_filters_unknown_tactic() -> None:
    """A non-canonical tactic value is dropped (would otherwise blow
    up downstream bucket lookups)."""
    payload = {
        "tactics": ["Execution", "BogusTactic"],
        "techniques": ["T1059"],
        "severity": "Low",
    }
    cov = extract_mitre(_envelope(Asset.SENTINEL_ANALYTIC), payload)
    assert cov.tactics == ("Execution",)
    assert "BogusTactic" not in cov.tactics


def test_sentinel_analytic_accepts_arm_only_tactics() -> None:
    """The ARM ``alertRules`` API enum includes 3 tactic values
    outside the 14-tactic ATT&CK Enterprise list: ``PreAttack``
    (legacy templates), ``ImpairProcessControl`` and
    ``InhibitResponseFunction`` (ICS/OT). The extractor must accept
    them so Sentinel rules carrying them aren't silently dropped.
    Regression for siem-security-architect-reviewer L1 finding on
    PR #153."""
    payload = {
        "tactics": ["PreAttack", "ImpairProcessControl", "InhibitResponseFunction"],
        "techniques": ["T1583"],
        "severity": "High",
    }
    cov = extract_mitre(_envelope(Asset.SENTINEL_ANALYTIC), payload)
    assert "PreAttack" in cov.tactics
    assert "ImpairProcessControl" in cov.tactics
    assert "InhibitResponseFunction" in cov.tactics


# ---------------------------------------------------------------------------
# Sentinel hunting payload reader
# ---------------------------------------------------------------------------


def test_sentinel_hunting_defaults_severity_to_informational() -> None:
    """Hunting queries don't carry a severity; the extractor defaults
    so the per-tactic severity histogram still renders."""
    payload = {
        "tactics": ["Discovery"],
        "techniques": ["T1018"],
    }
    cov = extract_mitre(_envelope(Asset.SENTINEL_HUNTING), payload)
    assert cov.severity == "informational"
    assert cov.tactics == ("Discovery",)


# ---------------------------------------------------------------------------
# Metadata + payload merge semantics
# ---------------------------------------------------------------------------


def test_metadata_only_path_returns_metadata_values() -> None:
    """Envelope with rich metadata but empty payload produces the
    metadata triple unchanged."""
    cov = extract_mitre(
        _envelope(Asset.SENTINEL_ANALYTIC, metadata=_meta(
            severity="high",
            tactics=["InitialAccess"],
            techniques=["T1190"],
        )),
        payload={},  # no payload-side data
    )
    assert cov.tactics == ("InitialAccess",)
    assert cov.techniques == ("T1190",)
    assert cov.severity == "high"


def test_metadata_and_payload_union_tactics_and_techniques() -> None:
    """When both sources have data the extractor unions them so
    authored content is not silently dropped."""
    cov = extract_mitre(
        _envelope(Asset.SENTINEL_ANALYTIC, metadata=_meta(
            severity="high",
            tactics=["InitialAccess"],
            techniques=["T1190"],
        )),
        payload={
            "tactics": ["Execution"],
            "techniques": ["T1059"],
            "severity": "Low",
        },
    )
    # Union of both sources, sorted.
    assert cov.tactics == ("Execution", "InitialAccess")
    assert cov.techniques == ("T1059", "T1190")
    # Metadata severity wins over payload severity.
    assert cov.severity == "high"


def test_payload_severity_used_when_metadata_absent() -> None:
    cov = extract_mitre(
        _envelope(Asset.SENTINEL_ANALYTIC),  # no metadata
        payload={
            "tactics": ["Execution"],
            "techniques": ["T1059"],
            "severity": "high",
        },
    )
    assert cov.severity == "high"


# ---------------------------------------------------------------------------
# Asset-kind gating + edge cases
# ---------------------------------------------------------------------------


def test_non_detection_asset_returns_empty() -> None:
    """Watchlists / parsers / data-connectors don't carry MITRE data --
    extractor returns empty triple regardless of payload."""
    cov = extract_mitre(_envelope(Asset.SENTINEL_WATCHLIST), payload={"foo": "bar"})
    assert cov.tactics == ()
    assert cov.techniques == ()


def test_unknown_severity_value_falls_back_to_default() -> None:
    """An unrecognised severity (e.g. "critical") doesn't crash; the
    extractor returns the canonical default so the per-tactic
    histogram still renders."""
    payload = {
        "detectionAction": {
            "alertTemplate": {
                "mitreTechniques": ["T1018"],
                "severity": "Critical",  # not in canonical set
                "category": "Discovery",
            }
        }
    }
    cov = extract_mitre(_envelope(Asset.DEFENDER_CUSTOM_DETECTION), payload)
    assert cov.severity == "informational"


# ---------------------------------------------------------------------------
# Real-corpus pin: the on-disk T1018 detection must produce non-zero
# Discovery coverage. If this fails, the extractor wiring is broken
# even if the unit tests pass.
# ---------------------------------------------------------------------------


def test_real_t1018_detection_produces_discovery_tactic() -> None:
    """Pin against an actual corpus envelope so wiring breakage
    surfaces immediately. ``t1018-remote-system-discovery.yml`` is a
    representative collected Defender detection: it has the typical
    skeleton ``metadata: {arm_name: ...}`` and stores the MITRE
    technique in payload.detectionAction.alertTemplate.mitreTechniques.
    """
    fixture = (
        REPO_ROOT
        / "detections"
        / "defender_custom_detection"
        / "t1018-remote-system-discovery.yml"
    )
    if not fixture.exists():
        pytest.skip(f"corpus fixture not present: {fixture}")

    raw = yaml.safe_load(fixture.read_text(encoding="utf-8"))
    envelope, payload = parse_envelope(raw)
    cov = extract_mitre(envelope, payload)

    assert "T1018" in cov.techniques
    assert "Discovery" in cov.tactics
    assert cov.severity in ("medium", "high", "low", "informational")


# ---------------------------------------------------------------------------
# Review regressions (C1, C2, C6, C7, C8, revoked ids)
# ---------------------------------------------------------------------------


def test_sentinel_sub_techniques_are_read() -> None:
    """C1: Sentinel stores sub-techniques in ``subTechniques``."""
    cov = extract_mitre(_envelope(Asset.SENTINEL_ANALYTIC), {
        "tactics": ["CredentialAccess"], "techniques": ["T1110"],
        "subTechniques": ["T1110.001", "T1110.003"],
    })
    assert cov.techniques == ("T1110", "T1110.001", "T1110.003")
    assert cov.techniques_for("CredentialAccess") == ("T1110", "T1110.001", "T1110.003")


def test_technique_ids_are_normalised_validated_and_deduped() -> None:
    """C7: messy ids are normalised; malformed ones are reported, never kept."""
    cov = extract_mitre(_envelope(Asset.SENTINEL_ANALYTIC), {
        "tactics": ["Discovery"],
        "techniques": [" T1082", "t1087", "T1087", "T10", "bogus", "T9999"],
    })
    assert cov.techniques == ("T1082", "T1087", "T9999")
    assert cov.counted_techniques == ("T1082", "T1087")
    assert cov.invalid_ids == ("T10", "bogus")
    assert cov.unknown_ids == ("T9999",)
    # Sentinel rules now report unmapped techniques too.
    assert cov.techniques_without_tactic == ("T9999",)


def test_techniques_are_listed_only_under_their_own_tactics() -> None:
    """C2: a technique is attributed to a tactic only if ATT&CK files it there."""
    cov = extract_mitre(_envelope(Asset.SENTINEL_ANALYTIC), {
        "tactics": ["Execution", "CredentialAccess"], "techniques": ["T1059", "T1110"],
    })
    assert cov.techniques_for("Execution") == ("T1059",)
    assert cov.techniques_for("CredentialAccess") == ("T1110",)
    assert cov.techniques_without_tactic == ()


def test_defender_category_is_the_tactic_not_every_technique_tactic() -> None:
    """C8: T1078 spans four tactics; the alert category claims one."""
    cov = extract_mitre(_envelope(Asset.DEFENDER_CUSTOM_DETECTION), {
        "detectionAction": {"alertTemplate": {
            "mitreTechniques": ["T1078"], "category": "InitialAccess", "severity": "low",
        }},
    })
    assert cov.tactics == ("InitialAccess",)
    assert cov.techniques_for("InitialAccess") == ("T1078",)
    assert cov.tactics_inferred is False


def test_rule_without_tactics_infers_them_from_techniques() -> None:
    """A Defender non-tactic category (or a Sentinel rule with no tactics)
    gets its tactics from the matrix, flagged as inferred."""
    cov = extract_mitre(_envelope(Asset.DEFENDER_CUSTOM_DETECTION), {
        "detectionAction": {"alertTemplate": {
            "mitreTechniques": ["T1018"], "category": "SuspiciousActivity",
        }},
    })
    assert cov.tactics == ("Discovery",)
    assert cov.tactics_inferred is True
    sentinel = extract_mitre(_envelope(Asset.SENTINEL_ANALYTIC), {"techniques": ["T1046"]})
    assert sentinel.tactics == ("Discovery",) and sentinel.tactics_inferred


def test_raw_metadata_is_salvaged_when_strict_metadata_failed() -> None:
    """C6: tags in a metadata block that failed strict validation still count."""
    cov = extract_mitre(
        _envelope(Asset.SENTINEL_ANALYTIC),  # strict parse produced no metadata
        {"query": "T | take 1"},
        raw_metadata={"owner": "x@y.z", "tactics": ["Impact"],
                      "techniques": ["T1486"], "severity": "High",
                      "references": ["ftp://bad"]},
    )
    assert cov.tactics == ("Impact",)
    assert cov.techniques == ("T1486",)
    assert cov.severity == "high"


def test_strict_metadata_wins_over_raw_metadata() -> None:
    cov = extract_mitre(
        _envelope(Asset.SENTINEL_ANALYTIC, metadata=_meta(tactics=["Execution"],
                                                           techniques=["T1059"])),
        {}, raw_metadata={"tactics": ["Impact"], "techniques": ["T1486"]},
    )
    assert cov.techniques == ("T1059",)


def test_revoked_ids_are_remapped_to_their_successor() -> None:
    cov = extract_mitre(_envelope(Asset.SENTINEL_ANALYTIC), {
        "tactics": ["DefenseEvasion"], "techniques": ["T1562"],
        "subTechniques": ["T1562.001"],
    })
    assert ("T1562.001", "T1685") in cov.remapped_ids
    assert cov.counted_techniques == ("T1685",)
    assert cov.techniques_for("DefenseEvasion") == ("T1685",)


def test_extractor_uses_an_injected_matrix() -> None:
    from contentops.coverage.matrix import AttackMatrix

    matrix = AttackMatrix.from_dict({
        "attack_version": "1.0",
        "tactics": [{"id": "Execution"}],
        "techniques": [{"id": "T0001", "name": "x", "tactics": ["Execution"]}],
        "sub_techniques": [],
        "revoked": {"T0002": "T0001"},
    })
    cov = extract_mitre(_envelope(Asset.SENTINEL_ANALYTIC),
                        {"techniques": ["T0002", "T1059"]}, matrix=matrix)
    assert cov.counted_techniques == ("T0001",)
    assert cov.unknown_ids == ("T1059",)
