# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for the three Navigator extractors + the scoring aggregator."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from contentops.navigator.extract import (
    ScoredTechnique,
    TechniqueHit,
    extract_defender_rule_techniques,
    extract_firing_techniques,
    extract_repo_techniques,
    extract_sentinel_rule_techniques,
    firing_techniques_query,
    score_techniques,
)


# ---------------------------------------------------------------------------
# extract_repo_techniques
# ---------------------------------------------------------------------------


def _base_meta(**overrides):
    base = dict(
        owner="x@example.com",
        runbookUrl="https://example.com/r",
        severity="medium",
        tactics=["Execution"],
        techniques=["T1059", "T1059.001"],
        expectedAlertsPerDay=0,
        fpHandling="placeholder",
    )
    base.update(overrides)
    return base


def _fake_detections(tmp_path: Path, *envelopes: dict) -> Path:
    root = tmp_path / "detections" / "sentinel_analytic"
    root.mkdir(parents=True)
    for i, env in enumerate(envelopes):
        (root / f"rule-{i}.yml").write_text(yaml.safe_dump(env), encoding="utf-8")
    return tmp_path / "detections"


def test_repo_extractor_pulls_metadata_techniques(tmp_path: Path) -> None:
    detections = _fake_detections(
        tmp_path,
        {
            "id": "rule-a",
            "version": "0.1.0",
            "asset": "sentinel_analytic",
            "status": "production",
            "metadata": _base_meta(
                description="Rule A description",
                techniques=["T1059", "T1059.001"],
            ),
            "payload": {"query": "T", "displayName": "Rule A", "queryFrequency": "PT5M",
                        "queryPeriod": "PT5M", "triggerOperator": "GreaterThan",
                        "triggerThreshold": 0, "severity": "Medium", "enabled": True,
                        "tactics": [], "subTechniques": []},
        },
    )
    hits = extract_repo_techniques(detections)
    technique_ids = sorted(h.technique_id for h in hits)
    assert technique_ids == ["T1059", "T1059.001"]
    assert all(h.source == "repo" for h in hits)
    # The payload displayName is the display key -- the same key the
    # deployed axis uses (review finding C11), not the description.
    assert all(h.display_name == "Rule A" for h in hits)


def test_repo_extractor_falls_back_to_envelope_id_without_display_name(tmp_path: Path) -> None:
    detections = _fake_detections(
        tmp_path,
        {
            "id": "rule-b",
            "version": "0.1.0",
            "asset": "sentinel_analytic",
            "status": "production",
            "metadata": _base_meta(techniques=["T1078"]),
            "payload": {"query": "T", "queryFrequency": "PT5M",
                        "queryPeriod": "PT5M", "triggerOperator": "GreaterThan",
                        "triggerThreshold": 0, "severity": "Medium", "enabled": True,
                        "tactics": [], "subTechniques": []},
        },
    )
    hits = extract_repo_techniques(detections)
    assert hits[0].display_name == "rule-b"


# ---------------------------------------------------------------------------
# extract_sentinel_rule_techniques
# ---------------------------------------------------------------------------


def _make_stub_response(body: dict, status: int = 200):
    return SimpleNamespace(
        status_code=status,
        text="" if status == 200 else "boom",
        json=lambda: body,
    )


class _StubArmProvider:
    """Duck-typed SentinelArmProvider stub: the extractor only calls
    ``list_resource`` (which paginates in the real provider)."""

    def __init__(self, body: dict, status: int = 200):
        self._body = body
        self._status = status
        self.listed: list[str] = []

    def list_resource(self, resource_type: str) -> list[dict]:
        self.listed.append(resource_type)
        if self._status >= 400:
            raise RuntimeError(f"ARM GET {resource_type} returned {self._status}")
        return list(self._body.get("value") or [])

    def close(self) -> None:
        pass


def test_sentinel_extractor_reads_properties_techniques() -> None:
    provider = _StubArmProvider({
        "value": [
            {
                "name": "abc",
                "properties": {
                    "displayName": "BruteForce SSH",
                    "techniques": ["T1110", "T1110.001"],
                },
            },
        ],
    })
    hits = extract_sentinel_rule_techniques(provider)
    assert len(hits) == 2
    assert all(h.source == "deployed" for h in hits)
    assert all(h.display_name == "BruteForce SSH" for h in hits)
    assert {h.technique_id for h in hits} == {"T1110", "T1110.001"}


def test_sentinel_extractor_skips_rules_without_techniques() -> None:
    provider = _StubArmProvider({
        "value": [
            {"name": "x", "properties": {"displayName": "X"}},  # no techniques
        ],
    })
    assert extract_sentinel_rule_techniques(provider) == []


def test_sentinel_extractor_raises_on_4xx() -> None:
    provider = _StubArmProvider({}, status=403)
    with pytest.raises(RuntimeError) as exc:
        extract_sentinel_rule_techniques(provider)
    assert "403" in str(exc.value)


# ---------------------------------------------------------------------------
# extract_defender_rule_techniques
# ---------------------------------------------------------------------------


class _StubDefenderClient:
    def __init__(self, rules: list[dict]):
        self._rules = rules

    def list_rules(self) -> list[dict]:
        return self._rules

    def close(self) -> None:
        pass


def test_defender_extractor_reads_mitre_techniques() -> None:
    client = _StubDefenderClient([
        {
            "id": "1",
            "displayName": "Mailbox Forwarding Anomaly",
            "detectionAction": {
                "alertTemplate": {
                    "mitreTechniques": ["T1114", "T1114.003"],
                },
            },
        },
    ])
    hits = extract_defender_rule_techniques(client)
    assert {h.technique_id for h in hits} == {"T1114", "T1114.003"}
    assert all(h.display_name == "Mailbox Forwarding Anomaly" for h in hits)


def test_defender_extractor_handles_missing_alert_template() -> None:
    client = _StubDefenderClient([
        {"id": "1", "displayName": "Empty"},  # no detectionAction
    ])
    assert extract_defender_rule_techniques(client) == []


# ---------------------------------------------------------------------------
# extract_firing_techniques + firing_techniques_query
# ---------------------------------------------------------------------------


def test_firing_query_filters_sentinel_native_and_custom_detection() -> None:
    """The query MUST exclude Sentinel-native alerts (axis 2 already
    counts those via ARM) and Defender CustomDetection alerts (also
    axis 2 via Graph). Otherwise the score double-counts."""
    kql = firing_techniques_query(since_days=30)
    assert '"Azure Sentinel"' in kql
    assert '"CustomDetection"' in kql
    assert "30d" in kql
    assert "mv-expand" in kql
    assert "parse_json(Techniques)" in kql


def test_firing_extractor_translates_rows_to_hits() -> None:
    from contentops.workspace_kql import QueryResult

    captured: dict[str, object] = {}

    def runner(kql, *, workspace_id, token):
        captured["kql"] = kql
        captured["workspace_id"] = workspace_id
        captured["token"] = token
        return QueryResult(
            rows=[
                {"technique_id": "T1059", "display_name": "Suspicious PowerShell"},
                {"technique_id": "T1110", "display_name": "Password Spray"},
            ],
            column_names=["technique_id", "display_name"],
        )

    hits = extract_firing_techniques(
        workspace_id="00000000-0000-0000-0000-000000000000",
        token="tok",
        since_days=7,
        query_runner=runner,
    )
    assert captured["workspace_id"] == "00000000-0000-0000-0000-000000000000"
    assert captured["token"] == "tok"
    assert "7d" in captured["kql"]
    assert [h.technique_id for h in hits] == ["T1059", "T1110"]
    assert all(h.source == "firings" for h in hits)


# ---------------------------------------------------------------------------
# score_techniques
# ---------------------------------------------------------------------------


def test_score_counts_unique_display_names_per_technique() -> None:
    """Same technique covered by three different rules -> score 3."""
    hits = [
        TechniqueHit("T1059", "rule-A", "repo"),
        TechniqueHit("T1059", "rule-B", "deployed"),
        TechniqueHit("T1059", "rule-C", "firings"),
        TechniqueHit("T1110", "rule-D", "repo"),
    ]
    scored = score_techniques(hits)
    by_id = {s.technique_id: s for s in scored}
    assert by_id["T1059"].score == 3
    assert by_id["T1110"].score == 1


def test_score_deduplicates_same_rule_across_axes() -> None:
    """A rule named X covering T1059 from both 'repo' and 'firings'
    counts ONCE on the technique's score (one unique display name).
    The per-axis breakdown still records the contribution per side."""
    hits = [
        TechniqueHit("T1059", "rule-A", "repo"),
        TechniqueHit("T1059", "rule-A", "firings"),
    ]
    scored = score_techniques(hits)
    assert scored[0].score == 1
    assert scored[0].repo_count == 1
    assert scored[0].firings_count == 1


def test_score_adds_parent_technique_with_zero_score() -> None:
    """Sub-technique covered but parent not directly -> parent appears
    at score 0 so the Navigator UI renders the parent tile."""
    hits = [
        TechniqueHit("T1059.001", "rule-A", "repo"),
    ]
    scored = score_techniques(hits)
    ids = {s.technique_id for s in scored}
    assert ids == {"T1059", "T1059.001"}
    parent = next(s for s in scored if s.technique_id == "T1059")
    assert parent.score == 0
    assert parent.repo_count == 0


def test_score_keeps_existing_parent_score_when_both_present() -> None:
    """If both T1059 and T1059.001 have hits, the parent doesn't get
    overwritten by a synthetic zero-score entry."""
    hits = [
        TechniqueHit("T1059", "rule-A", "repo"),
        TechniqueHit("T1059.001", "rule-B", "repo"),
    ]
    scored = score_techniques(hits)
    parent = next(s for s in scored if s.technique_id == "T1059")
    assert parent.score == 1


def test_score_output_is_sorted() -> None:
    """Deterministic ordering -- consumers can rely on it."""
    hits = [
        TechniqueHit("T1110", "x", "repo"),
        TechniqueHit("T1059", "y", "repo"),
    ]
    scored = score_techniques(hits)
    assert [s.technique_id for s in scored] == ["T1059", "T1110"]



# ---------------------------------------------------------------------------
# Review regressions: C10 / C11 / C12
# ---------------------------------------------------------------------------


def test_repo_axis_reads_payload_only_collected_rules(tmp_path: Path) -> None:
    """C10: collected rules carry ATT&CK tags only in the payload."""
    detections = _fake_detections(tmp_path, {
        "id": "collected-rule", "version": "1.0.0", "asset": "sentinel_analytic",
        "status": "production", "metadata": {"arm_name": "0f1e2d3c-0000-4000-8000-000000000001"},
        "payload": {"displayName": "Collected", "query": "T", "enabled": True,
                    "tactics": ["CredentialAccess"], "techniques": ["T1110"],
                    "subTechniques": ["T1110.003"]},
    })
    hits = extract_repo_techniques(detections)
    assert sorted(h.technique_id for h in hits) == ["T1110", "T1110.003"]


def test_repo_axis_matches_the_coverage_badge(coverage_corpus) -> None:
    from contentops.coverage import load_corpus

    covered = load_corpus(coverage_corpus).covered()
    hits = {h.technique_id for h in extract_repo_techniques(coverage_corpus)}
    parents = {t.split(".", 1)[0] for t in hits}
    assert parents == set(covered.techniques)
    assert {t for t in hits if "." in t} == set(covered.sub_techniques)


def test_repo_axis_honours_the_scope(coverage_corpus) -> None:
    from contentops.coverage import CoverageScope

    default = {h.technique_id for h in extract_repo_techniques(coverage_corpus)}
    assert "T1003" not in default and "T1021" not in default
    widened = {h.technique_id for h in extract_repo_techniques(
        coverage_corpus,
        scope=CoverageScope.from_flags(include_non_production=True, include_hunting=True),
    )}
    assert {"T1003", "T1021"} <= widened
    assert "T1486" not in widened  # disabled never counts


def test_same_rule_on_repo_and_deployed_axes_scores_once(tmp_path: Path) -> None:
    """C11: the repo and deployed axes key on the same display name."""
    detections = _fake_detections(tmp_path, {
        "id": "brute-force", "version": "1.0.0", "asset": "sentinel_analytic",
        "status": "production",
        "metadata": _base_meta(description="Long description first line",
                               tactics=["CredentialAccess"], techniques=["T1110"]),
        "payload": {"displayName": "Brute Force", "query": "T", "enabled": True},
    })
    provider = _StubArmProvider({"value": [
        {"name": "g1", "properties": {"displayName": "Brute Force", "enabled": True,
                                      "techniques": ["T1110"]}},
    ]})
    hits = extract_repo_techniques(detections) + extract_sentinel_rule_techniques(provider)
    scored = {s.technique_id: s for s in score_techniques(hits)}
    assert scored["T1110"].score == 1
    assert scored["T1110"].repo_count == 1 and scored["T1110"].deployed_count == 1


def test_sentinel_extractor_lists_every_page_and_reads_sub_techniques() -> None:
    """C12: list_resource (paginated) + subTechniques."""
    provider = _StubArmProvider({"value": [
        {"name": f"r{i}", "properties": {"displayName": f"Rule {i}", "enabled": True,
                                         "techniques": ["T1110"],
                                         "subTechniques": ["T1110.001"]}}
        for i in range(3)
    ]})
    hits = extract_sentinel_rule_techniques(provider)
    assert provider.listed == ["alertRules"]
    assert {h.technique_id for h in hits} == {"T1110", "T1110.001"}
    assert len({h.display_name for h in hits}) == 3


def test_disabled_deployed_rules_are_skipped() -> None:
    provider = _StubArmProvider({"value": [
        {"name": "on", "properties": {"displayName": "On", "enabled": True, "techniques": ["T1059"]}},
        {"name": "off", "properties": {"displayName": "Off", "enabled": False, "techniques": ["T1486"]}},
    ]})
    assert {h.technique_id for h in extract_sentinel_rule_techniques(provider)} == {"T1059"}
    assert {h.technique_id for h in extract_sentinel_rule_techniques(
        provider, include_disabled=True)} == {"T1059", "T1486"}
    client = _StubDefenderClient([
        {"id": "1", "displayName": "On", "status": "enabled",
         "detectionAction": {"alertTemplate": {"mitreTechniques": ["T1018"]}}},
        {"id": "2", "displayName": "Auto", "status": "autoDisabled",
         "detectionAction": {"alertTemplate": {"mitreTechniques": ["T1046"]}}},
    ])
    assert {h.technique_id for h in extract_defender_rule_techniques(client)} == {"T1018"}


def test_deployed_and_firing_ids_are_normalised_and_remapped() -> None:
    provider = _StubArmProvider({"value": [
        {"name": "m", "properties": {"displayName": "Messy", "enabled": True,
                                     "techniques": [" t1059", "T9999", "bogus"],
                                     "subTechniques": ["T1562.001"]}},
    ]})
    assert {h.technique_id for h in extract_sentinel_rule_techniques(provider)} == {
        "T1059", "T1685",
    }
