# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Snapshot test for the drift auto-PR body renderer.

Asserts the Markdown layout is stable: any change to wording, columns,
or ordering will be visible to a reviewer rather than silently shipping
to GitHub. The expected snapshot lives inline so reviewers see the
delta in the diff itself.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from contentops.upstream.drift_pr import (
    DriftEntrySummary,
    DriftReportSummary,
    SuppressionSummary,
    collect_owners,
    labels_for,
    parse_report,
    render_pr_body,
)


def _fabricated_report() -> DriftReportSummary:
    return DriftReportSummary(
        tenant="production",
        workspace="law-sentinel",
        run_id="12345",
        entries=[
            DriftEntrySummary(asset="sentinel_analytic", id="brute-force-001", kind="new"),
            DriftEntrySummary(asset="sentinel_hunting", id="anomalous-rdp", kind="changed"),
            DriftEntrySummary(asset="defender_custom_detection", id="defender-cred-dump", kind="changed"),
        ],
    )


def test_render_pr_body_snapshot() -> None:
    body = render_pr_body(
        _fabricated_report(),
        id_to_owner={
            "brute-force-001": "team-soc@example.com",
            "anomalous-rdp": "team-soc@example.com",
            "defender-cred-dump": "team-platform@example.com",
        },
    )
    expected = (
        "## Drift detected\n"
        "\n"
        "This PR was opened automatically by the `drift` workflow. "
        "It contains content found in the live Microsoft Sentinel / "
        "Defender XDR tenant that does not match the YAML in this repository.\n"
        "\n"
        "| Field | Value |\n"
        "| --- | --- |\n"
        "| Tenant | `production` |\n"
        "| Workspace | `law-sentinel` |\n"
        "| Workflow run | `12345` |\n"
        "| New assets | 1 |\n"
        "| Changed assets | 2 |\n"
        "| Suppressed | 0 |\n"
        "\n"
        "### New (1)\n"
        "| Asset | ID |\n"
        "| --- | --- |\n"
        "| `sentinel_analytic` | `brute-force-001` |\n"
        "\n"
        "### Changed (2)\n"
        "| Asset | ID |\n"
        "| --- | --- |\n"
        "| `defender_custom_detection` | `defender-cred-dump` |\n"
        "| `sentinel_hunting` | `anomalous-rdp` |\n"
        "\n"
        "### Owner checklist\n"
        "- [ ] @team-platform — `defender-cred-dump`\n"
        "- [ ] @team-soc — `anomalous-rdp`, `brute-force-001`\n"
        "\n"
        "---\n"
        "Review each file carefully. Merge to accept the upstream change, "
        "or close + run `contentops apply` to push the local state back.\n"
    )
    assert body == expected


def test_labels_includes_per_asset_kind() -> None:
    labels = labels_for(_fabricated_report())
    assert labels == sorted({
        "drift", "automated",
        "asset:sentinel_analytic",
        "asset:sentinel_hunting",
        "asset:defender_custom_detection",
    })


def test_render_pr_body_handles_empty_owners() -> None:
    body = render_pr_body(_fabricated_report(), id_to_owner={})
    assert "_No owners parsed from envelope metadata._" in body


def test_render_pr_body_renders_suppression_sections() -> None:
    report = DriftReportSummary(
        tenant="production",
        workspace="law-sentinel",
        run_id="12345",
        entries=[
            DriftEntrySummary(asset="sentinel_analytic", id="expired-rule", kind="changed"),
        ],
        suppressed=[
            SuppressionSummary(asset="sentinel_analytic", id="tuned-rule"),
        ],
        expired=[
            SuppressionSummary(asset="sentinel_analytic", id="expired-rule"),
        ],
        unused=[
            SuppressionSummary(asset="defender_custom_detection", id="dead-entry", expires="2026-01-01"),
        ],
    )
    body = render_pr_body(report, id_to_owner={})
    # Summary row reflects the suppressed count.
    assert "| Suppressed | 1 |" in body
    # Expired + unused get their own callout sections.
    assert "### Expired suppressions (1)" in body
    assert "| `sentinel_analytic` | `expired-rule` |" in body
    assert "### Unused suppressions (1)" in body
    assert "| `defender_custom_detection` | `dead-entry` | 2026-01-01 |" in body


def test_render_pr_body_omits_suppression_sections_when_empty() -> None:
    # The common case (no expired/unused) stays uncluttered: only the
    # count row is present, no Expired/Unused headers.
    body = render_pr_body(_fabricated_report(), id_to_owner={})
    assert "| Suppressed | 0 |" in body
    assert "Expired suppressions" not in body
    assert "Unused suppressions" not in body


def test_parse_report_reads_suppression_keys() -> None:
    raw = {
        "tenant": "t", "workspace": "w", "run_id": "1",
        "entries": [{"asset": "sentinel_analytic", "id": "a", "kind": "new"}],
        "suppressed": [{"asset": "sentinel_analytic", "id": "s"}],
        "expired": [{"asset": "sentinel_analytic", "id": "e"}],
        "unused": [{"asset": "sentinel_parser", "id": "u", "expires": "2026-02-02"}],
    }
    report = parse_report(raw)
    assert [s.id for s in report.suppressed] == ["s"]
    assert [s.id for s in report.expired] == ["e"]
    assert report.unused[0].expires == "2026-02-02"


def test_parse_report_tolerates_missing_suppression_keys() -> None:
    # A report written before the F15 schema bump has no suppression keys.
    raw = {
        "tenant": "t", "workspace": "w", "run_id": "1",
        "entries": [{"asset": "sentinel_analytic", "id": "a", "kind": "new"}],
    }
    report = parse_report(raw)
    assert report.suppressed == []
    assert report.expired == []
    assert report.unused == []


def test_collect_owners_walks_yaml(tmp_path: Path) -> None:
    detections = tmp_path / "detections"
    (detections / "sentinel").mkdir(parents=True)
    (detections / "sentinel" / "rule1.yml").write_text(
        yaml.safe_dump({
            "id": "brute-force-001",
            "version": "1.0.0",
            "asset": "sentinel_analytic",
            "status": "production",
            "metadata": {
                "owner": "team-soc@example.com",
                "runbookUrl": "https://example.com/r",
                "severity": "high",
                "tactics": ["InitialAccess"],
                "techniques": ["T1110"],
                "expectedAlertsPerDay": 1,
                "fpHandling": "investigate",
            },
            "payload": {"kind": "Scheduled", "displayName": "x"},
        }),
        encoding="utf-8",
    )
    (detections / "sentinel" / "rule2.yml").write_text(
        yaml.safe_dump({
            "id": "no-metadata",
            "version": "1.0.0",
            "asset": "sentinel_analytic",
            "status": "production",
            "legacy": True,
            "payload": {"kind": "Scheduled"},
        }),
        encoding="utf-8",
    )

    out = collect_owners(detections, ["brute-force-001", "no-metadata", "absent"])
    assert out == {"brute-force-001": "team-soc@example.com"}
