# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for `contentops new` scaffolder (W4-9)."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner

from contentops.cli import cli
from contentops.core.envelope import EnvelopeV2, parse_envelope
from contentops.devex.scaffold import ScaffoldError, scaffold
from contentops.lint.kql import at_or_above
from contentops.lint.runner import lint_assets


# Mirror ``contentops.devex.scaffold._SUPPORTED`` exactly — every kind
# `contentops new` can scaffold gets the validate+lint round-trip below.
# (sentinel_data_connector is intentionally absent from both: it's
# collected from the tenant, not authored from a template.)
SUPPORTED_ASSETS = (
    "sentinel_analytic",
    "sentinel_hunting",
    "sentinel_watchlist",
    "sentinel_parser",
    "defender_custom_detection",
)


@pytest.mark.parametrize("asset", SUPPORTED_ASSETS)
def test_each_template_validates_and_lints_clean(tmp_path: Path, asset: str) -> None:
    out = tmp_path / asset / "scaffold-example.yml"
    written = scaffold(
        asset, "scaffold-example",
        display_name="Scaffold Example",
        out=out, force=False,
    )
    assert written == out
    raw = yaml.safe_load(out.read_text(encoding="utf-8"))

    envelope, payload = parse_envelope(raw)
    assert envelope.id == "scaffold-example"
    assert envelope.asset.value == asset
    EnvelopeV2.model_validate(envelope.model_dump())

    # Handler-level payload validation
    if asset == "sentinel_analytic":
        from contentops.models import validate_sentinel_payload
        validate_sentinel_payload(payload)
    elif asset == "sentinel_hunting":
        from contentops.handlers.sentinel_hunting_models import SentinelHuntingPayload
        SentinelHuntingPayload(**payload)
    elif asset == "sentinel_watchlist":
        from contentops.handlers.sentinel_watchlist_models import SentinelWatchlistPayload
        SentinelWatchlistPayload(**payload)
    elif asset == "defender_custom_detection":
        from contentops.models import validate_defender_payload
        validate_defender_payload(payload)

    # Lint clean (no error-severity findings).
    linted = lint_assets(tmp_path)
    target = next((lf for lf in linted if lf.path == out), None)
    if target is not None:  # watchlist has no KQL field => no entry
        assert at_or_above(target.findings, "error") == [], target.findings


def test_scaffold_rejects_bad_id(tmp_path: Path) -> None:
    with pytest.raises(ScaffoldError) as exc:
        scaffold(
            "sentinel_analytic", "Bad_ID",
            display_name="x", out=tmp_path / "bad.yml",
        )
    assert "invalid" in str(exc.value).lower()
    assert exc.value.exit_code == 2


def test_scaffold_refuses_overwrite_without_force(tmp_path: Path) -> None:
    out = tmp_path / "x.yml"
    scaffold("sentinel_hunting", "first-id", out=out)
    with pytest.raises(ScaffoldError) as exc:
        scaffold("sentinel_hunting", "second-id", out=out, force=False)
    assert "refusing to overwrite" in str(exc.value)


def test_scaffold_force_overwrites(tmp_path: Path) -> None:
    out = tmp_path / "x.yml"
    scaffold("sentinel_hunting", "first-id", out=out)
    scaffold("sentinel_hunting", "second-id", out=out, force=True)
    raw = yaml.safe_load(out.read_text(encoding="utf-8"))
    assert raw["id"] == "second-id"


def test_default_output_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    written = scaffold("sentinel_analytic", "default-path-id")
    assert written == Path("detections/sentinel_analytic/default-path-id.yml")
    assert (tmp_path / written).is_file()


def test_unsupported_asset_rejected(tmp_path: Path) -> None:
    """An asset name that's not in the Asset enum at all is unknown
    (after the asset-taxonomy reduction every Asset enum entry is
    scaffold-supported)."""
    with pytest.raises(ScaffoldError) as exc:
        scaffold("sentinel_workbook", "some-id", out=tmp_path / "x.yml")
    assert exc.value.exit_code == 2
    # ``Asset(asset)`` raises ValueError -> ScaffoldError mentions the
    # supported list in its error message.
    assert "supported scaffolds" in str(exc.value).lower() or "unknown asset" in str(exc.value).lower()


def test_unknown_asset_rejected(tmp_path: Path) -> None:
    with pytest.raises(ScaffoldError) as exc:
        scaffold("does_not_exist", "some-id", out=tmp_path / "x.yml")
    assert exc.value.exit_code == 2


def test_cli_new_command_end_to_end(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["new", "sentinel_analytic", "cli-scaffold", "--name", "CLI Scaffold"],
    )
    assert result.exit_code == 0, result.output
    # Freshly-scaffolded envelopes carry TODO placeholder content for
    # description + attackDescription (so META002 / META003 are NOT
    # triggered — the field is non-empty). The remaining Section T
    # fields are seeded as empty lists, so the operator sees:
    #   * META001 warning  (lastValidatedAt unset)
    #   * META004 warning  (references: [])
    #   * META005 warning  (falsePositives: [])
    #   * META006 info     (blindSpots: [])
    #   * META007 info     (responseActions: [])
    # = 5 non-blocking findings. The author replaces the TODO text
    # and bumps lastValidatedAt before opening the PR.
    assert "lint: 5 non-blocking finding(s)" in result.output
    written = tmp_path / "detections" / "sentinel_analytic" / "cli-scaffold.yml"
    assert written.is_file()


def test_cli_new_refuses_overwrite_exit_1(tmp_path: Path) -> None:
    out = tmp_path / "scaffold.yml"
    scaffold("sentinel_hunting", "already-here", out=out)
    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["new", "sentinel_hunting", "already-here", "--out", str(out)],
    )
    assert result.exit_code == 1
    assert "refusing to overwrite" in result.output
