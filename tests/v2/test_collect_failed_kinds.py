# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""``contentops collect`` when one asset kind fails to list.

Two regressions:

* collect exited 0 when a handler's ``list_remote`` raised (a 403 on
  one kind), so CI opened a PR from a partial snapshot;
* ``--clear`` deleted every local YAML BEFORE listing, so that same
  403 wiped the failing kind's files with nothing to replace them.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner

from contentops.cli import cli
from contentops.core.asset import Asset
from contentops.core.registry import default_registry


class _Handler:
    def __init__(self, asset: Asset, *, fail: bool = False) -> None:
        self.asset = asset
        self._fail = fail

    def list_remote(self) -> list[dict]:
        if self._fail:
            raise RuntimeError("403 Forbidden")
        return []

    def to_envelope(self, remote: dict) -> dict | None:
        return None


@pytest.fixture
def register(monkeypatch):
    """Swap the default handlers for fakes; restore the registry after."""
    saved_factories = dict(default_registry._factories)
    saved_instances = dict(default_registry._instances)
    default_registry._factories.clear()
    default_registry._instances.clear()

    def _register(*handlers: _Handler) -> None:
        def _install() -> None:
            for h in handlers:
                default_registry.register(h.asset, lambda h=h: h)
        monkeypatch.setattr(
            "contentops.cli.commands.collect.register_default_handlers", _install,
        )

    yield _register
    default_registry._factories.clear()
    default_registry._instances.clear()
    default_registry._factories.update(saved_factories)
    default_registry._instances.update(saved_instances)


def _seed(detections: Path, kind: Asset, name: str) -> Path:
    d = detections / kind.value
    d.mkdir(parents=True, exist_ok=True)
    f = d / f"{name}.yml"
    f.write_text(f"id: {name}\n", encoding="utf-8")
    return f


def test_clear_keeps_files_of_a_kind_that_failed_to_list(
    tmp_path: Path, register,
) -> None:
    detections = tmp_path / "detections"
    kept = _seed(detections, Asset.DEFENDER_CUSTOM_DETECTION, "rule-d")
    cleared = _seed(detections, Asset.SENTINEL_WATCHLIST, "wl-a")
    register(
        _Handler(Asset.SENTINEL_WATCHLIST),
        _Handler(Asset.DEFENDER_CUSTOM_DETECTION, fail=True),
    )

    result = CliRunner().invoke(
        cli, ["collect", "--path", str(detections), "--clear", "--workers", "1"],
    )

    assert result.exit_code == 2, result.output
    assert kept.exists(), "a failed listing must not wipe that kind's YAML"
    assert not cleared.exists(), "kinds that listed are still cleared"
    assert "defender_custom_detection" in result.output


def test_collect_exits_2_when_a_kind_fails_without_clear(
    tmp_path: Path, register,
) -> None:
    detections = tmp_path / "detections"
    register(
        _Handler(Asset.SENTINEL_WATCHLIST),
        _Handler(Asset.DEFENDER_CUSTOM_DETECTION, fail=True),
    )

    result = CliRunner().invoke(
        cli, ["collect", "--path", str(detections), "--workers", "1"],
    )

    assert result.exit_code == 2, result.output
    assert "failed to list" in result.output


def test_collect_exits_0_when_every_kind_lists(tmp_path: Path, register) -> None:
    detections = tmp_path / "detections"
    cleared = _seed(detections, Asset.SENTINEL_WATCHLIST, "wl-a")
    register(
        _Handler(Asset.SENTINEL_WATCHLIST),
        _Handler(Asset.DEFENDER_CUSTOM_DETECTION),
    )

    result = CliRunner().invoke(
        cli, ["collect", "--path", str(detections), "--clear", "--workers", "1"],
    )

    assert result.exit_code == 0, result.output
    assert not cleared.exists()
