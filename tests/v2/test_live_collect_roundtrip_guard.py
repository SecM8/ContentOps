# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""The live collect round-trip, run against fake handlers.

It swallowed a ``list_remote`` failure into an empty list, so a kind the
tenant could not list was never round-tripped and the test still passed.
It also classified with its own loop instead of collect's (no remote-name
matching, no slug disambiguation, no per-kind comparison), so it did not
test what collect does.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from contentops.core.asset import Asset
from contentops.core.registry import default_registry

_REMOTE = {"name": "11111111-0000-0000-0000-000000000001",
           "properties": {"displayName": "Same name"}}
_TWIN = {"name": "22222222-0000-0000-0000-000000000002",
         "properties": {"displayName": "Same name"}}


class _Analytic:
    asset = Asset.SENTINEL_ANALYTIC

    def __init__(self, remotes, fail=False):
        self._remotes = remotes
        self._fail = fail

    def list_remote(self):
        if self._fail:
            raise RuntimeError("HTTP 403 listing alert rules")
        return list(self._remotes)

    def to_envelope(self, remote):
        # Two rules share a display name, so they share a slug: collect
        # tells them apart by suffix.
        return {"id": "same-name", "version": "0.0.0", "asset": "sentinel_analytic",
                "status": "production", "metadata": {"arm_name": remote["name"]},
                "payload": {"displayName": remote["properties"]["displayName"],
                            "kind": "Scheduled", "query": "T"}}

    def close(self):
        return None


@pytest.fixture
def registry(monkeypatch):
    saved_f, saved_i = dict(default_registry._factories), dict(default_registry._instances)
    default_registry._factories.clear()
    default_registry._instances.clear()
    seen: dict = {}

    def install(handler):
        def register(**kw):
            seen.update(kw)
            if not default_registry.has(handler.asset):
                default_registry.register(handler.asset, lambda: handler)
        monkeypatch.setattr("contentops.cli.handler_factories.register_default_handlers", register)
        return seen

    yield install
    default_registry._factories.clear()
    default_registry._instances.clear()
    default_registry._factories.update(saved_f)
    default_registry._instances.update(saved_i)


def test_a_kind_that_cannot_be_listed_fails_the_round_trip(tmp_path: Path, registry) -> None:
    from tests.integration.test_collect_live_roundtrip import test_live_collect_roundtrip_zero_drift

    registry(_Analytic([_REMOTE], fail=True))
    with pytest.raises(pytest.fail.Exception, match="sentinel_analytic"):
        test_live_collect_roundtrip_zero_drift(tmp_path)


def test_two_rules_with_one_name_round_trip_in_sync(tmp_path: Path, registry) -> None:
    """Collect's own classifier tells the two apart (suffixes by remote
    name); the old loop matched by bare slug and wrote one file for both."""
    from tests.integration.test_collect_live_roundtrip import test_live_collect_roundtrip_zero_drift

    seen = registry(_Analytic([_REMOTE, _TWIN]))
    test_live_collect_roundtrip_zero_drift(tmp_path)
    written = sorted(p.name for p in (tmp_path / "snapshot" / "sentinel_analytic").glob("*.yml"))
    assert len(written) == 2, written
    # References resolve against the snapshot, not ./detections.
    assert seen.get("detections_root") == tmp_path / "snapshot"
