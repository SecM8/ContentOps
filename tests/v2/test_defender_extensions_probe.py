# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for `contentops defender-extensions-probe` (F11)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from contentops.defender_extensions_probe import (
    ProbeReport,
    ProbeResult,
    probe,
    render_json,
    render_markdown,
)


# ---------------------------------------------------------------------------
# probe() — uses a request callable so tests don't need real HTTP
# ---------------------------------------------------------------------------


def _const(status: int):
    return lambda method, url: status


def test_probe_404_means_not_available() -> None:
    rep = probe(_const(404))
    assert all(not r.available for r in rep.results)
    assert "not GA" in rep.note


def test_probe_200_means_available() -> None:
    rep = probe(_const(200))
    assert all(r.available for r in rep.results)
    assert rep.has_available()
    assert "look live" in rep.note


def test_probe_403_treated_as_available_with_auth_note() -> None:
    rep = probe(_const(403))
    assert all(r.available for r in rep.results)
    for r in rep.results:
        assert "auth" in r.detail or "permission" in r.detail


def test_probe_405_is_NOT_available_but_keeps_verb_note() -> None:
    """405 = path placed but not serving GET. The deferred doc says
    wait for HTTP 200 before authoring a handler; the probe must
    align — 405 stays visible in the report (operators can watch
    the transition) but does not flip available=true, so the
    workflow doesn't exit 2 on a long-running 405 plateau."""
    rep = probe(_const(405))
    assert all(not r.available for r in rep.results)
    for r in rep.results:
        assert "verb" in r.detail
        assert "not GA" in r.detail
    assert not rep.has_available()


def test_probe_handles_request_failure_gracefully() -> None:
    def _boom(method, url):
        raise RuntimeError("connection refused")
    rep = probe(_boom)
    for r in rep.results:
        assert r.available is False
        assert "connection refused" in r.detail
        assert r.status_code is None


def test_probe_custom_endpoint_set() -> None:
    rep = probe(_const(404), endpoints={"my-test": "/security/test"})
    assert len(rep.results) == 1
    assert rep.results[0].name == "my-test"


def test_probe_default_endpoint_set_includes_three_known_endpoints() -> None:
    rep = probe(_const(404))
    names = {r.name for r in rep.results}
    assert {
        "savedQueries", "detection_tuning_rules", "alert_suppression_rules",
    }.issubset(names)


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def test_render_markdown_includes_one_row_per_endpoint() -> None:
    rep = probe(_const(404), endpoints={
        "a": "/x", "b": "/y", "c": "/z",
    })
    md = render_markdown(rep)
    assert md.count("`a`") == 1
    assert md.count("`b`") == 1
    assert md.count("`c`") == 1


def test_render_json_is_parseable() -> None:
    rep = probe(_const(200), endpoints={"a": "/x"})
    parsed = json.loads(render_json(rep))
    assert parsed["has_available"] is True
    assert len(parsed["results"]) == 1
    assert parsed["results"][0]["name"] == "a"
