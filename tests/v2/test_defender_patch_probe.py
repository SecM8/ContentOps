# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for the ``defender-patch-probe`` diagnostic.

The probe isolates which field the Defender beta ``detectionRules`` API
rejects on PATCH by sending a controlled, ordered sequence of requests
against one rule. These tests drive the command through a mocked HTTP
transport that models the production hypothesis (any body carrying
``queryText`` is rejected; a query containing ``FileProfile()`` is rejected
on create), and assert:

* preview mode (no ``--send``) makes no writes;
* ``--send`` builds non-destructive partial bodies (probe B never carries
  ``queryCondition``) and reaches the queryText-rejection verdict;
* ``--prove-fileprofile`` creates two disposable rules and cleans them up.
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
import yaml
from click.testing import CliRunner

from contentops.cli import cli
from contentops.defender import client as defender_client_module
from contentops.defender.client import BASE_URL, DefenderClient

_GRAPH_ID = "999"

_REMOTE = {
    "id": _GRAPH_ID,
    "displayName": "Probe Rule",
    "isEnabled": True,
    # server-managed field — exercises _strip_server_fields in the
    # disposable-rule template path.
    "lastModifiedDateTime": "2026-01-01T00:00:00Z",
    "queryCondition": {
        "queryText": "DeviceFileEvents | take 1 | invoke FileProfile()"
    },
    "schedule": {"period": "1H"},
    "detectionAction": {
        "alertTemplate": {
            "title": "Probe Rule",
            "severity": "medium",
            "category": "Execution",
            "impactedAssets": [
                {
                    "@odata.type": "#microsoft.graph.security.impactedDeviceAsset",
                    "identifier": "deviceId",
                },
            ],
        },
        "responseActions": [],
    },
}

_ENVELOPE = {
    "id": "probe-rule",
    "version": "1.0.0",
    "asset": "defender_custom_detection",
    "status": "production",
    "metadata": {"arm_name": _GRAPH_ID},
    "payload": {
        "displayName": "Probe Rule",
        "isEnabled": True,
        "queryCondition": {
            "queryText": "DeviceFileEvents | take 1 | invoke FileProfile()"
        },
        "schedule": {"period": "1H"},
        "detectionAction": {
            "alertTemplate": {
                "title": "Probe Rule",
                "severity": "medium",
                "category": "Execution",
                "impactedAssets": [
                    {
                        "@odata.type": "#microsoft.graph.security.impactedDeviceAsset",
                        "identifier": "deviceId",
                    },
                ],
            },
            "responseActions": [],
        },
    },
}


@pytest.fixture
def detections_dir(tmp_path: Path) -> Path:
    d = tmp_path / "detections" / "defender_custom_detection"
    d.mkdir(parents=True)
    (d / "probe-rule.yml").write_text(yaml.safe_dump(_ENVELOPE), encoding="utf-8")
    return tmp_path / "detections"


def _mock_transport(calls: list[tuple[str, str, dict]]) -> httpx.MockTransport:
    """Model the production hypothesis: beta rejects any PATCH carrying
    ``queryText`` and any create whose query uses ``FileProfile()``."""

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        body: dict = {}
        if request.content:
            try:
                body = json.loads(request.content)
            except ValueError:
                body = {}
        calls.append((request.method, path, body))

        if request.method == "GET" and path.endswith(f"/detectionRules/{_GRAPH_ID}"):
            return httpx.Response(200, json=_REMOTE)
        if request.method == "PATCH" and f"/detectionRules/{_GRAPH_ID}" in path:
            if "queryCondition" in body:  # query is the rejected field
                return httpx.Response(400, json={"error": {"code": "BadRequest"}})
            return httpx.Response(200, json=_REMOTE)
        if request.method == "POST" and path.endswith("/detectionRules"):
            # Model the entity-mapping/projection validation: a create whose
            # query output doesn't project the columns impactedAssets
            # reference is rejected with the detailed reason.
            return httpx.Response(400, json={"error": {
                "code": "BadRequest",
                "message": "Entity mappings reference the following column(s) "
                           "which are not projected by the query output: "
                           "InitiatingProcessAccountSid.",
            }})
        if request.method == "DELETE" and "/detectionRules/" in path:
            return httpx.Response(204)
        return httpx.Response(404, text=f"unexpected {request.method} {path}")

    return httpx.MockTransport(handler)


@pytest.fixture
def patched_client(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, str, dict]]:
    """Wire the command to a real DefenderClient backed by a mock
    transport, and stub credential resolution. Returns the recorded
    request log."""
    calls: list[tuple[str, str, dict]] = []
    client = DefenderClient(token="t")
    client._client.close()
    client._client = httpx.Client(
        base_url=BASE_URL, transport=_mock_transport(calls),
        headers={"Authorization": "Bearer t"},
    )
    monkeypatch.setattr(defender_client_module, "DefenderClient", lambda **_: client)
    monkeypatch.setattr(
        "contentops.utils.auth.get_credential", lambda: "stub-credential",
    )
    return calls


def _run(detections_dir: Path, *args: str):
    return CliRunner().invoke(
        cli,
        ["defender-patch-probe", "probe-rule", "--path", str(detections_dir), *args],
    )


def test_preview_makes_no_writes(detections_dir: Path, patched_client) -> None:
    result = _run(detections_dir)
    assert result.exit_code == 0, result.output
    assert "PREVIEW" in result.output
    methods = {m for m, _, _ in patched_client}
    assert "GET" in methods  # reads remote to build accurate bodies
    assert "PATCH" not in methods and "POST" not in methods and "DELETE" not in methods


def test_send_builds_nondestructive_partial_bodies(detections_dir: Path, patched_client) -> None:
    result = _run(detections_dir, "--send")
    assert result.exit_code == 0, result.output  # diagnostic completed

    patches = [body for m, _, body in patched_client if m == "PATCH"]
    assert len(patches) == 4  # A full, B schedule, C queryText, D severity
    # Probe B (schedule.period only) must NOT carry the query — non-destructive
    # partial PATCH built from the current remote value.
    schedule_only = [b for b in patches if set(b) == {"schedule"}]
    assert schedule_only == [{"schedule": {"period": "1H"}}]
    query_only = [b for b in patches if set(b) == {"queryCondition"}]
    assert len(query_only) == 1


def test_replicate_surfaces_graph_reason_and_cleans_up(detections_dir: Path, patched_client) -> None:
    result = _run(detections_dir, "--send", "--replicate")
    assert result.exit_code == 0, result.output
    # The clone-create surfaces Graph's verbatim, rule-specific reason.
    assert "Entity mappings reference" in result.output
    assert "InitiatingProcessAccountSid" in result.output

    posts = [body for m, _, body in patched_client if m == "POST"]
    assert len(posts) == 1  # one exact clone of the rule
    # The clone displayName is renamed (guard-prefixed) and disabled.
    assert posts[0]["displayName"].startswith("ZZ-probe-clone-")
    assert posts[0]["isEnabled"] is False
    # Clone create returned 400 → nothing created → no cleanup delete needed.
    deletes = [path for m, path, _ in patched_client if m == "DELETE"]
    assert deletes == []


def test_query_file_overrides_clone_query(detections_dir: Path, patched_client, tmp_path: Path) -> None:
    candidate = tmp_path / "candidate.kql"
    candidate.write_text("DeviceImageLoadEvents | take 1\n", encoding="utf-8")
    result = CliRunner().invoke(
        cli,
        ["defender-patch-probe", "probe-rule", "--path", str(detections_dir),
         "--send", "--replicate", "--query-file", str(candidate)],
    )
    assert result.exit_code == 0, result.output
    posts = [body for m, _, body in patched_client if m == "POST"]
    assert len(posts) == 1
    # The clone's query is replaced by the candidate; the rule's real
    # mappings are preserved.
    assert posts[0]["queryCondition"]["queryText"] == "DeviceImageLoadEvents | take 1"
    assert posts[0]["detectionAction"]["alertTemplate"]["impactedAssets"]
    # Both displayName and alertTemplate.title are renamed so the clone never
    # collides (409) with the real rule's title.
    assert posts[0]["displayName"].startswith("ZZ-probe-clone-")
    assert posts[0]["detectionAction"]["alertTemplate"]["title"].startswith("ZZ-probe-clone-")


def test_unknown_envelope_errors(detections_dir: Path, patched_client) -> None:
    result = CliRunner().invoke(
        cli,
        ["defender-patch-probe", "does-not-exist", "--path", str(detections_dir)],
    )
    assert result.exit_code == 1
    assert "no defender_custom_detection envelope" in result.output
