# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Autouse isolation for the v2 unit suite.

Makes the unit tests behave like a clean CI checkout regardless of the
developer's machine. Two operator-local, gitignored inputs would
otherwise leak into tests that invoke the CLI without supplying their
own config:

* ``config/tenant.yml`` — gitignored (CLAUDE.md invariant 3) and absent
  in CI, but present on an operator's machine. A command that loads it
  without ``--role`` on a multi-workspace tenant exits 2 ("specify
  --role"), so tests expecting exit 0 fail locally while passing in CI.
* ``.env`` — re-loaded at every CLI invocation by
  ``contentops.cli.root.cli`` via ``load_env_file()``; it repopulates
  ``AZURE_*`` auth vars that tests ``monkeypatch.delenv`` to assert the
  unset path, undoing the test's intent.

This fixture pins the clean-checkout baseline: no ``.env`` discovery, the
default tenant-config path points at a non-existent file, and the auth
env vars are cleared. Tests that need a config still pass ``--path`` or
``monkeypatch.setattr("contentops.config.CONFIG_PATH", ...)`` — their
setattr runs after this one and wins.

Scoped to ``tests/v2/`` (unit tests) ONLY. Integration and e2e tests
under ``tests/integration`` / ``tests/e2e`` legitimately need the real
config + credentials and have their own conftest; this file does not
apply to them.
"""

from __future__ import annotations

import pytest

# Auth/selection env vars an operator's `.env` or shell would set. Cleared
# per-test so the suite matches CI (where none are set for the unit job).
_LEAKABLE_AUTH_ENV_VARS = (
    "AZURE_CLIENT_ID",
    "AZURE_TENANT_ID",
    "AZURE_CLIENT_SECRET",
    "AZURE_SUBSCRIPTION_ID",
    "PIPELINE_ENV",
    "CONTENTOPS_AUTH_FALLBACK",
)


@pytest.fixture(autouse=True)
def _isolate_from_local_config_and_env(monkeypatch, tmp_path):
    """Isolate each v2 test from operator-local config/tenant.yml + .env,
    and run it from its own tmp CWD."""
    # 1) Never auto-discover the developer's .env at CLI invoke time
    #    (CI has none). load_env_file() calls this module-global, so a
    #    None return makes it a no-op.
    monkeypatch.setattr(
        "contentops.utils.env.find_dotenv", lambda *args, **kwargs: None
    )
    # 2) Point the default tenant-config path at a file that does not
    #    exist, so the gitignored config/tenant.yml is never picked up.
    #    load_tenant_config() then raises FileNotFoundError exactly as it
    #    does in a clean CI checkout.
    monkeypatch.setattr(
        "contentops.config.CONFIG_PATH", tmp_path / "no-such-tenant.yml"
    )
    # 3) Clear auth vars a developer .env / shell would otherwise leak.
    for var in _LEAKABLE_AUTH_ENV_VARS:
        monkeypatch.delenv(var, raising=False)
    # 4) Run each test from its own tmp directory so CWD-relative writes
    #    land in the test's tmp tree, not the operator's real working
    #    tree. The load-bearing case is the audit chain: the lifecycle
    #    commands (disable/enable/lock/unlock/retry) write via
    #    ``write_records(Path.cwd(), ...)``, which targets
    #    ``<cwd>/audit/<date>.jsonl`` using a FIXED ``.tmp`` name. Without
    #    an isolated CWD, those tests all write to the *same* real
    #    ``audit/<date>.jsonl`` and race on its single ``.tmp`` under
    #    ``pytest -n auto`` (CI's invocation) — intermittent
    #    FileNotFoundError / PermissionError on ``os.replace``, plus
    #    corruption of the operator's local hash-chained log. Tests that
    #    need a specific CWD just ``monkeypatch.chdir(...)`` again; theirs
    #    runs after this and wins.
    monkeypatch.chdir(tmp_path)
    # 5) get_credential() caches one credential per process; drop it so a
    #    credential built under another test's env vars never leaks in.
    from contentops.utils import auth as _auth
    _auth._reset_credential_cache()
    yield
    _auth._reset_credential_cache()


# ---------------------------------------------------------------------------
# Shared ATT&CK coverage corpus: one rule per review finding, so every
# coverage surface (heatmap, gaps, badge, Navigator, report, portfolio)
# can be checked against the same detections.
# ---------------------------------------------------------------------------

_SENTINEL_QUERY = "SecurityEvent | take 1"


def _sentinel(rule_id, *, tactics=(), techniques=(), sub_techniques=(),
              status="production", enabled=True, metadata=None, kind="sentinel_analytic"):
    payload = {"displayName": f"{rule_id} rule", "query": _SENTINEL_QUERY}
    if kind == "sentinel_analytic":
        payload.update({"kind": "Scheduled", "severity": "Medium", "enabled": enabled})
    if tactics:
        payload["tactics"] = list(tactics)
    if techniques:
        payload["techniques"] = list(techniques)
    if sub_techniques:
        payload["subTechniques"] = list(sub_techniques)
    doc = {"id": rule_id, "version": "1.0.0", "asset": kind, "status": status,
           "payload": payload}
    if metadata is not None:
        doc["metadata"] = metadata
    return doc


def _full_metadata(**overrides):
    base = {
        "owner": "soc@contoso.com", "runbookUrl": "https://wiki/runbook",
        "severity": "high", "tactics": ["InitialAccess"], "techniques": ["T1566"],
        "expectedAlertsPerDay": 1, "fpHandling": "n/a",
    }
    base.update(overrides)
    return base


COVERAGE_CORPUS = {
    # C1: Sentinel stores sub-techniques in their own field.
    "r1-subtechniques": _sentinel("r1-subtechniques", tactics=["CredentialAccess"],
                                  techniques=["T1110"], sub_techniques=["T1110.003"]),
    # C2: two tactics, two techniques -- each technique only under its own tactic.
    "r2-multi-tactic": _sentinel("r2-multi-tactic", tactics=["InitialAccess", "Execution"],
                                 techniques=["T1190", "T1059"]),
    # C3: T1018 is a Discovery technique on a Persistence rule.
    "r3-tactic-mismatch": _sentinel("r3-tactic-mismatch", tactics=["Persistence"],
                                    techniques=["T1018"]),
    # C3: techniques but no tactics -> tactics inferred.
    "r3b-no-tactics": _sentinel("r3b-no-tactics", techniques=["T1046"]),
    # C4: disabled.
    "r4-disabled": _sentinel("r4-disabled", tactics=["Impact"], techniques=["T1486"],
                             enabled=False),
    # C5: hunting query.
    "r5-hunting": _sentinel("r5-hunting", tactics=["LateralMovement"], techniques=["T1021"],
                            kind="sentinel_hunting"),
    # C6: partial metadata (no runbookUrl / fpHandling ...): tags must survive.
    "r6-partial-metadata": _sentinel("r6-partial-metadata", metadata={
        "owner": "soc@contoso.com", "tactics": ["Exfiltration"], "techniques": ["T1041"],
    }),
    # C6 (worse): every required key + one bad reference -> strict parse fails.
    "r6b-bad-reference": _sentinel("r6b-bad-reference", metadata=_full_metadata(
        references=["ftp://not-http.example"],
    )),
    # C7: messy, malformed and unknown ids.
    "r7-messy-ids": _sentinel("r7-messy-ids", tactics=["Discovery"],
                              techniques=[" T1082", "t1087", "T10", "bogus", "T9999"]),
    # C8: Defender T1078 spans four tactics; the category claims one.
    "r8-defender": {
        "id": "r8-defender", "version": "1.0.0", "asset": "defender_custom_detection",
        "status": "production",
        "payload": {
            "displayName": "r8-defender rule", "status": "enabled",
            "queryCondition": {"queryText": "DeviceProcessEvents | take 1"},
            "detectionAction": {"alertTemplate": {
                "title": "r8 alert title", "category": "InitialAccess",
                "mitreTechniques": ["T1078"], "severity": "medium",
            }},
        },
    },
    # Revoked: T1562 / T1562.001 -> T1685 (ATT&CK v19).
    "r9-revoked": _sentinel("r9-revoked", tactics=["DefenseEvasion"], techniques=["T1562"],
                            sub_techniques=["T1562.001"]),
    # Non-production.
    "r10-experimental": _sentinel("r10-experimental", tactics=["CredentialAccess"],
                                  techniques=["T1003"], status="experimental"),
}

# What the default scope (enabled production, hunting excluded) covers.
COVERAGE_CORPUS_PARENTS = frozenset({
    "T1110", "T1190", "T1059", "T1018", "T1046", "T1041", "T1566",
    "T1082", "T1087", "T1078", "T1685",
})
COVERAGE_CORPUS_SUBS = frozenset({"T1110.003"})
COVERAGE_CORPUS_TACTICS = frozenset({
    "CredentialAccess", "InitialAccess", "Execution", "Persistence",
    "Discovery", "Exfiltration", "DefenseEvasion",
})
COVERAGE_CORPUS_IN_SCOPE = 9


@pytest.fixture
def coverage_corpus(tmp_path):
    """Write COVERAGE_CORPUS under ``tmp_path/detections/<kind>/`` and
    return the detections root."""
    import yaml as _yaml

    root = tmp_path / "detections"
    for name, doc in COVERAGE_CORPUS.items():
        folder = root / doc["asset"]
        folder.mkdir(parents=True, exist_ok=True)
        (folder / f"{name}.yml").write_text(
            _yaml.safe_dump(doc, sort_keys=False), encoding="utf-8",
        )
    return root


@pytest.fixture
def coverage_corpus_expected():
    """What :func:`coverage_corpus` covers under the default scope."""
    from types import SimpleNamespace

    return SimpleNamespace(
        parents=COVERAGE_CORPUS_PARENTS,
        subs=COVERAGE_CORPUS_SUBS,
        tactics=COVERAGE_CORPUS_TACTICS,
        in_scope=COVERAGE_CORPUS_IN_SCOPE,
    )
