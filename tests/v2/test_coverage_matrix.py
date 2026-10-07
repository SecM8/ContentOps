# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""contentops.coverage.matrix -- the single ATT&CK matrix loader."""

from __future__ import annotations

import json

import pytest

from contentops.coverage.matrix import (
    ALL_TACTICS,
    ENTERPRISE_TACTICS,
    AttackMatrix,
    load_matrix,
    normalise_tactic,
    normalise_technique_id,
)

SYNTHETIC = {
    "attack_version": "19.2",
    "tactics": [{"id": "Execution"}, {"id": "DefenseEvasion"}],
    "techniques": [
        {"id": "T1059", "name": "Command and Scripting Interpreter", "tactics": ["Execution"]},
        {"id": "T1685", "name": "Disable or Modify Tools", "tactics": ["DefenseEvasion"]},
    ],
    "sub_techniques": [
        {"id": "T1059.001", "name": "PowerShell", "parent_id": "T1059", "tactics": ["Execution"]},
    ],
    "revoked": {"T1562.001": "T1685", "T1562": "T1685"},
    "deprecated": ["T1043"],
}


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("T1059", "T1059"), (" t1059.001 ", "T1059.001"), ("t1087", "T1087"),
        ("T10", None), ("T1059.1", None), ("bogus", None), ("", None),
        (None, None), (1059, None), ('T1059"><script>', None),
    ],
)
def test_normalise_technique_id(raw, expected) -> None:
    assert normalise_technique_id(raw) == expected


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("CredentialAccess", "CredentialAccess"), ("credential access", "CredentialAccess"),
        ("Credential_Access", "CredentialAccess"), ("defense-evasion", "DefenseEvasion"),
        ("Stealth", "DefenseEvasion"), ("PreAttack", "PreAttack"),
        ("NotATactic", None), (None, None),
    ],
)
def test_normalise_tactic(raw, expected) -> None:
    assert normalise_tactic(raw) == expected


def test_resolve_statuses() -> None:
    matrix = AttackMatrix.from_dict(SYNTHETIC)
    assert matrix.resolve("T1059.001") == ("T1059.001", "current")
    assert matrix.resolve("T1562.001") == ("T1685", "revoked")
    assert matrix.resolve("T1043") == (None, "deprecated")
    assert matrix.resolve("T9999") == (None, "unknown")
    assert matrix.tactics_for("T1685") == ("DefenseEvasion",)
    assert matrix.tactics_for("T9999") == ()
    assert matrix.attack_version == "19.2" and matrix.attack_major == "19"
    assert matrix.techniques == {"T1059", "T1685"}
    assert matrix.sub_techniques == {"T1059.001"}


def test_old_data_without_revocation_keys_still_loads() -> None:
    raw = {k: v for k, v in SYNTHETIC.items()
           if k not in ("attack_version", "revoked", "deprecated")}
    matrix = AttackMatrix.from_dict(raw)
    assert matrix.attack_version == "" and matrix.attack_major == ""
    assert matrix.resolve("T1562.001") == (None, "unknown")


def test_revocation_to_a_non_current_target_is_not_trusted() -> None:
    raw = json.loads(json.dumps(SYNTHETIC))
    raw["revoked"]["T1000"] = "T8888"  # target missing from the matrix
    assert AttackMatrix.from_dict(raw).resolve("T1000") == (None, "unknown")


def test_bundled_matrix_shape() -> None:
    matrix = load_matrix()
    assert matrix.tactics == set(ENTERPRISE_TACTICS)
    assert set(ALL_TACTICS) >= matrix.tactics
    assert len(matrix.techniques) >= 200 and len(matrix.sub_techniques) >= 400
    assert matrix.label == "MITRE ATT&CK Enterprise (full)"
    assert matrix.attack_major.isdigit()
