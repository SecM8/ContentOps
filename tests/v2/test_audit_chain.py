# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""W4-5: hash-chained audit trail tests."""

from __future__ import annotations

import hashlib
import json
from datetime import date, timedelta
from pathlib import Path

from click.testing import CliRunner

from contentops.audit import (
    AuditRecord,
    head_summary,
    verify_chain,
    write_records,
)
from contentops.audit.writer import (
    ZERO_HASH,
    _chain_records,
    _compute_record_hash,
)
from contentops.cli import cli


def _make_record(rid: str = "r1") -> AuditRecord:
    return AuditRecord(
        timestamp="2025-01-02T03:04:05.000000Z",
        asset="sentinel_analytic",
        id=rid,
        action="create",
        status="success",
        sha="abc",
        actor="alice",
        workflow_run=None,
        message=None,
        metadata_owner=None,
    )


# ---------- pure chain logic (no filesystem) ----------

def test_first_record_uses_zero_prev_hash() -> None:
    chained = _chain_records([_make_record("a")], ZERO_HASH)
    assert len(chained) == 1
    assert chained[0].prev_hash == ZERO_HASH
    assert chained[0].record_hash == _compute_record_hash(
        chained[0].__class__(**{**chained[0].__dict__, "record_hash": ""})
        if False else
        # use explicit recompute for clarity
        chained[0]
    )
    # explicit recompute against the to_json_unhashed contract
    expected = hashlib.sha256(
        chained[0].to_json_unhashed().encode("utf-8")
    ).hexdigest()
    assert chained[0].record_hash == expected


def test_subsequent_records_chain_correctly() -> None:
    chained = _chain_records(
        [_make_record("a"), _make_record("b"), _make_record("c")],
        ZERO_HASH,
    )
    assert chained[0].prev_hash == ZERO_HASH
    assert chained[1].prev_hash == chained[0].record_hash
    assert chained[2].prev_hash == chained[1].record_hash
    # Each record_hash unique (different ids)
    hashes = [r.record_hash for r in chained]
    assert len(set(hashes)) == 3


# ---------- write_records ----------

def test_write_records_first_record_uses_zero_prev_hash(tmp_path: Path) -> None:
    path = write_records(tmp_path, [_make_record("a")])
    line = path.read_text(encoding="utf-8").splitlines()[0]
    rec = json.loads(line)
    assert rec["prev_hash"] == ZERO_HASH
    assert len(rec["record_hash"]) == 64


def test_write_records_chains_within_same_file(tmp_path: Path) -> None:
    write_records(tmp_path, [_make_record("a"), _make_record("b")])
    path = write_records(tmp_path, [_make_record("c")])
    lines = path.read_text(encoding="utf-8").splitlines()
    a, b, c = (json.loads(line) for line in lines)
    assert a["prev_hash"] == ZERO_HASH
    assert b["prev_hash"] == a["record_hash"]
    assert c["prev_hash"] == b["record_hash"]


def test_chain_continues_across_days(tmp_path: Path) -> None:
    """First record on a new day must reference the previous day's tail."""
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()

    # Manually construct a "day 1" file using _chain_records.
    yesterday = (date.today() - timedelta(days=1)).isoformat()
    day1_records = _chain_records(
        [_make_record("d1a"), _make_record("d1b")], ZERO_HASH,
    )
    day1_path = audit_dir / f"{yesterday}.jsonl"
    day1_path.write_text(
        "".join(r.to_json() + "\n" for r in day1_records), encoding="utf-8",
    )

    # Now write today's batch — should chain from day1's tail.
    today_path = write_records(tmp_path, [_make_record("d2a")])
    assert today_path != day1_path
    today_rec = json.loads(today_path.read_text(encoding="utf-8").splitlines()[0])
    assert today_rec["prev_hash"] == day1_records[-1].record_hash


# ---------- verify_chain ----------

def test_verify_chain_clean(tmp_path: Path) -> None:
    write_records(tmp_path, [_make_record(f"r{i}") for i in range(5)])
    result = verify_chain(tmp_path)
    assert result.records_verified == 5
    assert result.files_checked == 1
    assert result.breaks == []


def test_verify_chain_no_audit_dir(tmp_path: Path) -> None:
    result = verify_chain(tmp_path)
    assert result.files_checked == 0
    assert result.records_verified == 0
    assert result.breaks == []


def test_verify_detects_record_tampering(tmp_path: Path) -> None:
    path = write_records(tmp_path, [_make_record("a"), _make_record("b")])
    lines = path.read_text(encoding="utf-8").splitlines()
    rec = json.loads(lines[0])
    rec["actor"] = "mallory"  # tamper
    lines[0] = json.dumps(rec, separators=(",", ":"))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    result = verify_chain(tmp_path)
    assert any(b.reason == "record_hash_invalid" for b in result.breaks)


def test_verify_detects_inserted_line(tmp_path: Path) -> None:
    path = write_records(
        tmp_path, [_make_record("a"), _make_record("b"), _make_record("c")],
    )
    lines = path.read_text(encoding="utf-8").splitlines()

    # Forge a line claiming to chain after line[0]; its own record_hash is
    # internally consistent, but the next genuine line still references the
    # original chain so prev_hash will mismatch.
    a = json.loads(lines[0])
    forged = AuditRecord(
        timestamp="2025-01-02T03:04:05.000000Z",
        asset="sentinel_analytic", id="forged", action="create",
        status="success", sha="abc", actor="mallory",
        workflow_run=None, message=None, metadata_owner=None,
        prev_hash=a["record_hash"], record_hash="",
    )
    forged_hash = hashlib.sha256(
        forged.to_json_unhashed().encode("utf-8")
    ).hexdigest()
    from dataclasses import replace
    forged = replace(forged, record_hash=forged_hash)
    spliced = [lines[0], forged.to_json(), lines[1], lines[2]]
    path.write_text("\n".join(spliced) + "\n", encoding="utf-8")

    result = verify_chain(tmp_path)
    assert any(b.reason == "prev_hash_mismatch" for b in result.breaks)


def test_verify_detects_truncation_is_clean(tmp_path: Path) -> None:
    """Truncating the tail leaves a valid (shorter) chain — not a break."""
    path = write_records(
        tmp_path, [_make_record("a"), _make_record("b"), _make_record("c")],
    )
    lines = path.read_text(encoding="utf-8").splitlines()
    path.write_text("\n".join(lines[:-1]) + "\n", encoding="utf-8")

    result = verify_chain(tmp_path)
    assert result.records_verified == 2
    assert result.breaks == []


def test_verify_cli_exit_codes_clean(tmp_path: Path) -> None:
    write_records(tmp_path, [_make_record("a")])
    runner = CliRunner()
    result = runner.invoke(cli, ["audit", "verify", "--root", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert "0 break(s)" in result.output


def test_verify_cli_exit_codes_broken(tmp_path: Path) -> None:
    path = write_records(tmp_path, [_make_record("a")])
    lines = path.read_text(encoding="utf-8").splitlines()
    rec = json.loads(lines[0])
    rec["actor"] = "mallory"
    lines[0] = json.dumps(rec, separators=(",", ":"))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(cli, ["audit", "verify", "--root", str(tmp_path)])
    assert result.exit_code == 1, result.output
    assert "record_hash_invalid" in result.output


def test_verify_cli_no_audit_dir_exits_zero(tmp_path: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["audit", "verify", "--root", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert "0 file(s)" in result.output


# ---------- Phase 4 review follow-ups: workspace + snippet_digest ----------


def test_record_with_workspace_and_digest_verifies(tmp_path: Path) -> None:
    """New AuditRecord fields are hashed cleanly and verify."""
    rec = AuditRecord(
        timestamp="2026-05-13T10:00:00.000000Z",
        asset="sentinel_analytic", id="r1", action="create",
        status="success", sha="abc", actor="alice",
        workflow_run=None, message=None, metadata_owner=None,
        workspace="law-prod",
        snippet_digest="0" * 64,
    )
    write_records(tmp_path, [rec])
    result = verify_chain(tmp_path)
    assert result.records_verified == 1
    assert result.breaks == []


def test_default_workspace_and_digest_are_none(tmp_path: Path) -> None:
    """Records constructed without the new kwargs default to None."""
    rec = _make_record("r1")  # _make_record doesn't pass the new fields
    assert rec.workspace is None
    assert rec.snippet_digest is None
    write_records(tmp_path, [rec])
    result = verify_chain(tmp_path)
    assert result.records_verified == 1
    assert result.breaks == []


def test_pre_phase4_record_on_disk_still_verifies(tmp_path: Path) -> None:
    """An on-disk record written BEFORE the schema bump (no
    workspace / snippet_digest keys in its JSON) must still verify
    cleanly. verify_chain works on the raw dict via json.loads, so
    the missing keys never enter the recomputed hash -- the chain
    extends naturally across the schema bump.
    """
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    # Hand-craft a JSONL line that mimics a pre-Phase-4 record:
    # only the original 11 fields, hash computed over that key set.
    pre_phase4_dict = {
        "timestamp": "2026-05-13T09:00:00.000000Z",
        "asset": "sentinel_analytic",
        "id": "old-rule",
        "action": "create",
        "status": "success",
        "sha": "abc",
        "actor": "alice",
        "workflow_run": None,
        "message": None,
        "metadata_owner": None,
        "prev_hash": ZERO_HASH,
    }
    record_hash = hashlib.sha256(
        json.dumps(pre_phase4_dict, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    pre_phase4_dict["record_hash"] = record_hash
    line = json.dumps(pre_phase4_dict, separators=(",", ":"))
    (audit_dir / "2026-05-13.jsonl").write_text(line + "\n", encoding="utf-8")

    result = verify_chain(tmp_path)
    assert result.records_verified == 1, (
        f"pre-Phase-4 record should verify cleanly across the schema bump; "
        f"breaks={result.breaks}"
    )
    assert result.breaks == []


def test_chain_extends_across_pre_and_post_phase4(tmp_path: Path) -> None:
    """A pre-Phase-4 record (no new fields) followed by a Phase-4
    record (with workspace + snippet_digest) must chain link
    correctly. Verifies the schema bump is hash-compatible end-to-end.
    """
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    pre_phase4_dict = {
        "timestamp": "2026-05-13T09:00:00.000000Z",
        "asset": "sentinel_analytic", "id": "old-rule",
        "action": "create", "status": "success",
        "sha": "abc", "actor": "alice",
        "workflow_run": None, "message": None, "metadata_owner": None,
        "prev_hash": ZERO_HASH,
    }
    pre_hash = hashlib.sha256(
        json.dumps(pre_phase4_dict, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    pre_phase4_dict["record_hash"] = pre_hash
    pre_line = json.dumps(pre_phase4_dict, separators=(",", ":"))
    (audit_dir / "2026-05-13.jsonl").write_text(pre_line + "\n", encoding="utf-8")

    # Now write a Phase-4 record using the live writer; it must
    # link to the pre-Phase-4 record's hash.
    new_rec = AuditRecord(
        timestamp="2026-05-13T10:00:00.000000Z",
        asset="sentinel_analytic", id="new-rule", action="create",
        status="success", sha="def", actor="bob",
        workflow_run=None, message=None, metadata_owner=None,
        workspace="law-prod", snippet_digest="abc123",
    )
    write_records(tmp_path, [new_rec])

    result = verify_chain(tmp_path)
    assert result.records_verified == 2
    assert result.breaks == [], f"chain broke across schema bump: {result.breaks}"


def test_chain_extends_across_pre_and_post_phase4_in_separate_files(
    tmp_path: Path,
) -> None:
    """Cross-phase Seam I gap: schema bump across a calendar day
    boundary, where day 1 is a pre-Phase-4 .jsonl and day 2 is a
    Phase-4 .jsonl. ``verify_chain`` reads files in date-sorted
    order; the cross-file ``prev_hash`` link must still hold.
    """
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()

    # Day 1 - pre-Phase-4 record in its own file.
    day1_dict = {
        "timestamp": "2026-05-13T09:00:00.000000Z",
        "asset": "sentinel_analytic", "id": "old-rule",
        "action": "create", "status": "success",
        "sha": "abc", "actor": "alice",
        "workflow_run": None, "message": None, "metadata_owner": None,
        "prev_hash": ZERO_HASH,
    }
    day1_hash = hashlib.sha256(
        json.dumps(day1_dict, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    day1_dict["record_hash"] = day1_hash
    (audit_dir / "2026-05-13.jsonl").write_text(
        json.dumps(day1_dict, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )

    # Day 2 - Phase-4 record in a separate file. The writer's
    # _last_record_tail walks reverse-date order to seed prev_hash;
    # confirm it picks up day 1's hash and chains forward.
    day2_rec = AuditRecord(
        timestamp="2026-05-14T09:00:00.000000Z",
        asset="sentinel_analytic", id="new-rule", action="create",
        status="success", sha="def", actor="bob",
        workflow_run=None, message=None, metadata_owner=None,
        workspace="law-prod", snippet_digest="abc123",
    )
    # write_records picks today's date; force the day-2 file by
    # writing the chained record manually. (We can't call
    # write_records for "tomorrow" without monkeypatching date.)
    from contentops.audit.writer import _chain_records
    chained = _chain_records([day2_rec], day1_hash, prev_timestamp=day1_dict["timestamp"])
    (audit_dir / "2026-05-14.jsonl").write_text(
        chained[0].to_json() + "\n", encoding="utf-8",
    )

    result = verify_chain(tmp_path)
    assert result.records_verified == 2
    assert result.breaks == [], (
        f"chain broke across day-boundary schema bump: {result.breaks}"
    )


# ---------------------------------------------------------------------------
# head_summary + `audit head` CLI (Wave 5 attestation input)
# ---------------------------------------------------------------------------


def test_head_summary_empty_root(tmp_path: Path) -> None:
    s = head_summary(tmp_path)
    assert s["head_hash"] is None
    assert s["tail_timestamp"] is None
    assert s["files_checked"] == 0
    assert s["records_verified"] == 0
    assert s["chain_breaks"] == 0
    assert s["verified"] is True


def test_head_summary_populated(tmp_path: Path) -> None:
    write_records(tmp_path, [_make_record("r1"), _make_record("r2")])
    s = head_summary(tmp_path)
    assert isinstance(s["head_hash"], str) and len(s["head_hash"]) == 64
    assert s["tail_timestamp"]  # non-empty ISO string
    assert s["records_verified"] == 2
    assert s["chain_breaks"] == 0
    assert s["verified"] is True


def test_head_summary_reports_break(tmp_path: Path) -> None:
    write_records(tmp_path, [_make_record("r1"), _make_record("r2")])
    # Corrupt a committed record so the chain no longer self-verifies.
    audit_file = next((tmp_path / "audit").glob("*.jsonl"))
    text = audit_file.read_text(encoding="utf-8")
    audit_file.write_text(text.replace('"r1"', '"r1-tampered"'), encoding="utf-8")
    s = head_summary(tmp_path)
    assert s["verified"] is False
    assert s["chain_breaks"] >= 1


def test_cli_audit_head_json_stdout(tmp_path: Path) -> None:
    write_records(tmp_path, [_make_record("r1")])
    result = CliRunner().invoke(cli, ["audit", "head", "--root", str(tmp_path)])
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert isinstance(data["head_hash"], str) and len(data["head_hash"]) == 64
    assert data["records_verified"] == 1 and data["verified"] is True


def test_cli_audit_head_writes_out_file(tmp_path: Path) -> None:
    write_records(tmp_path, [_make_record("r1")])
    out = tmp_path / "audit-head.json"
    result = CliRunner().invoke(
        cli, ["audit", "head", "--root", str(tmp_path), "--out", str(out)],
    )
    assert result.exit_code == 0, result.output
    assert out.exists()
    assert json.loads(out.read_text(encoding="utf-8"))["records_verified"] == 1
