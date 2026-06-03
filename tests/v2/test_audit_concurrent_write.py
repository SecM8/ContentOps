# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for AuditConcurrentWriteError — the pre-replace tail re-check.

Background: ``write_records()`` reads the audit tail at entry, chains
its records off that predecessor, then atomically replaces the day's
JSONL file. If a second writer slipped a record in between the
initial tail-read and the replace, the second writer's records would
be chained off a stale predecessor AND its replace would overwrite
the first writer's bytes — silent lost-write + chain break.

The fix re-reads the tail right before ``os.replace`` and raises
``AuditConcurrentWriteError`` if the predecessor moved. These tests
verify the raise path fires when the chain advances under the writer
and stays quiet on the normal serial path.
"""

from __future__ import annotations

from datetime import date
from pathlib import Path
from unittest.mock import patch

import pytest

from contentops.audit.writer import (
    AuditConcurrentWriteError,
    AuditRecord,
    write_orphan_records,
    write_records,
    write_records_with_retry,
)


def _record(asset_id: str) -> AuditRecord:
    """Minimal record. write_records chains prev_hash + record_hash for us."""
    return AuditRecord(
        timestamp="2026-05-17T10:00:00.000000Z",
        asset="sentinel_analytic",
        id=asset_id,
        action="apply",
        status="success",
        sha="0000000000000000000000000000000000000000",
        actor="tester",
        workflow_run=None,
        message=None,
        metadata_owner=None,
    )


def test_serial_writes_pass(tmp_path: Path) -> None:
    """Sanity: two sequential ``write_records`` calls produce a valid chain."""
    write_records(tmp_path, [_record("rule-a")])
    write_records(tmp_path, [_record("rule-b")])
    today = tmp_path / "audit" / f"{date.today():%Y-%m-%d}.jsonl"
    lines = today.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2


def test_concurrent_write_raises(tmp_path: Path) -> None:
    """Simulate the race: between the initial _last_record_tail and the
    pre-replace re-check, another writer slips in a record.

    Strategy — patch the second ``_last_record_tail`` call so it
    returns a different hash than the first. write_records should
    detect the move and raise.
    """
    write_records(tmp_path, [_record("rule-a")])  # seed the chain

    real_tail = "contentops.audit.writer._last_record_tail"
    # First call returns the real tail; second call (the pre-replace
    # re-check) returns a different hash to simulate a racing writer.
    from contentops.audit.writer import _last_record_tail
    seeded_tail = _last_record_tail(tmp_path / "audit")
    racing_tail = ("a" * 64, seeded_tail[1])

    call_count = {"n": 0}

    def _patched(audit_dir: Path):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return seeded_tail
        return racing_tail

    with patch(real_tail, side_effect=_patched):
        with pytest.raises(AuditConcurrentWriteError) as excinfo:
            write_records(tmp_path, [_record("rule-b")])
    # The exception message should mention both predecessors so the
    # operator can correlate to the racing writer in audit logs.
    msg = str(excinfo.value)
    assert seeded_tail[0][:12] in msg
    assert racing_tail[0][:12] in msg


def test_concurrent_write_does_not_leave_temp_file(tmp_path: Path) -> None:
    """When the race detection fires, the ``.tmp`` sibling file must
    be cleaned up — otherwise a subsequent successful write would
    have a stale temp lying around."""
    write_records(tmp_path, [_record("rule-a")])
    from contentops.audit.writer import _last_record_tail
    seeded_tail = _last_record_tail(tmp_path / "audit")
    racing_tail = ("b" * 64, seeded_tail[1])

    # Mirror the race in test_concurrent_write_raises: first call sees
    # the seeded predecessor, second call sees a racing writer's
    # different hash so write_records aborts before os.replace.
    call_count = {"n": 0}

    def _patched(audit_dir: Path):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return seeded_tail
        return racing_tail

    real_tail = "contentops.audit.writer._last_record_tail"
    with patch(real_tail, side_effect=_patched):
        with pytest.raises(AuditConcurrentWriteError):
            write_records(tmp_path, [_record("rule-b")])

    audit_dir = tmp_path / "audit"
    tmp_files = list(audit_dir.glob("*.tmp"))
    assert tmp_files == [], f"unexpected temp files: {tmp_files}"


def test_initial_write_to_empty_audit_dir(tmp_path: Path) -> None:
    """First-ever write: no prior record exists, the race check uses
    ZERO_HASH on both sides and passes."""
    write_records(tmp_path, [_record("rule-a")])
    today = tmp_path / "audit" / f"{date.today():%Y-%m-%d}.jsonl"
    assert today.exists()
    assert today.read_text(encoding="utf-8").count("\n") == 1


# ---------------------------------------------------------------------------
# write_records_with_retry — the apply-path resilience wrapper
# ---------------------------------------------------------------------------


def test_retry_succeeds_on_first_attempt(tmp_path: Path) -> None:
    """No race: the wrapper is a transparent pass-through to write_records."""
    path = write_records_with_retry(tmp_path, [_record("rule-a")])
    assert path.exists()
    assert len(path.read_text(encoding="utf-8").splitlines()) == 1


def test_retry_recovers_after_a_transient_race(tmp_path: Path) -> None:
    """First attempt hits the race; the retry calls write_records again
    (which re-reads the fresh tail) and succeeds."""
    from contentops.audit import writer as W
    real = W.write_records
    calls = {"n": 0}

    def flaky(root: Path, records):
        calls["n"] += 1
        if calls["n"] == 1:
            raise AuditConcurrentWriteError("forced first-attempt race")
        return real(root, records)

    with patch("contentops.audit.writer.write_records", side_effect=flaky):
        path = write_records_with_retry(tmp_path, [_record("rule-a")])
    assert calls["n"] == 2, "should have retried exactly once"
    assert path.exists()
    assert path.read_text(encoding="utf-8").strip() != ""


def test_retry_reraises_after_exhausting_attempts(tmp_path: Path) -> None:
    """A persistent race exhausts the retries and surfaces the error so the
    caller can decide (apply turns it into a warning + orphan sidecar)."""
    calls = {"n": 0}

    def always_race(root: Path, records):
        calls["n"] += 1
        raise AuditConcurrentWriteError("persistent race")

    with patch("contentops.audit.writer.write_records", side_effect=always_race):
        with pytest.raises(AuditConcurrentWriteError):
            write_records_with_retry(tmp_path, [_record("x")], attempts=3)
    assert calls["n"] == 3, "should have tried exactly `attempts` times"


def test_retry_resolves_a_real_tail_race(tmp_path: Path) -> None:
    """End-to-end with the genuine race machinery: force the pre-replace
    re-check of the FIRST attempt to see a moved tail (raise), then let the
    retry re-chain off the real fresh tail and succeed."""
    write_records(tmp_path, [_record("rule-a")])  # seed the chain
    from contentops.audit.writer import _last_record_tail

    audit_dir = tmp_path / "audit"
    seeded = _last_record_tail(audit_dir)
    racing = ("c" * 64, seeded[1])
    calls = {"n": 0}

    def patched(d: Path):
        calls["n"] += 1
        # write_records reads the tail twice per attempt (entry + pre-replace).
        # Call #2 is attempt-1's pre-replace check — force the mismatch there.
        if calls["n"] == 2:
            return racing
        return _last_record_tail(d)

    with patch("contentops.audit.writer._last_record_tail", side_effect=patched):
        path = write_records_with_retry(tmp_path, [_record("rule-b")], attempts=3)

    assert path.exists()
    # rule-a (seed) + rule-b (written on the successful retry) = 2 chained records.
    assert len(path.read_text(encoding="utf-8").splitlines()) == 2


def test_orphan_writer_persists_batch_without_touching_the_chain(tmp_path: Path) -> None:
    """The last-resort sink writes the unchained batch to a `.orphan` sidecar
    and leaves the main chain file alone (data completeness, no chain mutation)."""
    import json

    write_records(tmp_path, [_record("rule-a")])  # real chain: 1 record
    orphan = write_orphan_records(
        tmp_path, [_record("rule-b"), _record("rule-c")]
    )
    assert orphan.name.endswith(".jsonl.orphan")
    orphan_lines = orphan.read_text(encoding="utf-8").splitlines()
    assert len(orphan_lines) == 2
    for line in orphan_lines:
        json.loads(line)  # recoverable as valid JSON records

    main = tmp_path / "audit" / f"{date.today():%Y-%m-%d}.jsonl"
    assert len(main.read_text(encoding="utf-8").splitlines()) == 1, (
        "the main hash chain must be untouched by the orphan write"
    )


def test_orphan_writer_appends_across_calls(tmp_path: Path) -> None:
    """Repeated orphan dumps accumulate rather than clobber."""
    write_orphan_records(tmp_path, [_record("a")])
    orphan = write_orphan_records(tmp_path, [_record("b")])
    assert len(orphan.read_text(encoding="utf-8").splitlines()) == 2
