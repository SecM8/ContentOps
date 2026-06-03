# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Regression tests for audit timestamp monotonicity (Item 9 / G16).

Phase-1-through-3 left the hash chain tamper-evident for content but
not for *ordering*. Two batches emitted at the same wall-clock instant
could land in non-deterministic order. The writer now bumps colliding
timestamps forward by 1µs; the verifier reports a new
``timestamp_regression`` ChainBreak when a record's timestamp is
strictly earlier than the previous record's.

These tests pin:

  1. ``_chain_records`` bumps a same-instant record to ``prev+1µs``
     so its on-disk timestamp is strictly after its predecessor's.
  2. ``write_records`` carries the timestamp floor across batches /
     across day files via ``_last_record_tail``.
  3. ``verify_chain`` does NOT flag equal timestamps as a regression
     (backward compat with pre-Item-9 logs, which routinely carry
     adjacent records sharing a wall-clock instant).
  4. ``verify_chain`` DOES flag a maliciously reordered log where a
     later record's timestamp is strictly earlier than its
     predecessor's.
  5. The CLI surfaces the new break reason cleanly (exit 1).
  6. A bumped record's hash is still self-consistent — the bump
     happens before hashing, so verification passes the
     ``record_hash_invalid`` check on the bumped record.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from datetime import date
from pathlib import Path

from click.testing import CliRunner

from contentops.audit import AuditRecord, verify_chain, write_records
from contentops.audit.writer import (
    ZERO_HASH,
    _chain_records,
    _last_record_tail,
    _monotonic_timestamp,
)
from contentops.cli import cli


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


_FIXED_TS = "2025-01-02T03:04:05.000000Z"


def _record(rid: str = "r1", *, ts: str = _FIXED_TS) -> AuditRecord:
    return AuditRecord(
        timestamp=ts,
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


# ---------------------------------------------------------------------------
# _monotonic_timestamp — pure helper
# ---------------------------------------------------------------------------


def test_monotonic_returns_candidate_unchanged_when_strictly_later() -> None:
    """Fast path: candidate already advances past prev, no bump needed."""
    out = _monotonic_timestamp(
        "2025-01-02T03:04:05.000000Z",
        "2025-01-02T03:04:05.000001Z",
    )
    assert out == "2025-01-02T03:04:05.000001Z"


def test_monotonic_bumps_equal_timestamp_by_one_microsecond() -> None:
    """When candidate equals prev, bump prev by 1µs."""
    out = _monotonic_timestamp(
        "2025-01-02T03:04:05.000000Z",
        "2025-01-02T03:04:05.000000Z",
    )
    assert out == "2025-01-02T03:04:05.000001Z"


def test_monotonic_bumps_backwards_timestamp_to_prev_plus_one() -> None:
    """When candidate is strictly earlier than prev (clock skew),
    advance to prev+1µs — never let the chain go backwards."""
    out = _monotonic_timestamp(
        "2025-01-02T03:04:05.500000Z",
        "2025-01-02T03:04:05.100000Z",
    )
    assert out == "2025-01-02T03:04:05.500001Z"


def test_monotonic_empty_prev_is_a_noop() -> None:
    """First record in a brand-new chain has no predecessor — the
    candidate flows through unchanged."""
    out = _monotonic_timestamp("", "2025-01-02T03:04:05.000000Z")
    assert out == "2025-01-02T03:04:05.000000Z"


def test_monotonic_unparseable_prev_falls_through_safely() -> None:
    """A predecessor in an unrecognised format doesn't crash the
    writer — we return the candidate unchanged rather than mint a
    fake successor from a format we can't parse. Defence-in-depth
    for forward-compatibility with a future schema."""
    out = _monotonic_timestamp("not-a-timestamp", "2025-01-02T03:04:05.000000Z")
    assert out == "2025-01-02T03:04:05.000000Z"


# ---------------------------------------------------------------------------
# _chain_records — writer's monotonicity guarantee within a batch
# ---------------------------------------------------------------------------


def test_chain_records_bumps_same_instant_batch_into_strict_order() -> None:
    """Three records emitted at the same wall-clock instant come out
    strictly ordered: T, T+1µs, T+2µs."""
    batch = [_record("a"), _record("b"), _record("c")]
    chained = _chain_records(batch, ZERO_HASH)
    assert [r.timestamp for r in chained] == [
        "2025-01-02T03:04:05.000000Z",
        "2025-01-02T03:04:05.000001Z",
        "2025-01-02T03:04:05.000002Z",
    ]


def test_chain_records_passes_through_already_increasing_timestamps() -> None:
    """No bumps when wall-clock advanced naturally between records."""
    batch = [
        _record("a", ts="2025-01-02T03:04:05.000000Z"),
        _record("b", ts="2025-01-02T03:04:06.000000Z"),
        _record("c", ts="2025-01-02T03:04:07.000000Z"),
    ]
    chained = _chain_records(batch, ZERO_HASH)
    assert [r.timestamp for r in chained] == [
        "2025-01-02T03:04:05.000000Z",
        "2025-01-02T03:04:06.000000Z",
        "2025-01-02T03:04:07.000000Z",
    ]


def test_chain_records_bumps_backwards_timestamp_within_batch() -> None:
    """Worst-case clock skew: second record arrives with a timestamp
    earlier than the first. Writer advances it to first+1µs."""
    batch = [
        _record("a", ts="2025-01-02T03:04:05.000000Z"),
        _record("b", ts="2025-01-02T03:04:04.999999Z"),  # earlier!
    ]
    chained = _chain_records(batch, ZERO_HASH)
    assert chained[0].timestamp == "2025-01-02T03:04:05.000000Z"
    assert chained[1].timestamp == "2025-01-02T03:04:05.000001Z"


def test_chain_records_seeds_from_prev_timestamp() -> None:
    """Cross-batch monotonicity: a new batch chained after an earlier
    tail must respect the tail's timestamp as its floor."""
    batch = [_record("a", ts="2025-01-02T03:04:05.000000Z")]
    chained = _chain_records(
        batch, ZERO_HASH, prev_timestamp="2025-01-02T03:04:05.999999Z",
    )
    # Candidate (000000) is earlier than prev (999999) -> bumped to
    # prev + 1µs.
    assert chained[0].timestamp == "2025-01-02T03:04:06.000000Z"


def test_chain_records_bumped_record_is_internally_consistent() -> None:
    """The hash covers the bumped timestamp — verify_chain still
    treats the resulting record as untampered, because the bump
    happens BEFORE hashing."""
    batch = [_record("a"), _record("b")]
    chained = _chain_records(batch, ZERO_HASH)
    for rec in chained:
        expected = hashlib.sha256(
            rec.to_json_unhashed().encode("utf-8"),
        ).hexdigest()
        assert rec.record_hash == expected, rec.id


# ---------------------------------------------------------------------------
# write_records — end-to-end monotonicity (filesystem + chain)
# ---------------------------------------------------------------------------


def test_write_records_carries_timestamp_floor_across_batches(
    tmp_path: Path,
) -> None:
    """Two separate write_records calls with same-instant timestamps
    still produce strictly-ordered records on disk."""
    write_records(tmp_path, [_record("a")])
    write_records(tmp_path, [_record("b")])

    today_file = tmp_path / "audit" / f"{date.today():%Y-%m-%d}.jsonl"
    lines = today_file.read_text(encoding="utf-8").splitlines()
    ts_a = json.loads(lines[0])["timestamp"]
    ts_b = json.loads(lines[1])["timestamp"]
    # Both writes used the same wall-clock instant; second batch must
    # land strictly after the first via the cross-batch seed.
    assert ts_b > ts_a, (ts_a, ts_b)


def test_last_record_tail_returns_hash_and_timestamp(tmp_path: Path) -> None:
    """``_last_record_tail`` surfaces both fields so write_records can
    seed the timestamp floor (not just the hash chain)."""
    write_records(tmp_path, [_record("a"), _record("b"), _record("c")])
    audit_dir = tmp_path / "audit"
    h, ts = _last_record_tail(audit_dir)
    assert len(h) == 64
    # Three same-instant records → last one at +2µs.
    assert ts == "2025-01-02T03:04:05.000002Z"


def test_last_record_tail_empty_dir_returns_defaults(tmp_path: Path) -> None:
    h, ts = _last_record_tail(tmp_path / "no-such-dir")
    assert h == ZERO_HASH
    assert ts == ""


# ---------------------------------------------------------------------------
# verify_chain — non-regression detection
# ---------------------------------------------------------------------------


def test_verify_chain_accepts_equal_timestamps_on_old_logs(
    tmp_path: Path,
) -> None:
    """Backward compat: a pre-Item-9 log where adjacent records share
    the same timestamp (the historical "same-instant batch" shape)
    must still verify clean. Only strictly-decreasing time triggers
    the new break.

    We construct the file by hand to model what an older writer
    would have emitted before this hardening landed: equal
    timestamps, hash chain intact, no monotonicity bump.
    """
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()

    # Build three records that all share the same timestamp, then
    # chain them by hand (skipping the new monotonic bump that
    # _chain_records would normally apply).
    records = [_record(f"r{i}") for i in range(3)]
    prev_hash = ZERO_HASH
    lines: list[str] = []
    for rec in records:
        chained = replace(rec, prev_hash=prev_hash, record_hash="")
        h = hashlib.sha256(
            chained.to_json_unhashed().encode("utf-8"),
        ).hexdigest()
        chained = replace(chained, record_hash=h)
        lines.append(chained.to_json())
        prev_hash = h

    (audit_dir / f"{date.today():%Y-%m-%d}.jsonl").write_text(
        "\n".join(lines) + "\n", encoding="utf-8",
    )

    result = verify_chain(tmp_path)
    assert result.records_verified == 3
    assert result.breaks == [], (
        "equal timestamps in pre-Item-9 logs must verify clean; "
        f"got breaks: {result.breaks}"
    )


def test_verify_chain_detects_timestamp_regression(tmp_path: Path) -> None:
    """A maliciously reordered log where time goes backwards is
    flagged with reason='timestamp_regression'."""
    # Build a clean chain first, then swap two records' timestamps to
    # simulate a tampering attempt that reorders the log.
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()

    later = _record("later", ts="2025-01-02T03:04:09.000000Z")
    earlier = _record("earlier", ts="2025-01-02T03:04:05.000000Z")

    # Chain them with the EARLIER record first (the natural order)
    # to get hash-valid lines, then re-order on disk so the LATER
    # record's hash references EARLIER's record_hash but the chain
    # of times goes backwards. We have to rebuild the chain so the
    # hashes match the reordered line sequence.
    chained = _chain_records([earlier, later], ZERO_HASH)
    # On disk: same order — earlier(ts=5) then later(ts=9). That's
    # the BASE case. Now invert the timestamps in place but keep the
    # chain intact: record 0 carries earlier's content + earlier's
    # ts, record 1 carries later's content but its timestamp is moved
    # to 03:04:04 (BEFORE record 0's). We must re-hash to keep the
    # record_hash field consistent with the modified line — otherwise
    # verify reports record_hash_invalid first and short-circuits the
    # timestamp check.
    forged_later_pre = replace(
        chained[1],
        timestamp="2025-01-02T03:04:04.000000Z",  # earlier than record 0!
        record_hash="",
    )
    new_hash = hashlib.sha256(
        forged_later_pre.to_json_unhashed().encode("utf-8"),
    ).hexdigest()
    forged_later = replace(forged_later_pre, record_hash=new_hash)

    today_path = audit_dir / f"{date.today():%Y-%m-%d}.jsonl"
    today_path.write_text(
        chained[0].to_json() + "\n" + forged_later.to_json() + "\n",
        encoding="utf-8",
    )

    result = verify_chain(tmp_path)
    regression_breaks = [
        b for b in result.breaks if b.reason == "timestamp_regression"
    ]
    assert len(regression_breaks) == 1, result.breaks
    # The break points at the offending (second) line.
    assert regression_breaks[0].line_number == 2


def test_verify_chain_no_regression_on_strictly_increasing(
    tmp_path: Path,
) -> None:
    """Clean chain with strictly-increasing timestamps verifies clean."""
    write_records(tmp_path, [
        _record("a", ts="2025-01-02T03:04:05.000000Z"),
        _record("b", ts="2025-01-02T03:04:06.000000Z"),
        _record("c", ts="2025-01-02T03:04:07.000000Z"),
    ])
    result = verify_chain(tmp_path)
    assert result.breaks == []


def test_verify_chain_detects_regression_across_files(tmp_path: Path) -> None:
    """Timestamp non-regression is enforced ACROSS files, not just
    within a file. A second-day log whose first record predates the
    first day's tail is flagged."""
    from datetime import timedelta
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    yesterday = (date.today() - timedelta(days=1)).isoformat()
    today = f"{date.today():%Y-%m-%d}"

    day1 = _chain_records(
        [_record("d1", ts="2025-01-02T12:00:00.000000Z")], ZERO_HASH,
    )
    (audit_dir / f"{yesterday}.jsonl").write_text(
        day1[0].to_json() + "\n", encoding="utf-8",
    )

    # Day 2's record claims an earlier timestamp. Chain it correctly
    # from day1's tail so prev_hash is valid (only timestamp_regression
    # should fire).
    day2 = _chain_records(
        [_record("d2", ts="2025-01-02T11:00:00.000000Z")],
        day1[-1].record_hash,
    )
    (audit_dir / f"{today}.jsonl").write_text(
        day2[0].to_json() + "\n", encoding="utf-8",
    )

    result = verify_chain(tmp_path)
    assert any(
        b.reason == "timestamp_regression" for b in result.breaks
    ), result.breaks


# ---------------------------------------------------------------------------
# CLI surface
# ---------------------------------------------------------------------------


def test_audit_verify_cli_exits_nonzero_on_timestamp_regression(
    tmp_path: Path,
) -> None:
    """``contentops audit verify`` exit code reflects the new break
    class — a future hash-chain-only verifier wouldn't see this
    failure, so the CLI gate matters."""
    # Reuse the cross-file regression scenario; same shape.
    from datetime import timedelta
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    yesterday = (date.today() - timedelta(days=1)).isoformat()

    day1 = _chain_records(
        [_record("d1", ts="2025-01-02T12:00:00.000000Z")], ZERO_HASH,
    )
    (audit_dir / f"{yesterday}.jsonl").write_text(
        day1[0].to_json() + "\n", encoding="utf-8",
    )
    day2 = _chain_records(
        [_record("d2", ts="2025-01-02T11:00:00.000000Z")],
        day1[-1].record_hash,
    )
    (audit_dir / f"{date.today():%Y-%m-%d}.jsonl").write_text(
        day2[0].to_json() + "\n", encoding="utf-8",
    )

    result = CliRunner().invoke(
        cli, ["audit", "verify", "--root", str(tmp_path)],
    )
    assert result.exit_code == 1, result.output
    assert "timestamp_regression" in result.output
