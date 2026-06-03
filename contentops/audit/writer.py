# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""JSONL audit-trail writer for `contentops apply`.

Records are hash-chained: each record stores `prev_hash` (the SHA-256 of the
previous record's serialized JSON line) and `record_hash` (the SHA-256 of its
own JSON serialization with `record_hash` removed). The first record on the
first day uses `prev_hash = "0" * 64`. The first record on a subsequent day
continues the chain from the previous day's last record.

Serialization is deterministic: dataclass field declaration order, with
`json.dumps(separators=(",", ":"))`.

Timestamp monotonicity (G16 / Item 9 of the post-Phase-3 hardening
backlog):

  * Within a batch, ``_chain_records`` walks records in order and
    advances each timestamp to ``max(record.timestamp, prev_timestamp
    + 1µs)`` if it would otherwise equal or precede its predecessor.
    Two records emitted at the same wall-clock instant are now
    deterministically ordered — the second appears one microsecond
    after the first.
  * Across batches, ``write_records`` seeds the chain with the
    previous tail's timestamp (alongside its hash) so a fresh batch
    cannot pre-date an earlier record on disk.
  * ``verify_chain`` enforces ``current_timestamp >= prev_timestamp``
    (strictly going BACKWARDS is a break; equal stays legal so old
    logs that pre-date this rule still verify).

The monotonicity bump preserves the existing schema — the
``timestamp`` field stays a fixed-width ISO 8601 string; no new
field is added. Pre-bump records on disk verify unchanged because
the verifier only enforces non-regression, never the bump itself.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from dataclasses import asdict, dataclass, field, replace
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable

ZERO_HASH: str = "0" * 64


class AuditConcurrentWriteError(RuntimeError):
    """Raised when the audit-chain tail moved between the predecessor
    lookup and the atomic replace.

    Two writers running concurrently both see the same predecessor on
    entry to ``write_records``; the second to call ``os.replace`` would
    silently overwrite the first's records (lost-write) and produce a
    chain that fails ``verify_chain`` for everyone downstream. The
    pre-replace re-check raises this instead so the caller can retry
    once with the fresh predecessor.

    Workflows that drive ``contentops apply`` / ``prune`` / ``rollback``
    serialize via a shared ``concurrency`` group so this race is rare;
    the assertion is the belt-and-braces for the local-dev /
    out-of-band-execution case where workflow serialization doesn't
    apply.
    """

# Timestamp format the rest of the pipeline emits (see
# commands.apply / commands.prune ``datetime.now(...).strftime(...)``).
# All timestamps share this exact width and timezone suffix, so lexical
# string comparison sorts them correctly — no need to parse for the
# common case. Parsing is reserved for the +1µs bump path.
_TIMESTAMP_FMT = "%Y-%m-%dT%H:%M:%S.%fZ"


@dataclass(frozen=True)
class AuditRecord:
    timestamp: str
    asset: str
    id: str
    action: str
    status: str
    sha: str
    actor: str
    workflow_run: str | None
    message: str | None
    metadata_owner: str | None
    # Phase 4 (workspace-aware snippet substitution) added two
    # optional fields. Old records on disk don't have them; their
    # stored ``record_hash`` was computed over the JSON dict that
    # didn't include the keys, so ``verify_chain`` (which works on
    # raw dicts via ``json.loads`` + key-set dropping ``record_hash``)
    # continues to pass for them. New records get the keys serialized
    # and hashed, populated when the apply ran multi-workspace and /
    # or with snippet substitution.
    workspace: str | None = None
    snippet_digest: str | None = None
    prev_hash: str = ZERO_HASH
    record_hash: str = ""

    def to_json_unhashed(self) -> str:
        """Serialize without the `record_hash` field (input to hashing).

        `prev_hash` is included so chain integrity covers it.
        """
        d = asdict(self)
        d.pop("record_hash", None)
        return json.dumps(d, separators=(",", ":"))

    def to_json(self) -> str:
        """Serialize the full record (single line, deterministic)."""
        return json.dumps(asdict(self), separators=(",", ":"))


@dataclass(frozen=True)
class ChainBreak:
    file: Path
    line_number: int
    expected_prev_hash: str
    actual_prev_hash: str
    # Reason codes:
    #   "prev_hash_mismatch"      — record points at a different hash
    #                               than the chain's actual tail
    #   "record_hash_invalid"     — stored record_hash != re-computed
    #                               hash (content tampered)
    #   "missing_field"           — record line couldn't be parsed or
    #                               lacks prev_hash / record_hash
    #   "timestamp_regression"    — record's timestamp is strictly
    #                               earlier than the previous record's
    #                               (added in the Item-9 monotonicity
    #                               hardening; equal timestamps stay
    #                               legal for old-log backward compat)
    reason: str


@dataclass(frozen=True)
class ChainVerificationResult:
    files_checked: int
    records_verified: int
    breaks: list[ChainBreak] = field(default_factory=list)


def _compute_record_hash(rec: AuditRecord) -> str:
    """SHA-256 hex of the record's JSON serialization (without record_hash)."""
    return hashlib.sha256(rec.to_json_unhashed().encode("utf-8")).hexdigest()


def _monotonic_timestamp(prev_ts: str, candidate: str) -> str:
    """Return ``candidate`` if strictly greater than ``prev_ts``, else
    ``prev_ts`` advanced by one microsecond.

    All in-process audit timestamps share the fixed-width ISO format
    ``%Y-%m-%dT%H:%M:%S.%fZ``, so lexical comparison is a faithful
    proxy for chronological comparison. We only fall through to the
    arithmetic bump when the candidate doesn't already exceed the
    previous timestamp.

    Returns ``candidate`` unchanged in the (frequent) fast path —
    when wall-clock advanced between records, the candidate already
    sorts strictly after the previous string and no parsing happens.

    Parse failures degrade gracefully: if ``prev_ts`` doesn't match
    the expected format (e.g. it came from a record written by a
    future schema), we return the candidate unmodified — the
    verifier will catch any real regression at audit-verify time.
    """
    if not prev_ts or candidate > prev_ts:
        return candidate
    # Strictly equal or smaller — need to bump. Parse and add 1µs.
    try:
        dt_prev = datetime.strptime(prev_ts, _TIMESTAMP_FMT).replace(
            tzinfo=timezone.utc,
        )
    except ValueError:
        # Unparseable predecessor — leave the candidate alone rather
        # than mint a fake successor based on a format we don't
        # recognise.
        return candidate
    bumped = (dt_prev + timedelta(microseconds=1)).strftime(_TIMESTAMP_FMT)
    return bumped


def _chain_records(
    records: Iterable[AuditRecord],
    prev_hash: str,
    *,
    prev_timestamp: str = "",
) -> list[AuditRecord]:
    """Return a list of records with `prev_hash` and `record_hash` set.

    ``prev_timestamp`` seeds the monotonicity chain with the previous
    on-disk record's timestamp. Each successive record's timestamp
    is advanced to ``max(record.timestamp, prev_timestamp + 1µs)``
    so two records sharing a wall-clock instant get a deterministic
    order, and a clock-skewed apply can never write a record that
    pre-dates one already on disk.

    The bump applies before hashing, so the hash chain covers the
    monotonic timestamp directly — no separate sequence field needed
    and the existing record schema is unchanged.

    Pure function — no filesystem access. Unit-testable in isolation.
    """
    chained: list[AuditRecord] = []
    current_prev = prev_hash
    current_ts = prev_timestamp
    for rec in records:
        bumped_ts = _monotonic_timestamp(current_ts, rec.timestamp)
        with_prev = replace(
            rec,
            timestamp=bumped_ts,
            prev_hash=current_prev,
            record_hash="",
        )
        h = _compute_record_hash(with_prev)
        chained.append(replace(with_prev, record_hash=h))
        current_prev = h
        current_ts = bumped_ts
    return chained


def _last_record_tail(audit_dir: Path) -> tuple[str, str]:
    """Look up the tail (record_hash, timestamp) across existing files.

    Walks ``audit/*.jsonl`` in reverse date order and returns the most
    recent record's ``(record_hash, timestamp)`` so a fresh batch can
    chain its hash AND seed its monotonicity baseline. Returns
    ``(ZERO_HASH, "")`` when no records are found on disk yet — the
    monotonicity check then becomes a no-op for the very first batch
    of the very first day.
    """
    if not audit_dir.exists():
        return ZERO_HASH, ""
    files = sorted(audit_dir.glob("*.jsonl"))
    for path in reversed(files):
        try:
            content = path.read_text(encoding="utf-8")
        except OSError:
            continue
        for line in reversed(content.splitlines()):
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            rh = rec.get("record_hash")
            if isinstance(rh, str) and rh:
                ts = rec.get("timestamp") or ""
                return rh, ts if isinstance(ts, str) else ""
    return ZERO_HASH, ""


def _last_record_hash(audit_dir: Path) -> str:
    """Backward-compat shim: callers historically asked only for the hash."""
    return _last_record_tail(audit_dir)[0]


def write_records(root: Path, records: Iterable[AuditRecord]) -> Path:
    """Append a batch of records to today's audit file, chained.

    Atomicity: the new tail (existing bytes + new lines) is written to a
    sibling temp file, fsynced, then `os.replace`d into place.

    Each record's timestamp is advanced to be strictly greater than
    the previous record's (whether that predecessor is in the same
    batch or already on disk) — see ``_chain_records`` /
    ``_monotonic_timestamp``.
    """
    target_dir = root / "audit"
    target_dir.mkdir(parents=True, exist_ok=True)
    path = target_dir / f"{date.today():%Y-%m-%d}.jsonl"

    prev_hash, prev_timestamp = _last_record_tail(target_dir)
    chained = _chain_records(records, prev_hash, prev_timestamp=prev_timestamp)

    new_bytes = "".join(rec.to_json() + "\n" for rec in chained).encode("utf-8")
    existing = path.read_bytes() if path.exists() else b""

    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "wb") as fh:
        fh.write(existing)
        fh.write(new_bytes)
        fh.flush()
        os.fsync(fh.fileno())

    # Concurrent-writer guard. Re-read the tail right before the atomic
    # replace; if it moved, another writer slipped in between our
    # initial _last_record_tail and here. Replacing would either lose
    # their records (their file content disappears under us) or break
    # the chain (our records chain off a stale predecessor). Raise so
    # the caller can retry with the fresh predecessor.
    current_prev_hash, _ = _last_record_tail(target_dir)
    if current_prev_hash != prev_hash:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise AuditConcurrentWriteError(
            f"audit tail moved during write "
            f"(expected predecessor {prev_hash[:12]}..., "
            f"now {current_prev_hash[:12]}...). "
            "Another writer raced this one; retry."
        )

    os.replace(tmp, path)
    return path


def write_records_with_retry(
    root: Path, records: Iterable[AuditRecord], *, attempts: int = 3,
) -> Path:
    """``write_records`` that retries the transient concurrent-writer race.

    ``write_records`` raises ``AuditConcurrentWriteError`` when the audit
    tail moved between reading the predecessor and the atomic replace.
    Each retry calls ``write_records`` again, which re-reads the *fresh*
    tail and re-chains off it (``_chain_records`` is pure — it never
    mutates the input records), so the race resolves itself. Raises
    ``AuditConcurrentWriteError`` only if **every** attempt collides.
    """
    if attempts < 1:
        raise ValueError("attempts must be >= 1")
    # Materialise so a generator input survives multiple attempts.
    records = list(records)
    last_exc: AuditConcurrentWriteError | None = None
    for _ in range(attempts):
        try:
            return write_records(root, records)
        except AuditConcurrentWriteError as exc:
            last_exc = exc
            continue
    assert last_exc is not None  # loop ran >=1 time and only continues on this
    raise last_exc


def write_orphan_records(root: Path, records: Iterable[AuditRecord]) -> Path:
    """Last-resort sink for an audit batch that lost the write race after
    retries.

    Writes the records (unchained) to a sidecar ``audit/<date>.jsonl.orphan``
    so the batch is **recoverable for manual reconciliation** rather than
    silently dropped — data completeness over silence. The main chain file
    is left untouched (the racing writer's records are intact there). This
    is a recovery artifact, not part of the verified hash chain; ``audit
    verify`` only walks ``*.jsonl``.
    """
    target_dir = root / "audit"
    target_dir.mkdir(parents=True, exist_ok=True)
    path = target_dir / f"{date.today():%Y-%m-%d}.jsonl.orphan"
    with open(path, "ab") as fh:
        for rec in records:
            fh.write((rec.to_json() + "\n").encode("utf-8"))
        fh.flush()
        os.fsync(fh.fileno())
    return path


def verify_chain(root: Path) -> ChainVerificationResult:
    """Verify hash-chain integrity across all audit/*.jsonl files.

    Three classes of break are reported:

      * ``record_hash_invalid`` — content was tampered with after
        the record was written (the stored hash doesn't match what
        recomputation would produce).
      * ``prev_hash_mismatch`` — the chain has been spliced or
        records have been reordered (a record's ``prev_hash`` no
        longer matches the previous record's actual ``record_hash``).
      * ``timestamp_regression`` — a record's timestamp is strictly
        EARLIER than the previous record's, which the monotonic
        writer would never produce. Either the file was tampered with
        post-hoc OR clock skew at write time was so severe the writer
        couldn't compensate. Equal timestamps stay legal — old logs
        that pre-date Item-9 hardening regularly carry adjacent
        records sharing a wall-clock instant.

    The walk is single-pass across date-sorted files; ``expected_prev``
    chains hash state across files, ``prev_timestamp`` chains the
    monotonicity check.
    """
    audit_dir = root / "audit"
    breaks: list[ChainBreak] = []
    if not audit_dir.exists():
        return ChainVerificationResult(files_checked=0, records_verified=0, breaks=breaks)

    files = sorted(audit_dir.glob("*.jsonl"))
    records_verified = 0
    expected_prev = ZERO_HASH
    prev_timestamp = ""  # seed; first record's timestamp becomes the new floor

    for f in files:
        try:
            content = f.read_text(encoding="utf-8")
        except OSError:
            continue
        for ln, line in enumerate(content.splitlines(), start=1):
            if not line.strip():
                continue
            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                breaks.append(ChainBreak(
                    file=f, line_number=ln,
                    expected_prev_hash=expected_prev, actual_prev_hash="",
                    reason="missing_field",
                ))
                continue
            if "record_hash" not in d or "prev_hash" not in d:
                breaks.append(ChainBreak(
                    file=f, line_number=ln,
                    expected_prev_hash=expected_prev,
                    actual_prev_hash=str(d.get("prev_hash", "")),
                    reason="missing_field",
                ))
                continue

            actual_prev = d["prev_hash"]
            stored_hash = d["record_hash"]
            d_for_hash = {k: v for k, v in d.items() if k != "record_hash"}
            computed = hashlib.sha256(
                json.dumps(d_for_hash, separators=(",", ":")).encode("utf-8")
            ).hexdigest()

            if computed != stored_hash:
                breaks.append(ChainBreak(
                    file=f, line_number=ln,
                    expected_prev_hash=expected_prev, actual_prev_hash=actual_prev,
                    reason="record_hash_invalid",
                ))
            elif actual_prev != expected_prev:
                breaks.append(ChainBreak(
                    file=f, line_number=ln,
                    expected_prev_hash=expected_prev, actual_prev_hash=actual_prev,
                    reason="prev_hash_mismatch",
                ))

            # Timestamp non-regression check. We use lexical compare
            # because every in-pipeline-produced timestamp shares the
            # fixed-width %Y-%m-%dT%H:%M:%S.%fZ format. A record whose
            # ``timestamp`` field is missing or non-string skips the
            # check (the missing_field branch above already covers
            # records where the chain itself is unparseable). Equal
            # timestamps pass — required for backward compat with
            # pre-Item-9 logs.
            current_ts = d.get("timestamp")
            if (
                isinstance(current_ts, str)
                and prev_timestamp
                and current_ts < prev_timestamp
            ):
                breaks.append(ChainBreak(
                    file=f, line_number=ln,
                    expected_prev_hash=expected_prev,
                    actual_prev_hash=actual_prev,
                    reason="timestamp_regression",
                ))
            if isinstance(current_ts, str) and current_ts:
                prev_timestamp = current_ts

            records_verified += 1
            expected_prev = stored_hash

    return ChainVerificationResult(
        files_checked=len(files),
        records_verified=records_verified,
        breaks=breaks,
    )


def head_summary(root: Path) -> dict:
    """Summarise the audit chain head for out-of-band notarisation.

    Returns a small, self-describing dict the deploy workflow writes to
    ``audit-head.json`` and attests with GitHub Artifact Attestations
    (Sigstore-backed). Carries the chain tail hash + timestamp alongside the
    verify counts so a third party can confirm the attested run produced a
    consistent chain — and can tell an empty/short chain (``head_hash`` null,
    low ``records_verified``) from a full one.

    NOTE on scope: ``audit/`` is gitignored and restored per run from the
    artifact only, so on a fresh CI runner the chain begins at
    ``ZERO_HASH`` — this summary describes THIS run's records, not a
    cumulative ledger. See SECURITY.md for the provenance-not-authenticity
    boundary this attestation draws.
    """
    audit_dir = root / "audit"
    head_hash, tail_ts = _last_record_tail(audit_dir)
    result = verify_chain(root)
    return {
        "head_hash": None if head_hash == ZERO_HASH else head_hash,
        "tail_timestamp": tail_ts or None,
        "files_checked": result.files_checked,
        "records_verified": result.records_verified,
        "chain_breaks": len(result.breaks),
        "verified": not result.breaks,
    }


def _resolve_sha(root: Path | None = None) -> str:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(root) if root is not None else None,
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        return "unknown"
    sha = result.stdout.strip()
    if result.returncode != 0 or not sha:
        return "unknown"
    return sha


def _resolve_actor() -> str:
    return (
        os.getenv("GITHUB_ACTOR")
        or os.getenv("USER")
        or os.getenv("USERNAME")
        or "unknown"
    )
