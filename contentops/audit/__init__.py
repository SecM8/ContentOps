# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Append-only audit trail for `contentops apply`."""

from __future__ import annotations

from contentops.audit.writer import (
    AuditConcurrentWriteError,
    AuditRecord,
    ChainBreak,
    ChainVerificationResult,
    _resolve_actor,
    _resolve_sha,
    head_summary,
    verify_chain,
    write_orphan_records,
    write_records,
    write_records_with_retry,
)

__all__ = [
    "AuditConcurrentWriteError",
    "AuditRecord",
    "ChainBreak",
    "ChainVerificationResult",
    "head_summary",
    "verify_chain",
    "write_records",
    "write_records_with_retry",
    "write_orphan_records",
    "_resolve_sha",
    "_resolve_actor",
]
