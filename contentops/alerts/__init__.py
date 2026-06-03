# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Alert tracking and daily rollup reporting.

This module provides:

* **models** -- Pydantic v2 models for Graph alerts, Sentinel incidents,
  and a unified ``NormalizedAlert`` shape consumed by the rollup engine.
* **provider** -- ``GraphAlertsProvider`` that fetches alerts from the
  Microsoft Graph Security ``alerts_v2`` endpoint (v1.0), with automatic
  fallback to Sentinel ARM incidents when Graph is unavailable.
* **rollup** -- daily rollup computation (classification counts, MTTR,
  top titles, rule effectiveness) and Markdown / JSON rendering.
* **report** -- multi-day trend reports (daily volume, classification
  trend, MTTR trend, noisiest rules, unresolved backlog).
* **detection_health** -- per-detection health metrics and
  recommendations (TUNE / SILENT / HEALTHY / REVIEW).
* **health_snapshot** -- JSON snapshot + week-over-week delta for
  detection health reports.
* **health_badge** -- shields.io endpoint badge for detection health.
* **ledger** -- persistent PII-free alert ledger (JSONL append-only).
* **sync** -- smart-sync orchestrator with watermark-based lookback.
"""

__all__ = [
    "daily_store",
    "detection_health",
    "health_badge",
    "health_snapshot",
    "ledger",
    "models",
    "provider",
    "report",
    "rollup",
    "sync",
]
