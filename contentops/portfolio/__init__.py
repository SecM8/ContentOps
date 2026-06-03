# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Portfolio reporting (W4-6).

Emits a flat per-detection inventory (CSV / JSON) used by SOC leadership
to triage the detection catalog. Renders inputs only by default;
``--with-telemetry`` augments with F20 telemetry columns; ``--rank``
layers an effectiveness score on top (see :mod:`contentops.portfolio.score`).
"""

from __future__ import annotations

from contentops.portfolio.report import (
    COLUMNS,
    build_rows,
    iso8601_duration_to_minutes,
    write_csv,
    write_json,
)
from contentops.portfolio.score import (
    ScoreWeights,
    compute_score,
    parse_weights,
    rank_rows,
)

__all__ = [
    "COLUMNS",
    "ScoreWeights",
    "build_rows",
    "compute_score",
    "iso8601_duration_to_minutes",
    "parse_weights",
    "rank_rows",
    "write_csv",
    "write_json",
]
