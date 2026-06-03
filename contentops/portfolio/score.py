# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Rule effectiveness scoring on top of telemetry-augmented portfolio rows.

The score is a single number per rule, weighting the three behaviours a
detection-engineer typically watches:

* **true positives** (``incidents_30d - closed_fp_30d``) — incidents
  raised by the rule that the analyst kept open. Positive contribution.
* **false positives** (``closed_fp_30d``) — incidents the analyst
  closed as benign. Negative contribution, weighted higher than TPs
  because analyst time burned on bad alerts is the dominant cost.
* **silence** (``alerts_30d == 0``) — rule didn't fire at all in the
  lookback window. A flat penalty rather than scaled, since silence
  is a binary "is this rule still useful?" signal more than a
  magnitude.

Pure function — same inputs always produce the same output. Telemetry
fetching, sorting, rendering all live in the CLI; this module only
computes.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ScoreWeights:
    """The three knobs that govern the scoring formula.

    Defaults reflect operator priors:

    * ``tp=1`` baseline.
    * ``fp=2`` — analyst-time-burned is twice as costly as
      analyst-time-saved-by-a-TP is valuable. Sentinel reality:
      a closed FP burns ~10-15 minutes of triage; a TP that wasn't
      caught elsewhere is worth a multi-hour incident.
    * ``silence=30`` — a 30-day quiet window with the rule enabled
      is a strong "retire or tune" signal; same magnitude as a
      day-per-month penalty.

    Override via ``contentops portfolio --score-weights tp=1,fp=3,silence=60``.
    """
    tp: float = 1.0
    fp: float = 2.0
    silence: float = 30.0


def parse_weights(spec: str | None) -> ScoreWeights:
    """Parse a ``key=value,key=value`` CLI spec into ScoreWeights.

    Unknown keys are rejected with ``ValueError`` so a typo never
    silently uses defaults — the operator's intent is explicit.
    Empty / None returns the defaults.
    """
    if not spec:
        return ScoreWeights()
    known = {"tp", "fp", "silence"}
    out: dict[str, float] = {}
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "=" not in chunk:
            raise ValueError(
                f"--score-weights entry {chunk!r} is not key=value "
                f"(expected e.g. tp=1,fp=2,silence=30)"
            )
        key, _, value = chunk.partition("=")
        key = key.strip()
        if key not in known:
            raise ValueError(
                f"--score-weights unknown key {key!r}; "
                f"expected one of {sorted(known)}"
            )
        try:
            out[key] = float(value.strip())
        except ValueError as exc:
            raise ValueError(
                f"--score-weights value for {key!r} is not numeric: {value!r}"
            ) from exc
    return ScoreWeights(**{**ScoreWeights().__dict__, **out})


def compute_score(row: dict[str, Any], weights: ScoreWeights) -> float | None:
    """Compute the effectiveness score for one portfolio row.

    Returns ``None`` when the row has no telemetry data (every
    ``*_30d`` field is None) — distinguishes "unknown effectiveness"
    from "scored zero." A row that was matched against telemetry but
    found to have all-zero values scores 0.0 (eligible for ranking;
    silence penalty applies).

    Sentinel hunting queries and Defender-tenant rules with no
    incident lineage still receive a score — they'll just sit at the
    silence-penalty floor, surfacing exactly the way a retirement
    candidate should.
    """
    alerts = row.get("alerts_30d")
    incidents = row.get("incidents_30d")
    closed_fp = row.get("closed_fp_30d")

    # No telemetry merged at all — distinct from "telemetry says zero."
    if alerts is None and incidents is None and closed_fp is None:
        return None

    incidents_val = int(incidents or 0)
    closed_fp_val = int(closed_fp or 0)
    alerts_val = int(alerts or 0)

    tp = max(0, incidents_val - closed_fp_val)
    fp = closed_fp_val
    silent = alerts_val == 0

    score = (tp * weights.tp) - (fp * weights.fp)
    if silent:
        score -= weights.silence
    return round(score, 2)


def rank_rows(
    rows: list[dict[str, Any]],
    weights: ScoreWeights,
) -> list[dict[str, Any]]:
    """Annotate every row with a ``score`` field and sort ascending.

    Ascending = lowest first = retirement candidates surface at the
    top of the list. Rows with ``score is None`` (no telemetry) sort
    to the bottom — operators want to see scored rules first; the
    unknowns are a separate triage step.
    """
    for row in rows:
        row["score"] = compute_score(row, weights)
    return sorted(
        rows,
        key=lambda r: (
            r["score"] is None,
            r["score"] if r["score"] is not None else 0,
        ),
    )


__all__ = [
    "ScoreWeights",
    "compute_score",
    "parse_weights",
    "rank_rows",
]
