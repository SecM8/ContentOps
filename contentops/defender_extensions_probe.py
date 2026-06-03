# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Quarterly probe of Defender Graph extension endpoints (F11).

Surfaces when Microsoft GAs the savedQueries / detection-tuning
rules / alert-suppression endpoints documented in
``docs/assets/defender_graph_extensions_deferred.md``. Closes G5
in surface-only form (the actual handlers ship when the endpoints
go GA).

Today the probe returns ``available=False`` for every endpoint —
that's correct, the endpoints aren't GA. Run quarterly (or on
demand) to find out when that changes.

Pure functions; the CLI passes a request callable so tests don't
need an httpx client.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Callable


# Canonical URLs the probe checks. Update this list when Microsoft
# documents a new extension endpoint we want to track.
_ENDPOINTS: dict[str, str] = {
    "savedQueries": "/security/savedQueries",
    "detection_tuning_rules": "/security/rules/detectionTuningRules",
    "alert_suppression_rules": "/security/alertSuppressionRules",
}


@dataclass(frozen=True)
class ProbeResult:
    """One endpoint's probe outcome."""
    name: str
    url: str
    status_code: int | None
    available: bool
    detail: str = ""


@dataclass
class ProbeReport:
    results: list[ProbeResult] = field(default_factory=list)
    note: str = ""

    def has_available(self) -> bool:
        return any(r.available for r in self.results)


def _classify(status_code: int) -> tuple[bool, str]:
    """Map an HTTP status code to (available, detail).

    `available=True` means "Microsoft has shipped a GA-ish surface at
    this URL we should author a handler for." Concretely:

    - 200 / 204 — endpoint exists and returned data
    - 401 / 403 — endpoint exists and answers; permission grant unlocks it
    - 405 — endpoint *path* placed but doesn't accept GET. NOT available:
      docs/assets/defender_graph_extensions_deferred.md is explicit
      that 405 is the canonical "partway through GA" signal — wait
      for HTTP 200 from GET before authoring a handler. The status
      stays in the report (so operators can watch the transition)
      but does not flip the workflow exit code.
    - 404 — endpoint doesn't exist yet
    - everything else — unknown
    """
    if status_code in (200, 204):
        return True, "endpoint live"
    if status_code in (401, 403):
        return True, "endpoint live but auth/permission required"
    if status_code == 405:
        return False, "endpoint live but rejects GET (verb-check needed) — not GA"
    if status_code == 404:
        return False, "not GA"
    return False, f"unexpected status {status_code}"


def probe(
    requester: Callable[[str, str], int],
    *,
    endpoints: dict[str, str] | None = None,
) -> ProbeReport:
    """Probe each endpoint and return a structured report.

    `requester(method, url)` returns the HTTP status code.
    Tests pass a mock that returns whatever they want; the CLI
    passes a wrapper around the existing Graph client.
    """
    targets = endpoints if endpoints is not None else _ENDPOINTS
    results: list[ProbeResult] = []
    for name, path in targets.items():
        try:
            status_code: int | None = requester("HEAD", path)
        except Exception as exc:  # noqa: BLE001 — surfaced as detail
            results.append(ProbeResult(
                name=name, url=path, status_code=None,
                available=False,
                detail=f"request failed: {exc}"[:200],
            ))
            continue
        available, detail = _classify(status_code)
        results.append(ProbeResult(
            name=name, url=path, status_code=status_code,
            available=available, detail=detail,
        ))

    note = ""
    if any(r.available for r in results):
        note = (
            "One or more endpoints look live — author the corresponding "
            "handler under contentops/handlers/ and update "
            "docs/assets/defender_graph_extensions_deferred.md."
        )
    else:
        note = "All endpoints still 404 — Microsoft has not GA'd them. Re-probe next quarter."
    return ProbeReport(results=results, note=note)


def render_markdown(report: ProbeReport) -> str:
    lines: list[str] = []
    lines.append("# Defender extensions probe")
    lines.append("")
    lines.append(f"_{report.note}_")
    lines.append("")
    lines.append("| Endpoint | Path | Status | Available | Detail |")
    lines.append("|---|---|---:|:---:|---|")
    for r in report.results:
        status = str(r.status_code) if r.status_code is not None else "—"
        avail = "yes" if r.available else "no"
        lines.append(
            f"| `{r.name}` | `{r.url}` | {status} | {avail} | {r.detail} |"
        )
    lines.append("")
    return "\n".join(lines)


def render_json(report: ProbeReport) -> str:
    return json.dumps({
        "note": report.note,
        "has_available": report.has_available(),
        "results": [asdict(r) for r in report.results],
    }, indent=2) + "\n"


__all__ = [
    "ProbeResult", "ProbeReport",
    "probe", "render_markdown", "render_json",
]
