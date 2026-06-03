# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Refresh the bundled MITRE ATT&CK Enterprise matrix.

Fetches the latest enterprise-attack STIX bundle from MITRE's
maintained GitHub repo (https://github.com/mitre-attack/attack-stix-data),
extracts the minimum data ContentOps needs for coverage analysis, writes
it to ``contentops/coverage/data/mitre_attack_full.json``.

We pull from ``mitre-attack/attack-stix-data`` (the actively maintained
STIX 2.1 source), NOT the legacy ``mitre/cti`` repo, which MITRE froze at
ATT&CK v15.1 and no longer updates.

The bundled output carries three flat tables:

* ``tactics`` — the 14 enterprise tactics with shortName + name
* ``techniques`` — parent techniques (~200): id, name, tactics
* ``sub_techniques`` — sub-techniques (~470): id, name, parent_id, tactics

Tactic identifiers are canonical PascalCase (``DefenseEvasion``,
``CommandAndControl``, ...) so they match ``coverage.report.ALL_TACTICS``
and ``coverage.extract._CANONICAL_TACTICS``; a CI test
(``tests/v2/test_coverage_gaps.py``) asserts the committed file never
drifts off the canonical set.

Cadence: ``.github/workflows/attack-matrix-refresh.yml`` runs this weekly
and opens a PR with the refreshed bundle. The pipeline NEVER calls this
script at runtime — coverage reads the committed file (offline, so it
works for locked-down adopters). This script is purely a generator.
"""

from __future__ import annotations

import json
import sys
import urllib.request
from pathlib import Path


STIX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    "enterprise-attack/enterprise-attack.json"
)
OUT_PATH = (
    Path(__file__).resolve().parent.parent
    / "contentops" / "coverage" / "data" / "mitre_attack_full.json"
)


def fetch_stix() -> dict:
    print(f"fetching {STIX_URL} ...", file=sys.stderr)
    with urllib.request.urlopen(STIX_URL, timeout=120) as resp:
        return json.load(resp)


def _technique_id(stix_obj: dict) -> str | None:
    for ref in stix_obj.get("external_references", []) or []:
        if ref.get("source_name") == "mitre-attack":
            ext_id = ref.get("external_id")
            if isinstance(ext_id, str) and ext_id.startswith("T"):
                return ext_id
    return None


# The upstream STIX surfaces "Defense Evasion" under two non-Sentinel
# short-names ("stealth" and "defense-impairment"). Microsoft Sentinel's
# Microsoft.SecurityInsights/alertRules tactic enum — the vocabulary every
# deployed detection is tagged with and the one coverage.report.ALL_TACTICS
# / coverage.extract._CANONICAL_TACTICS use — only has ``DefenseEvasion``.
# Normalise the source names back onto the canonical Sentinel tactic so a
# technique MITRE files under either folds into DefenseEvasion coverage
# (rather than being silently dropped by the canonical-tactic filter at
# read time). tests/v2/test_coverage_gaps.py asserts the committed file
# carries only canonical tactics, so this map must keep them in sync.
_TACTIC_NORMALIZE: dict[str, str] = {
    "Stealth": "DefenseEvasion",
    "DefenseImpairment": "DefenseEvasion",
}


def _canonical_tactic(short: str) -> str:
    """phase/short-name (kebab) -> canonical PascalCase Sentinel tactic."""
    pascal = "".join(part.capitalize() for part in short.split("-"))
    return _TACTIC_NORMALIZE.get(pascal, pascal)


def _tactics_from_kill_chain(stix_obj: dict) -> list[str]:
    """Map ATT&CK kill_chain_phases short-names to canonical PascalCase
    tactic identifiers used everywhere else in the pipeline.

    De-dupes within a single technique so a technique tagged with both
    ``stealth`` and ``defense-impairment`` (which both normalise to
    ``DefenseEvasion``) lists DefenseEvasion once."""
    out: list[str] = []
    for phase in stix_obj.get("kill_chain_phases", []) or []:
        if phase.get("kill_chain_name") != "mitre-attack":
            continue
        tactic = _canonical_tactic(phase.get("phase_name", ""))
        if tactic and tactic not in out:
            out.append(tactic)
    return out


def extract(bundle: dict) -> dict:
    """Walk the STIX bundle and pull tactics + techniques + sub-techniques.

    STIX object types:

    * ``x-mitre-tactic`` — the 14 tactics
    * ``attack-pattern`` — techniques (incl. sub-techniques, distinguished
      by ``x_mitre_is_subtechnique: true``)
    """
    # Keyed by canonical id so the two source tactics that normalise to
    # DefenseEvasion (stealth, defense-impairment) collapse into a single
    # canonical tactic row instead of two.
    tactics_by_id: dict[str, dict] = {}
    parents: list[dict] = []
    subs: list[dict] = []

    for obj in bundle.get("objects", []) or []:
        # Skip deprecated / revoked content — coverage of a retired
        # technique would be a false positive for "this tenant is up to
        # date with MITRE."
        if obj.get("revoked") is True or obj.get("x_mitre_deprecated") is True:
            continue

        if obj.get("type") == "x-mitre-tactic":
            short = obj.get("x_mitre_shortname", "")
            canonical = _canonical_tactic(short)
            # First writer wins for the display name; the canonical
            # DefenseEvasion row keeps a stable label even though it is
            # sourced from "stealth"/"defense-impairment" upstream.
            if canonical == "DefenseEvasion":
                tactics_by_id[canonical] = {
                    "id": canonical,
                    "short_name": "defense-evasion",
                    "name": "Defense Evasion",
                }
            else:
                tactics_by_id.setdefault(canonical, {
                    "id": canonical,
                    "short_name": short,
                    "name": obj.get("name", ""),
                })
            continue

        if obj.get("type") != "attack-pattern":
            continue
        tid = _technique_id(obj)
        if not tid:
            continue
        tactics_list = _tactics_from_kill_chain(obj)
        record = {
            "id": tid,
            "name": obj.get("name", ""),
            "tactics": tactics_list,
        }
        if obj.get("x_mitre_is_subtechnique") is True:
            # Sub-technique ids look like "T1059.001" — split off the parent.
            parent_id = tid.split(".", 1)[0] if "." in tid else None
            record["parent_id"] = parent_id
            subs.append(record)
        else:
            parents.append(record)

    tactics = sorted(tactics_by_id.values(), key=lambda t: t["id"])
    parents.sort(key=lambda t: t["id"])
    subs.sort(key=lambda t: t["id"])

    return {
        "source": "https://github.com/mitre-attack/attack-stix-data enterprise-attack",
        "schema_version": 2,
        "tactics": tactics,
        "techniques": parents,
        "sub_techniques": subs,
    }


def main() -> int:
    bundle = fetch_stix()
    extracted = extract(bundle)
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(
        json.dumps(extracted, indent=2, sort_keys=False) + "\n",
        encoding="utf-8",
    )
    counts = (
        f"{len(extracted['tactics'])} tactics, "
        f"{len(extracted['techniques'])} techniques, "
        f"{len(extracted['sub_techniques'])} sub-techniques"
    )
    print(f"wrote {OUT_PATH}: {counts}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
