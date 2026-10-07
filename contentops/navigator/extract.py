# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Pure extractors for the three Navigator data axes.

Each extractor returns a list of ``TechniqueHit`` records. Aggregation
(deduplication, parent rollup, scoring) lives in :func:`score_techniques`
so the extractors stay focused on their respective sources.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from contentops.coverage.corpus import Corpus, CoverageScope, load_corpus
from contentops.coverage.matrix import AttackMatrix, load_matrix, normalise_technique_id


@dataclass(frozen=True)
class TechniqueHit:
    """One (technique_id, display_name, source) triple.

    ``source`` is one of ``"repo"``, ``"deployed"``, or ``"firings"``.
    Carried through aggregation so the renderer can break down counts
    per axis in the Navigator layer's ``metadata`` block.
    """

    technique_id: str
    display_name: str
    source: str


def _current_ids(values: Iterable[Any], matrix: AttackMatrix) -> list[str]:
    """Normalise ids (" t1059" -> T1059), remap revoked ones and keep only
    techniques in the current ATT&CK matrix -- the same rules the coverage
    engine applies, so every axis speaks the same id space."""
    out: list[str] = []
    for value in values:
        tid = normalise_technique_id(value)
        if tid is None:
            continue
        current, _status = matrix.resolve(tid)
        if current is not None and current not in out:
            out.append(current)
    return out


def _as_list(value: Any) -> list[Any]:
    return list(value) if isinstance(value, (list, tuple)) else []


# ---------------------------------------------------------------------------
# Axis 1: repo envelopes
# ---------------------------------------------------------------------------


def extract_repo_techniques(
    detections_root: Path,
    *,
    scope: CoverageScope | None = None,
    corpus: Corpus | None = None,
) -> list[TechniqueHit]:
    """Collect technique ids from the repo's in-scope detections.

    Uses the shared coverage engine (:func:`contentops.coverage.corpus.load_corpus`):
    metadata *and* the platform-native payload fields (so collected rules,
    which carry their ATT&CK tags only in the payload, are not empty), the
    same scope as ``contentops coverage`` (default: enabled production
    rules, hunting excluded), so this axis covers exactly the techniques
    the badge counts. The display name is the payload ``displayName`` --
    the same key the deployed axis uses, so one rule seen in the repo and
    deployed scores once.
    """
    corpus = corpus or load_corpus(detections_root, scope=scope)
    out: list[TechniqueHit] = []
    for entry in corpus.in_scope():
        for tech in entry.mitre.counted_techniques:
            out.append(TechniqueHit(
                technique_id=tech, display_name=entry.display_name, source="repo",
            ))
    return out


# ---------------------------------------------------------------------------
# Axis 2: deployed rules (Sentinel ARM + Defender Graph)
# ---------------------------------------------------------------------------


def extract_sentinel_rule_techniques(
    provider: Any, *, include_disabled: bool = False,
) -> list[TechniqueHit]:
    """Pull techniques from live Sentinel analytic-rule definitions.

    ``provider`` is a ``contentops.providers.sentinel_arm.SentinelArmProvider``
    (duck-typed so tests can pass a stub); only ``list_resource("alertRules")``
    is called, which follows ARM ``nextLink`` pagination -- a large
    workspace's rules beyond the first page are no longer dropped.

    Reads ``techniques`` and ``subTechniques``. Disabled rules detect
    nothing and are skipped unless ``include_disabled``. Returns one
    TechniqueHit per (rule, technique) pair.
    """
    try:
        rules = provider.list_resource("alertRules")
    except Exception as exc:
        raise RuntimeError(f"Sentinel alertRules fetch failed: {exc}") from exc

    matrix = load_matrix()
    out: list[TechniqueHit] = []
    for rule in rules or []:
        if not isinstance(rule, dict):
            continue
        properties = rule.get("properties") or {}
        if not include_disabled and properties.get("enabled") is False:
            continue
        display = (
            properties.get("displayName")
            or rule.get("name")
            or "(unnamed Sentinel rule)"
        )
        ids = _as_list(properties.get("techniques")) + _as_list(properties.get("subTechniques"))
        for tech in _current_ids(ids, matrix):
            out.append(TechniqueHit(
                technique_id=tech, display_name=str(display), source="deployed",
            ))
    return out


def extract_defender_rule_techniques(
    client: Any, *, include_disabled: bool = False,
) -> list[TechniqueHit]:
    """Pull techniques from live Defender XDR custom detection definitions.

    ``client`` is a ``contentops.defender.client.DefenderClient`` (or a
    duck-typed equivalent with a ``list_rules()`` method). Internally
    that method calls ``GET https://graph.microsoft.com/beta/security/
    rules/detectionRules`` with the App Registration's
    ``CustomDetection.Read.All`` (or ``ReadWrite.All``) scope.

    The Defender side carries MITRE techniques on the
    ``detectionAction.alertTemplate.mitreTechniques`` path. Disabled
    rules (``status`` disabled / autoDisabled) are skipped unless
    ``include_disabled``.
    """
    from contentops.defender.rule_status import is_enabled

    try:
        rules = client.list_rules()
    except Exception as exc:
        raise RuntimeError(f"Defender detectionRules fetch failed: {exc}") from exc

    matrix = load_matrix()
    out: list[TechniqueHit] = []
    for rule in rules or []:
        if not isinstance(rule, dict):
            continue
        if not include_disabled and not is_enabled(rule):
            continue
        display = rule.get("displayName") or rule.get("id") or "(unnamed Defender rule)"
        action = rule.get("detectionAction") or {}
        template = action.get("alertTemplate") or {}
        for tech in _current_ids(_as_list(template.get("mitreTechniques")), matrix):
            out.append(TechniqueHit(
                technique_id=tech, display_name=str(display), source="deployed",
            ))
    return out


# ---------------------------------------------------------------------------
# Axis 3: live firings via SecurityAlert
# ---------------------------------------------------------------------------


def firing_techniques_query(since_days: int = 365) -> str:
    """Return the KQL that powers the firings extractor.

    Mirrors the operator's original Microsoft2ATT&CK script:

    * 365-day lookback (configurable).
    * Excludes Sentinel-native alerts (already counted via axis 2 from
      the analytic-rule definitions) AND Defender custom detections
      (also counted via axis 2). Leaves Defender's built-in product
      alerts (MDE, MDO, MDCA, MDI, MDA) -- the rule definitions for
      these live in Microsoft's product code, not in our repo, so the
      firings ARE the only signal we get for them.
    * ``mv-expand`` the JSON ``Techniques`` array so one alert row
      with three techniques becomes three result rows.
    """
    return f"""
SecurityAlert
| where TimeGenerated > ago({since_days}d)
| where not(ProductName == "Azure Sentinel")
  and not(ProductName == "Microsoft Defender Advanced Threat Protection"
          and AlertType == "CustomDetection")
| where isnotempty(Techniques)
| extend tech_list = parse_json(Techniques)
| mv-expand tech_list to typeof(string)
| project technique_id = tostring(tech_list), display_name = DisplayName
| where isnotempty(technique_id)
""".strip()


def extract_firing_techniques(
    *,
    workspace_id: str,
    token: str,
    since_days: int = 365,
    query_runner: Any = None,
) -> list[TechniqueHit]:
    """Fetch (technique, rule-name) pairs from the workspace's SecurityAlert.

    ``query_runner`` defaults to ``contentops.workspace_kql.query`` -- the
    parameter exists so tests can swap in a mock. Returns one
    TechniqueHit per (rule_name, technique) pair surfaced in the
    window.
    """
    if query_runner is None:
        from contentops.workspace_kql import query as query_runner  # noqa: PLR0915
    result = query_runner(
        firing_techniques_query(since_days=since_days),
        workspace_id=workspace_id,
        token=token,
    )
    matrix = load_matrix()
    out: list[TechniqueHit] = []
    for row in result.rows:
        name = row.get("display_name")
        if not isinstance(name, str) or not name:
            continue
        for tech in _current_ids([row.get("technique_id")], matrix):
            out.append(TechniqueHit(
                technique_id=tech, display_name=name, source="firings",
            ))
    return out


# ---------------------------------------------------------------------------
# Scoring: aggregate the per-axis hits into Navigator-ready records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ScoredTechnique:
    technique_id: str
    score: int                       # unique display names across all axes
    repo_count: int
    deployed_count: int
    firings_count: int
    contributing_rules: tuple[str, ...]


def score_techniques(hits: list[TechniqueHit]) -> list[ScoredTechnique]:
    """Aggregate hits into scored techniques.

    The score for a technique is the count of *unique display names*
    contributing across all axes -- a technique covered by three
    different rules (whether repo, deployed, or firing) scores 3.
    Per-axis counts are surfaced separately so the renderer (or
    downstream consumers) can break down where coverage comes from.

    Parent technique rollup: when only ``Txxxx.NNN`` sub-techniques
    are covered, the parent ``Txxxx`` is added with score 0 so the
    Navigator UI shows a placeholder tile. Reproduces the operator's
    original script behaviour.
    """
    # name_sets[technique] -> set of distinct display names (across axes)
    # per_source_names[technique][axis] -> set of names from that axis
    name_sets: dict[str, set[str]] = {}
    per_source_names: dict[str, dict[str, set[str]]] = {}
    for hit in hits:
        ns = name_sets.setdefault(hit.technique_id, set())
        ns.add(hit.display_name)
        psn = per_source_names.setdefault(hit.technique_id, {})
        psn.setdefault(hit.source, set()).add(hit.display_name)

    scored: list[ScoredTechnique] = []
    for tech_id, names in name_sets.items():
        per = per_source_names.get(tech_id, {})
        scored.append(ScoredTechnique(
            technique_id=tech_id,
            score=len(names),
            repo_count=len(per.get("repo", set())),
            deployed_count=len(per.get("deployed", set())),
            firings_count=len(per.get("firings", set())),
            contributing_rules=tuple(sorted(names)),
        ))

    # Parent rollup: any covered sub-technique implies the parent tile
    # must render too, even if no rule names the bare parent.
    parents_to_add: dict[str, ScoredTechnique] = {}
    have = {s.technique_id for s in scored}
    for s in scored:
        if "." in s.technique_id:
            parent = s.technique_id.split(".", 1)[0]
            if parent not in have and parent not in parents_to_add:
                parents_to_add[parent] = ScoredTechnique(
                    technique_id=parent,
                    score=0,
                    repo_count=0,
                    deployed_count=0,
                    firings_count=0,
                    contributing_rules=(),
                )
    scored.extend(parents_to_add.values())
    scored.sort(key=lambda s: s.technique_id)
    return scored


__all__ = [
    "TechniqueHit",
    "ScoredTechnique",
    "extract_defender_rule_techniques",
    "extract_firing_techniques",
    "extract_repo_techniques",
    "extract_sentinel_rule_techniques",
    "firing_techniques_query",
    "score_techniques",
]
