# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Coverage / invariant pin tests for the KQL lint surface (Phase 6).

These tests don't exercise individual rule logic (covered by
``test_lint.py``, ``test_lint_strict_take_limit.py``,
``test_snippets.py``, etc.). Instead they pin structural
invariants that have historically drifted:

1. ``KQL_FIELDS_BY_ASSET`` keys equal the set of KQL-bearing
   ``Asset`` enum values (single bidirectional set-equality check
   that combines coverage + non-coverage in one assertion).
2. ``KQLOVERRIDE001-004`` are dispatched by the runner for every
   KQL-bearing asset (regression catch for PR #136 / #138).
3. The severity each rule emits matches what the public docs
   (``docs/reference/feature-catalog.md``) claim — added in the
   PR #144 review follow-up after the reviewer caught 3 severity
   mismatches in the doc table I had just rewritten.

When a future asset is added or renamed, item 1 fails loudly
instead of producing silent coverage gaps (the gap that PR #138
caught for ``sentinel_parser``).
"""

from __future__ import annotations

from pathlib import Path
from textwrap import dedent

from contentops.core.asset import KQL_FIELDS_BY_ASSET, Asset
from contentops.lint.kql import lint_kql


# ---------------------------------------------------------------------------
# Item 1: KQL_FIELDS_BY_ASSET keys EQUAL the set of KQL-bearing assets
# (bidirectional set-equality combines coverage + non-coverage in one check)
# ---------------------------------------------------------------------------


# Asset kinds that intentionally do NOT carry KQL queries. Watchlists
# are CSV data (``rawContent`` + ``itemsSearchKey``); data connectors
# are config bundles (``dataTypes`` + ``kind``). Verified non-KQL
# against the handler implementations.
_NON_KQL_BEARING_ASSETS: frozenset[Asset] = frozenset({
    Asset.SENTINEL_WATCHLIST,
    Asset.SENTINEL_DATA_CONNECTOR,
})


def test_kql_fields_map_matches_kql_bearing_assets_exactly() -> None:
    """Bidirectional set-equality: KQL_FIELDS_BY_ASSET.keys() must
    equal the set of KQL-bearing Asset enum values. Catches both:

    * a KQL-bearing asset missing from the map (PR #138-style gap
      where ``sentinel_parser`` was added to the enum but forgotten
      in the map);
    * a non-KQL-bearing asset accidentally added to the map (e.g.
      someone wires a watchlist field through KQL substitution by
      mistake).

    Replaces three separate per-direction tests with one
    bidirectional check. The previous
    ``test_kql_fields_map_only_references_surviving_assets`` was
    near-tautological because deleted enum values fail at module
    import time; the set-equality form catches a real failure
    mode (drift between enum and map).
    """
    expected = set(Asset) - _NON_KQL_BEARING_ASSETS
    actual = set(KQL_FIELDS_BY_ASSET.keys())
    assert actual == expected, (
        f"KQL_FIELDS_BY_ASSET coverage drift.\n"
        f"  Missing (KQL-bearing assets NOT in the map): "
        f"{sorted(a.value for a in expected - actual)}\n"
        f"  Extra   (non-KQL assets IN the map): "
        f"{sorted(a.value for a in actual - expected)}\n"
        f"Either fix contentops/core/asset.py:KQL_FIELDS_BY_ASSET "
        f"or update _NON_KQL_BEARING_ASSETS in this test."
    )


# ---------------------------------------------------------------------------
# Item 4: KQLOVERRIDE rules dispatched by the runner for KQL-bearing assets
# ---------------------------------------------------------------------------


_SAMPLE_PAYLOADS_BY_ASSET: dict[Asset, str] = {
    Asset.SENTINEL_ANALYTIC: dedent("""\
        id: zz-test
        version: 0.1.0
        asset: sentinel_analytic
        status: production
        payload:
          kind: Scheduled
          displayName: zz
          severity: Low
          query: |
            {{ malformed-placeholder }}
          queryFrequency: PT5M
          queryPeriod: PT5M
          triggerOperator: GreaterThan
          triggerThreshold: 0
    """),
    Asset.SENTINEL_HUNTING: dedent("""\
        id: zz-test
        version: 0.1.0
        asset: sentinel_hunting
        status: production
        payload:
          displayName: zz
          query: |
            {{ malformed-placeholder }}
          category: Hunting Queries
    """),
    Asset.SENTINEL_PARSER: dedent("""\
        id: zz-test
        version: 0.1.0
        asset: sentinel_parser
        status: production
        payload:
          displayName: zz
          query: |
            {{ malformed-placeholder }}
          category: Function
          functionAlias: zz
    """),
    Asset.DEFENDER_CUSTOM_DETECTION: dedent("""\
        id: zz-test
        version: 0.1.0
        asset: defender_custom_detection
        status: production
        payload:
          displayName: zz
          isEnabled: true
          queryCondition:
            queryText: |
              {{ malformed-placeholder }}
    """),
}


def test_kqloverride_rules_dispatched_for_each_kql_bearing_asset(
    tmp_path: Path,
) -> None:
    """Pin: when a KQL-bearing envelope contains a malformed snippet
    placeholder, the runner emits KQLOVERRIDE001 for every
    KQL-bearing asset kind. PR #138 added sentinel_parser to
    KQL_FIELDS_BY_ASSET; this test prevents a future regression
    where a new KQL-bearing asset is added but the snippet engine's
    coverage is forgotten."""
    from contentops.lint.runner import lint_assets

    detections = tmp_path / "detections"
    for asset, body in _SAMPLE_PAYLOADS_BY_ASSET.items():
        sub = detections / asset.value
        sub.mkdir(parents=True, exist_ok=True)
        (sub / "zz-test.yml").write_text(body, encoding="utf-8")

    linted = lint_assets(detections)
    by_asset: dict[Asset, set[str]] = {}
    for lf in linted:
        if lf.asset is None:
            continue
        by_asset.setdefault(lf.asset, set()).update(
            f.rule_id for f in lf.findings
        )

    # The malformed placeholder ``{{ malformed-placeholder }}`` (extra
    # spaces, no .yml suffix) trips KQLOVERRIDE001. Every KQL-bearing
    # asset should produce that finding.
    for asset in _SAMPLE_PAYLOADS_BY_ASSET:
        ids = by_asset.get(asset, set())
        assert "KQLOVERRIDE001" in ids, (
            f"KQLOVERRIDE001 did not fire for {asset.value!r}. "
            f"Findings produced: {sorted(ids)}. The runner may have "
            f"stopped dispatching lint_kql_placeholders for this "
            f"asset kind. Check contentops/lint/runner.py and "
            f"contentops/core/asset.py:KQL_FIELDS_BY_ASSET."
        )


# ---------------------------------------------------------------------------
# Item 4: severity emitted by each rule matches what the docs claim
# (PR #144 review caught 3 severity mismatches. This pin-test catches
# future drift between code-level severity and operator-facing doc
# claims at PR-time, not in cross-phase review.)
# ---------------------------------------------------------------------------


# Single source of truth for "what severity does each rule actually emit?"
# Mirrors the rule tables in docs/reference/feature-catalog.md. When you
# change a rule's severity in the lint code, update BOTH this map AND
# the catalog row -- the assertions below cross-check them.
_EXPECTED_SEVERITIES: dict[str, str] = {
    # Strict-wrapper carrier id (contentops/lint/strict.py) for
    # Kusto.Language diagnostics + allowlist-parse warnings.
    "KQL000": "warning",
    # KQL heuristics in contentops/lint/kql.py
    "KQL001": "error",      # unbalanced brackets
    "KQL002": "error",      # unterminated string
    "KQL003": "error",      # empty / comment-only query
    "KQL004": "warning",    # project *
    "KQL005": "warning",    # bare `| take` -- KQL101 errors regardless of arg
    "KQL006": "warning",    # evaluate bag_unpack
    "KQL007": "error",      # union *
    "KQL008": "warning",    # externaldata() references external infra
    "KQL010": "error",      # cluster()/workspace() cross-scope
    # Snippet rules in contentops/lint/snippets.py (Phase 4)
    "KQLOVERRIDE001": "error",
    "KQLOVERRIDE002": "error",
    "KQLOVERRIDE003": "error",
    "KQLOVERRIDE004": "error",
    # Payload rules in contentops/lint/payload.py
    "PAYLOAD001": "error",   # ARM 400 trigger -- must gate
    "PAYLOAD002": "warning", # advisory: slug truncation, non-destructive
    "PAYLOAD003": "warning", # empty MITRE tactics/techniques mapping
    "PAYLOAD004": "warning", # Defender recommendedActions is null
    "PAYLOAD005": "warning", # FileProfile output column filtered w/o column_ifexists
    "PAYLOAD006": "warning", # entity column not re-projected after FileProfile
    # Strict-mode policy in contentops/lint/strict_rules.py
    "KQL101": "error",       # | take / | limit forbidden in production
    # Envelope-metadata rules in contentops/lint/metadata_rules.py.
    # Baseline severities (the non-strict default path): META002-005
    # escalate to error under policy.scaffoldStrict=true and META001
    # escalates on unparseable/strict-stale, but the catalog + this pin
    # record the out-of-the-box severity. META006/007/009 are info-only;
    # META008 (scaffold placeholder past experimental) is always error.
    # These are not tripped by _all_emitted_severities()'s kitchen-sink
    # helper (it doesn't run lint_metadata), so the emitted-severity
    # cross-check below skips them; they are still pinned here so the
    # generated catalog's lint table stays complete and in sync.
    "META001": "warning",
    "META002": "warning",
    "META003": "warning",
    "META004": "warning",
    "META005": "warning",
    "META006": "info",
    "META007": "info",
    "META008": "error",
    "META009": "info",
}


def _all_emitted_severities() -> dict[str, set[str]]:
    """Run every rule against a query / payload designed to trip it,
    then return ``{rule_id: {severity, ...}}``. A rule that emits
    multiple severities (different findings) shows up as a multi-set.
    """
    from contentops.lint.kql import lint_kql
    from contentops.lint.payload import lint_payload
    from contentops.lint.snippets import (
        lint_kql_placeholders, lint_overrides_directory,
    )
    from contentops.lint.strict_rules import run_python_rules

    seen: dict[str, set[str]] = {}

    def _record(findings):
        for f in findings:
            seen.setdefault(f.rule_id, set()).add(f.severity)

    # Kitchen-sink query designed to trip as many heuristic + strict
    # rules as possible. ``kind`` is currently unused by the
    # heuristics but pass each kind through for forward compat with
    # future per-kind rules.
    bad_query = (
        "(\n"               # unbalanced bracket  -> KQL001
        '"unterminated\n'   #                      -> KQL002
        "project *\n"       #                      -> KQL004
        "| take\n"          # bare take            -> KQL005
        "| evaluate bag_unpack(x)\n"  #             -> KQL006
        "| union *\n"       #                      -> KQL007
        "| take 100\n"      # KQL101 strict-mode   -> KQL101
    )
    for kind in ("sentinel_analytic", "sentinel_hunting", "sentinel_parser"):
        _record(lint_kql(bad_query, kind=kind))
    # Empty query -> KQL003
    _record(lint_kql("   \n  // only comment\n", kind="sentinel_analytic"))

    # Snippet-placeholder rules (KQLOVERRIDE001-003)
    _record(lint_kql_placeholders(
        "{{ bad-placeholder }}\n"           # 001 (spaces)
        "M\n{{../etc/secret.yml}}\nN\n"     # 002 (path traversal)
        "X | where {{a/b.yml}} | take 1\n"  # 003 (mid-line)
    ))

    # PAYLOAD001 -- templateVersion without alertRuleTemplateName
    from contentops.core.asset import Asset
    _record(lint_payload(
        {"templateVersion": "1.0.0", "displayName": "X"},
        asset=Asset.SENTINEL_ANALYTIC,
    ))
    # PAYLOAD002 -- displayName whose slug exceeds 80 chars
    _record(lint_payload(
        {"displayName": "x" * 200},
        asset=Asset.SENTINEL_ANALYTIC,
    ))
    # PAYLOAD005 -- FileProfile output column filtered without column_ifexists
    _record(lint_payload(
        {"queryCondition": {"queryText":
            "DeviceEvents | invoke FileProfile(SHA1,1000) | where GlobalPrevalence >= 50"}},
        asset=Asset.DEFENDER_CUSTOM_DETECTION,
    ))
    # PAYLOAD006 -- entity column not re-projected after the FileProfile invoke
    _record(lint_payload(
        {"queryCondition": {"queryText":
            "DeviceEvents | invoke FileProfile(SHA1,1000) | distinct SHA1"},
         "detectionAction": {"alertTemplate": {
             "impactedAssets": [{"identifier": "deviceId"}]}}},
        asset=Asset.DEFENDER_CUSTOM_DETECTION,
    ))

    # KQL101 strict-mode (already covered by lint_kql call above
    # via the kitchen-sink query, but pin via run_python_rules too)
    _record(run_python_rules("T | take 100"))

    # KQLOVERRIDE004 -- requires a file fixture; covered separately
    # below to keep this helper synchronous + filesystem-free.

    return seen


def test_emitted_severity_matches_documented_severity() -> None:
    """Every rule actually emitted by the lint pipeline must emit
    exactly the severity the public docs claim for it.

    Would have caught the 3 doc-mismatch findings the reviewer
    surfaced on PR #144 at PR-time instead of in cross-phase review.
    """
    emitted = _all_emitted_severities()
    mismatches: list[str] = []
    for rule_id, expected_sev in _EXPECTED_SEVERITIES.items():
        if rule_id not in emitted:
            # KQLOVERRIDE004 is filesystem-driven; not exercised by
            # the helper. Skip rules we didn't try to trip.
            continue
        emitted_sevs = emitted[rule_id]
        if emitted_sevs != {expected_sev}:
            mismatches.append(
                f"  {rule_id}: doc/_EXPECTED says {expected_sev!r}, "
                f"code emits {sorted(emitted_sevs)!r}"
            )
    assert not mismatches, (
        "Emitted severity does not match documented severity. Either "
        "fix the rule's emit, fix _EXPECTED_SEVERITIES in this file, "
        "or fix docs/reference/feature-catalog.md (probably all "
        "three need to agree).\n" + "\n".join(mismatches)
    )


def test_kqloverride004_emits_error(tmp_path) -> None:
    """KQLOVERRIDE004 is the one rule that's filesystem-driven (it
    walks ``overrides/**/*.yml``). Pin its severity separately."""
    from contentops.lint.snippets import lint_overrides_directory
    overrides = tmp_path / "overrides"
    overrides.mkdir()
    # Missing 'content' key -> KQLOVERRIDE004
    (overrides / "bad.yml").write_text(
        "description: 'no content key'\n", encoding="utf-8",
    )
    findings = lint_overrides_directory(overrides)
    assert len(findings) == 1
    _path, finding = findings[0]
    assert finding.rule_id == "KQLOVERRIDE004"
    assert finding.severity == _EXPECTED_SEVERITIES["KQLOVERRIDE004"]


# ---------------------------------------------------------------------------
# Item 5: every Asset enum value has a registered handler factory
# (Seam E from the cross-phase review). Catches a future asset
# addition that updates ``Asset`` + ``KQL_FIELDS_BY_ASSET`` but
# forgets to wire a factory in ``register_default_handlers``. The
# runtime failure mode without this test is a confusing "no handler
# for <kind>: <path>" line at apply time -- this test fails loudly
# at PR-time instead.
# ---------------------------------------------------------------------------


def test_every_asset_has_registered_handler(
    tmp_path, monkeypatch,
) -> None:
    """Every ``Asset`` enum value must have a handler factory
    registered by ``register_default_handlers`` when both engines
    are enabled. Mirrors the severity-pin and KQL_FIELDS_BY_ASSET
    coverage tests -- forces the developer adding a new asset to
    update three places (enum, KQL map, handler factory) in
    lock-step.
    """
    from textwrap import dedent
    from contentops.cli.handler_factories import register_default_handlers
    from contentops.core.registry import default_registry

    # Use a tmp tenant.yml that enables BOTH engines so every
    # handler factory registers. The engine-gating logic added in
    # PR #133/#134 conditionally skips factories when an engine is
    # disabled; we want full coverage for this parity check.
    cfg_path = tmp_path / "tenant.yml"
    cfg_path.write_text(dedent("""\
        tenant:
          name: parity-test
          tenantId: aad-1
          defender:
            enabled: true
          sentinelWorkspaces:
            - role: prod
              subscriptionId: sub-prod
              resourceGroup: rg
              workspaceName: law-prod
              location: westeurope
    """), encoding="utf-8")

    monkeypatch.setattr("contentops.config.CONFIG_PATH", cfg_path)
    monkeypatch.delenv("PIPELINE_WORKSPACE_NAME", raising=False)
    default_registry.reset_all()
    try:
        register_default_handlers()
        missing = [a for a in Asset if not default_registry.has(a)]
        assert not missing, (
            f"Asset(s) {sorted(a.value for a in missing)} have no "
            f"registered handler factory. Update "
            f"contentops/cli/handler_factories.py:register_default_handlers "
            f"so every Asset enum value gets a factory (or document "
            f"the omission with a comment + skip in this test)."
        )
    finally:
        default_registry.reset_all()
