# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Regression for L-2: KQL101 fires on production envelopes without --strict.

Previously ``no_take_or_limit`` lived only in the strict pipeline, so
``contentops lint`` (no flag) silently accepted a production rule
with ``| take 100``. The runner now invokes the strict Python rules
inline and downgrades severity to warning on non-production
envelopes, mirroring the gradual-strict pattern used for META rules.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from contentops.core.asset import Asset
from contentops.lint.runner import lint_assets


_PROD_YAML = """\
id: noisy-rule
version: 0.1.0
asset: sentinel_analytic
status: production
metadata:
  arm_name: abc
payload:
  query: |
    SecurityEvent | take 50
"""

_EXPERIMENTAL_YAML = _PROD_YAML.replace("status: production", "status: experimental")


def _write(tmp_path: Path, content: str) -> Path:
    target = tmp_path / "sentinel_analytic" / "rule.yml"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    return target


def test_kql101_errors_on_production_without_strict(tmp_path: Path) -> None:
    _write(tmp_path, _PROD_YAML)
    results = lint_assets(tmp_path, asset_filter=Asset.SENTINEL_ANALYTIC)
    assert results
    k101 = [
        f for r in results for f in r.findings if f.rule_id == "KQL101"
    ]
    assert len(k101) == 1
    assert k101[0].severity == "error"


def test_kql101_warns_on_non_production_without_strict(tmp_path: Path) -> None:
    _write(tmp_path, _EXPERIMENTAL_YAML)
    results = lint_assets(tmp_path, asset_filter=Asset.SENTINEL_ANALYTIC)
    assert results
    k101 = [
        f for r in results for f in r.findings if f.rule_id == "KQL101"
    ]
    assert len(k101) == 1
    assert k101[0].severity == "warning"
