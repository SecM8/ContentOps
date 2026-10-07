# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""MITRE ATT&CK coverage reporting (M2)."""

from __future__ import annotations

from contentops.coverage.corpus import (
    Corpus,
    CorpusEntry,
    CoverageScope,
    load_corpus,
)
from contentops.coverage.extract import ExtractedCoverage, extract_mitre
from contentops.coverage.report import (
    ALL_TACTICS,
    CoverageLevel,
    CoverageReport,
    CoverageSummary,
    TacticCoverage,
    compute_coverage,
    coverage_summary,
    render_badge,
    render_json,
    render_markdown,
    summary_from_corpus,
)

__all__ = [
    "ALL_TACTICS",
    "Corpus",
    "CorpusEntry",
    "CoverageLevel",
    "CoverageReport",
    "CoverageScope",
    "CoverageSummary",
    "ExtractedCoverage",
    "TacticCoverage",
    "compute_coverage",
    "coverage_summary",
    "extract_mitre",
    "load_corpus",
    "render_badge",
    "render_json",
    "render_markdown",
    "summary_from_corpus",
]
