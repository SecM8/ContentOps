# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Markdown status reports for the internal-facing dashboard.

Two thin renderers over existing models:

* :func:`contentops.status.configuration.render_configuration` —
  reads :class:`contentops.devex.conformance.ConformanceReport` for
  layers L1 + L2 (local install + tenant config) and renders a
  PASS/FAIL/SKIP table per layer.

* :func:`contentops.status.deployments.render_deployments` —
  joins :func:`contentops.core.discovery.discover_assets`,
  :class:`contentops.state.EnvState`, and
  :func:`contentops.audit_query.query_latest` into per-asset-kind
  tables of what is deployed, when, by which sha, and the last
  audit action.

Both are committed under ``docs/status/`` and regenerated daily by
``.github/workflows/status-refresh.yml``. Pure repo + state-file
introspection; no tenant API calls.
"""

from contentops.status.configuration import render_configuration
from contentops.status.deployments import render_deployments

__all__ = ["render_configuration", "render_deployments"]
