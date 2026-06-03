# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Shared helpers for handler ``delete(remote_id) -> ActionResult``.

Every write-capable handler exposes a ``delete()`` method. The actual
HTTP call differs — Sentinel handlers use ``SentinelArmProvider.delete_resource``,
Defender handlers use the Graph beta provider, etc. — but the
response interpretation is identical: 200 / 204 / 404 are all
``success`` (404 ⇒ already gone, idempotent), anything else maps to
``error-<status_code>`` with the response body in ``detail`` and
``error``.

Keeping the response-handling in one place means that every handler
behaves the same way under the prune CLI's max-deletes / audit
machinery.
"""

from __future__ import annotations

import httpx

from contentops.core.asset import Asset
from contentops.core.result import ActionResult, PlanAction


def delete_result_from_response(
    remote_id: str,
    asset: Asset,
    response: httpx.Response,
) -> ActionResult:
    """Normalise a delete response into an ActionResult.

    200 / 204 = deleted; 404 = already gone (also success — prune is
    idempotent). Anything else is an error.
    """
    if response.status_code in (200, 204, 404):
        return ActionResult(
            asset_id=remote_id,
            asset_kind=asset.value,
            action=PlanAction.DELETE,
            status="success",
            detail=(
                "already absent (404)"
                if response.status_code == 404
                else "deleted"
            ),
        )
    body = response.text[:200] if hasattr(response, "text") else ""
    return ActionResult(
        asset_id=remote_id,
        asset_kind=asset.value,
        action=PlanAction.DELETE,
        status=f"error-{response.status_code}",
        detail=body,
        error=body,
    )


def delete_result_from_exception(
    remote_id: str, asset: Asset, exc: Exception,
) -> ActionResult:
    """ActionResult wrapper for an exception during delete (network / auth)."""
    msg = str(exc)[:200]
    return ActionResult(
        asset_id=remote_id,
        asset_kind=asset.value,
        action=PlanAction.DELETE,
        status="error-exception",
        detail=msg,
        error=msg,
    )
