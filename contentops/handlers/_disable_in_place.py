# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Switch a tenant object off as it is.

A rule locked with ``localCustomization: true`` was tuned in the portal; the
repository's copy is out of date on purpose. ``contentops disable`` on such a
rule (status ``deprecated``) must switch it off without sending the
repository's body, which would overwrite the tuning and bring it back on
re-enable. Each handler that can switch a kind off reads the tenant's object,
changes only its on/off state and writes that back; this module holds the
shared read / write / verify steps.
"""

from __future__ import annotations

from typing import Any, Callable

from contentops.core.result import ActionResult, PlanAction
from contentops.handlers._verify import ETAG_CONFLICT_MESSAGE

NOT_IN_TENANT = "not in the tenant; nothing to switch off"
ALREADY_OFF = "already switched off in the tenant"
NO_DISABLE_IN_PLACE = (
    "locked: this kind cannot be switched off without sending the file; "
    "switch it off in the portal, or deploy with --force-overwrite"
)


def disable_existing(
    *,
    asset_kind: str,
    envelope_id: str,
    existing: dict | None,
    is_off: Callable[[dict], bool],
    switch_off: Callable[[dict], Any],
    read_back: Callable[[], dict | None],
) -> ActionResult:
    """``existing``: the tenant's object (None when absent). ``switch_off``
    writes it switched off and returns the HTTP response; ``read_back``
    reads it again for the check."""
    if existing is None:
        return ActionResult(asset_id=envelope_id, asset_kind=asset_kind,
                            action=PlanAction.SKIP, status="skipped", detail=NOT_IN_TENANT)
    if is_off(existing):
        return ActionResult(asset_id=envelope_id, asset_kind=asset_kind,
                            action=PlanAction.DISABLE, status="success", detail=ALREADY_OFF,
                            verified=True)
    response = switch_off(existing)
    code = getattr(response, "status_code", 200)
    if code == 412:
        return ActionResult(asset_id=envelope_id, asset_kind=asset_kind,
                            action=PlanAction.DISABLE, status="error-412",
                            detail=ETAG_CONFLICT_MESSAGE, error=ETAG_CONFLICT_MESSAGE, verified=False)
    if not 200 <= code < 300:
        text = str(getattr(response, "text", ""))[:200]
        return ActionResult(asset_id=envelope_id, asset_kind=asset_kind,
                            action=PlanAction.DISABLE, status=f"error-{code}",
                            detail=text, error=text, verified=False)
    after = read_back()
    if after is None or not is_off(after):
        err = "post-apply GET: the object is not switched off"
        return ActionResult(asset_id=envelope_id, asset_kind=asset_kind,
                            action=PlanAction.DISABLE, status="success", detail=err,
                            error=err, verified=False)
    return ActionResult(asset_id=envelope_id, asset_kind=asset_kind,
                        action=PlanAction.DISABLE, status="success",
                        detail="switched off in the tenant as it is (locked)", verified=True)
