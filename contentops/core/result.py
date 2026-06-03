# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Plan/apply result objects shared across handlers."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any


class PlanAction(str, enum.Enum):
    CREATE = "create"
    UPDATE = "update"
    DISABLE = "disable"
    SKIP = "skip"
    NOOP = "noop"
    DELETE = "delete"


class NotSupportedError(Exception):
    """Raised when a handler is asked to perform an operation it cannot.

    Currently used by read-only / collect-only handlers when called via
    ``Handler.delete(...)``. The pipeline catches this and emits a
    SKIP ActionResult rather than failing the prune batch.
    """


@dataclass
class ActionResult:
    """Outcome of one plan or apply step for a single asset."""

    asset_id: str
    asset_kind: str
    action: PlanAction
    status: str
    detail: str = ""
    extra: dict[str, Any] = field(default_factory=dict)
    # Post-apply verification: True when content-hash compare succeeds,
    # False when the remote diverges from what we sent (or 412 etag conflict),
    # None for plan-only / dry-run / skip / read-only operations.
    verified: bool | None = None
    error: str | None = None

    @property
    def is_error(self) -> bool:
        # Anchored so future ``"errors-cleared"``-style statuses don't
        # falsely classify as failure. Handlers today only emit either
        # the bare string ``"error"`` or ``"error-<code>"``.
        return self.status == "error" or self.status.startswith("error-")

    @property
    def is_failure(self) -> bool:
        """True when this asset should fail the apply batch.

        An asset fails if the API call errored OR the post-apply hash
        check came back negative.
        """
        return self.is_error or self.verified is False

    def as_row(self) -> str:
        verified_col: str
        if self.verified is True:
            verified_col = "ok"
        elif self.verified is False:
            verified_col = "MISMATCH"
        else:
            verified_col = "-"
        return (
            f"  {self.asset_id:40s} {self.asset_kind:30s} "
            f"{self.action.value:8s} {self.status:18s} {verified_col}"
        )
