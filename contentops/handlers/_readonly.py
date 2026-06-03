# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Read-only handler base — for assets we collect but don't deploy.

Sentinel exposes a number of resource types that are interesting to
*collect* into git (workspace manager assignments, source controls,
incidents, incident tasks, watchlist items) but are inherently
operational rather than declarative — pushing them via apply doesn't
make sense.

This base handler implements the standard ``Handler`` contract with
``apply()`` short-circuited to a SKIP, leaving subclasses to fill in
``list_remote()`` and ``to_envelope()``. Subclasses can also override
``validate()`` and ``plan()`` if they want strict validation of the
inbound YAML at PR time.
"""

from __future__ import annotations

import logging
from typing import Callable

from contentops.core.asset import Asset
from contentops.core.handler import LoadedAsset
from contentops.core.result import ActionResult, NotSupportedError, PlanAction
from contentops.providers.sentinel_arm import SentinelArmProvider

logger = logging.getLogger(__name__)


class ReadOnlySentinelHandler:
    """Base class for collect-only Sentinel handlers.

    Subclasses set:
      * ``asset``         — Asset enum value
      * ``RESOURCE_TYPE`` — ARM resource type segment (e.g. ``incidents``)
      * ``API_VERSION``   — optional override for the resource's
                            api-version when it differs from the
                            provider default (2025-07-01-preview)

    Subclasses must implement ``to_envelope(remote: dict) -> dict | None``.

    ``list_remote()`` is implemented here using ``list_resource()`` on
    the provider; subclasses that need pagination beyond what the
    provider already handles, or need to filter the listing, can
    override it.
    """

    asset: Asset
    RESOURCE_TYPE: str = ""
    API_VERSION: str | None = None
    READ_ONLY_MESSAGE: str = (
        "read-only asset — collect-only handler does not push to the API"
    )

    def __init__(self, provider_factory: Callable[[], SentinelArmProvider | None]) -> None:
        self._provider_factory = provider_factory
        self._provider: SentinelArmProvider | None = None

    def _provider_or_create(self) -> SentinelArmProvider | None:
        if self._provider is None:
            self._provider = self._provider_factory()
        return self._provider

    def validate(self, loaded: LoadedAsset) -> None:
        # Default: no schema enforcement on read-only assets. Subclasses
        # that want stricter PR-time validation override this.
        return None

    def plan(self, loaded: LoadedAsset) -> ActionResult:
        return ActionResult(
            asset_id=loaded.envelope.id, asset_kind=self.asset.value,
            action=PlanAction.SKIP, status="planned",
            detail=self.READ_ONLY_MESSAGE,
        )

    def apply(self, loaded: LoadedAsset, *, dry_run: bool = False) -> ActionResult:
        return ActionResult(
            asset_id=loaded.envelope.id, asset_kind=self.asset.value,
            action=PlanAction.SKIP, status="skipped",
            detail=self.READ_ONLY_MESSAGE,
        )

    def delete(self, remote_id: str) -> ActionResult:
        raise NotSupportedError(
            f"{self.asset.value} is a read-only / collect-only handler — "
            f"{self.READ_ONLY_MESSAGE}"
        )

    def close(self) -> None:
        if self._provider is not None:
            self._provider.close()
            self._provider = None

    # --- Drift / collect support --------------------------------------

    def list_remote(self) -> list[dict]:
        provider = self._provider_or_create()
        if provider is None:
            return []
        if self.API_VERSION:
            url = provider.resource_url(
                self.RESOURCE_TYPE, api_version=self.API_VERSION,
            )
            response = provider.request("GET", url)
            response.raise_for_status()
            return response.json().get("value", []) or []
        return provider.list_resource(self.RESOURCE_TYPE)

    def to_envelope(self, remote: dict) -> dict | None:
        raise NotImplementedError(
            f"{type(self).__name__}.to_envelope must be overridden "
            "to map remote resources onto envelope dicts"
        )
