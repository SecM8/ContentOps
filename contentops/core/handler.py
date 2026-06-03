# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Handler protocol — every asset type implements this surface."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from contentops.core.asset import Asset
from contentops.core.envelope import EnvelopeV2
from contentops.core.result import ActionResult


@dataclass
class LoadedAsset:
    """A parsed asset file ready for plan/apply."""

    path: Path
    envelope: EnvelopeV2
    payload: dict[str, Any]


@runtime_checkable
class Handler(Protocol):
    """Per-asset handler.

    Each handler owns the full lifecycle for one `Asset` value:
      - validate(): pure pydantic / cross-field validation
      - plan(): no side effects, returns the action that apply() would take
      - apply(): performs the API call (honors dry_run)
      - delete(remote_id): destructive — removes one remote resource.
        ``remote_id`` is whatever the handler considers the unique
        identifier (ARM ``name`` segment for Sentinel handlers, graph
        ``id`` for Defender custom detection, server-assigned name for
        TI indicators). Read-only handlers raise NotSupportedError.
    """

    asset: Asset

    def validate(self, loaded: LoadedAsset) -> None: ...

    def plan(self, loaded: LoadedAsset) -> ActionResult: ...

    def apply(self, loaded: LoadedAsset, *, dry_run: bool = False) -> ActionResult: ...

    def delete(self, remote_id: str) -> ActionResult: ...
