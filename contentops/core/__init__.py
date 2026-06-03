# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Core abstractions for the v2 detection pipeline.

Asset-agnostic envelope, handler protocol, registry, plan/apply primitives.
This layer knows nothing about HTTP or specific Microsoft APIs — those
concerns belong in `contentops.providers` (transport) and
`contentops.handlers` (per-asset business logic).
"""

from contentops.core.asset import Asset
from contentops.core.envelope import EnvelopeV2, parse_envelope
from contentops.core.handler import Handler, LoadedAsset
from contentops.core.registry import HandlerRegistry, default_registry
from contentops.core.result import ActionResult, PlanAction

__all__ = [
    "Asset",
    "EnvelopeV2",
    "parse_envelope",
    "Handler",
    "LoadedAsset",
    "HandlerRegistry",
    "default_registry",
    "ActionResult",
    "PlanAction",
]
