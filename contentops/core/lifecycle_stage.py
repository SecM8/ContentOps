# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Authoring-workflow lifecycle stages (T.2 — Fortune 500 detection SDLC).

The detect.fyi research-driven detection-engineering article describes a
six-stage authoring lifecycle distinct from the runtime deploy state
held by ``envelope.status``. The two axes are orthogonal:

* ``status`` (existing): drives **runtime** deploy behaviour — the apply
  path, the env-status filter, the deprecation gate. Values today:
  ``experimental`` / ``test`` / ``production`` / ``deprecated``.
* ``lifecycleStage`` (new — this module): tracks **authoring** progress
  for sprint planning, dashboards, and SOC team-lead visibility. It
  never gates deploy behaviour; readers are the operator and the
  forthcoming portfolio dashboard.

A rule can be (and often will be) at different positions on the two
axes — e.g. ``lifecycleStage: optimization`` + ``status: production``
is a mature rule under active tuning, while
``lifecycleStage: engineering`` + ``status: experimental`` is a rule
being drafted but already deployed for shadow telemetry.

Stages, in normal progression order (operators may also skip / reorder
per their workflow):

* ``concept`` — idea captured; threat hypothesis recorded; CTI input
  noted. Nothing committed beyond the hypothesis sentence.
* ``research`` — data sources mapped, feasibility / cost reviewed;
  decision on whether to proceed.
* ``engineering`` — KQL drafted; lint passing; ready for review.
* ``delivery`` — merged + applied to integration; ready to promote.
* ``optimization`` — in production; tuning rounds underway based on
  FP-rate / fire-rate telemetry.
* ``feedback`` — mature, low-touch; periodic re-validation only.
"""

from __future__ import annotations

from typing import Literal


LifecycleStage = Literal[
    "concept",
    "research",
    "engineering",
    "delivery",
    "optimization",
    "feedback",
]


# Convenience tuple for code that needs to enumerate every stage
# (e.g. CLI choices, doc generation). Keep in sync with the Literal
# above by reading from it via ``typing.get_args(LifecycleStage)`` —
# duplicating here just makes import-cycle-free iteration easier.
LIFECYCLE_STAGES: tuple[str, ...] = (
    "concept",
    "research",
    "engineering",
    "delivery",
    "optimization",
    "feedback",
)
