# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Per-asset handlers — one module per Asset value.

Each handler implements the `Handler` protocol from `contentops.core`.
Existing v1 deploy/collect logic is wrapped (not duplicated) by the
`sentinel_analytic` and `defender_custom_detection` handlers.
"""
