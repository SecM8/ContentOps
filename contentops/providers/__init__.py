# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Transport-level providers (HTTP clients) for Microsoft APIs.

Providers are intentionally thin: they handle auth headers, retries,
and URL construction, but know nothing about asset semantics.
Per-asset business logic belongs in `contentops.handlers`.
"""
