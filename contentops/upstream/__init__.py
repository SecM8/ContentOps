# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Pipeline-opened-PR machinery (DESIGN §19).

Render bodies, branch names and supersede logic for the workflows that
turn upstream-of-Git changes (live tenant drift, Microsoft catalog
updates, schema diffs) into reviewable PRs.
"""
