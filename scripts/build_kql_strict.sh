#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0
#
# Build the Kusto.Language strict-lint wrapper for contentops lint --strict.
# Produces tools/kql_strict.dll at the path that
# contentops.lint.strict._resolve_wrapper() expects.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PROJECT_DIR="$REPO_ROOT/tools/kql_strict"
OUT_DIR="$REPO_ROOT/tools"

if ! command -v dotnet >/dev/null 2>&1; then
    echo "error: dotnet not on PATH. Install .NET 8 SDK and retry." >&2
    exit 1
fi

# Run from the project directory so dotnet sees `global.json` and uses
# the pinned .NET 8 SDK. The GitHub runners pre-install .NET 10 too, and
# without global.json on the resolution path, `dotnet publish` boots
# under 10.x which mishandles top-level statements in our wrapper.
cd "$PROJECT_DIR"

dotnet --version
dotnet publish \
    --configuration Release \
    --output "$OUT_DIR" \
    --nologo

echo "wrote $OUT_DIR/kql_strict.dll"
