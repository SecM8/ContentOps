# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0
#
# Build the Kusto.Language strict-lint wrapper for contentops lint --strict.
# Produces tools/kql_strict.dll at the path that
# contentops.lint.strict._resolve_wrapper() expects.

$ErrorActionPreference = "Stop"

$RepoRoot   = (Resolve-Path "$PSScriptRoot\..").Path
$ProjectDir = Join-Path $RepoRoot "tools\kql_strict"
$OutDir     = Join-Path $RepoRoot "tools"

if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) {
    Write-Error "dotnet not on PATH. Install .NET 8 SDK and retry."
    exit 1
}

# Run from the project directory so dotnet sees `global.json` and uses
# the pinned .NET 8 SDK. The GitHub runners pre-install .NET 10 too, and
# without global.json on the resolution path, `dotnet publish` boots
# under 10.x which mishandles top-level statements in our wrapper.
Push-Location $ProjectDir
try {
    dotnet publish `
        --configuration Release `
        --output $OutDir `
        --nologo
}
finally {
    Pop-Location
}

Write-Host "wrote $OutDir\kql_strict.dll"
