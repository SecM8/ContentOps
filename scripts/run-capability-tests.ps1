# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0
#
# PowerShell wrapper for the e2e capability matrix.
#
# Usage:
#   pwsh scripts/run-capability-tests.ps1                  # mocked (default)
#   pwsh scripts/run-capability-tests.ps1 -Mode offline
#   pwsh scripts/run-capability-tests.ps1 -Mode live
#   pwsh scripts/run-capability-tests.ps1 -Mode mocked -VerboseOutput
#
# Exit codes:
#   0  every covered capability PASSed (SKIPs do not fail).
#   non-zero  at least one capability FAILed; consult the rendered
#             table or the JSON sidecar for details.

[CmdletBinding()]
param(
    [ValidateSet('offline','mocked','live')]
    [string]$Mode = 'mocked',
    [switch]$VerboseOutput,
    [string]$JsonOut = (Join-Path $PSScriptRoot '..' | Join-Path -ChildPath '.e2e-results.json')
)

$ErrorActionPreference = 'Stop'

$env:RUN_E2E = '1'
if ($Mode -eq 'live') {
    $env:RUN_LIVE_TESTS = '1'
    Write-Host "[e2e] live mode — RUN_LIVE_TESTS=1; INTEGRATION_* must be set in your environment."
}

$resolvedJson = (Resolve-Path -LiteralPath (Split-Path -Parent $JsonOut) -ErrorAction SilentlyContinue)
if (-not $resolvedJson) {
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $JsonOut) | Out-Null
}
$jsonAbs = [IO.Path]::GetFullPath($JsonOut)

$pytestArgs = @(
    'tests/e2e/test_full_capability_matrix.py',
    "--mode=$Mode",
    "--e2e-json=$jsonAbs",
    '-q',
    '--no-header',
    '-p', 'no:cacheprovider'
)
if ($VerboseOutput) { $pytestArgs += '-v' }

Write-Host "[e2e] mode=$Mode  json=$jsonAbs"
Write-Host "[e2e] python -m pytest $($pytestArgs -join ' ')"

& python -m pytest @pytestArgs
$pytestExit = $LASTEXITCODE

if (Test-Path $jsonAbs) {
    Write-Host ''
    Write-Host '[e2e] result table:'
    & python -m tests.e2e._render_table --json $jsonAbs
}

exit $pytestExit
