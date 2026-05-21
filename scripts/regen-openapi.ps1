<#
.SYNOPSIS
  Regenerate docs/api/openapi.json from the auth service's Swashbuckle config.

.DESCRIPTION
  Builds AuthenticationService in Release, then runs the Swashbuckle CLI
  ('dotnet swagger tofile') against the built assembly to dump its OpenAPI 3
  document to docs/api/openapi.json. That file is what catalog-info.yaml's
  REST API entity references via 'definition: $text: docs/api/openapi.json',
  so re-running this script keeps the Backstage API definition in sync with
  what the running service actually serves at /swagger/v1/swagger.json.

  The dotnet-swagger CLI loads the built assembly's host configuration
  (services + middleware pipeline) but does NOT start a real HTTP server or
  connect to MySQL/Redis -- it just walks the registered controllers and
  emits the swagger document. So no infrastructure needs to be running.

  Use cases:
   - Manually: a dev added/changed an endpoint and wants to refresh the spec
     before opening a PR.
   - CI: .github/workflows/regen-openapi.yml runs this on every push to main
     and auto-commits if the output drifted.

.NOTES
  Requires .NET 10 SDK + the tools restored via 'dotnet tool restore' (which
  picks up .config/dotnet-tools.json). The script handles that automatically.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$authProjectDir = Join-Path $repoRoot 'AuthenticationService'
$authProject = Join-Path $authProjectDir 'AuthenticationService.csproj'
$builtDll = Join-Path $authProjectDir 'bin\Release\net10.0\AuthenticationService.dll'
$outputJson = Join-Path $repoRoot 'docs\api\openapi.json'
$outputDir = Split-Path $outputJson -Parent

# --- 1. Prereq check ---------------------------------------------------------
if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) {
    Write-Error '.NET SDK not found. Install .NET 10 from https://dotnet.microsoft.com/download.'
}

# --- 2. Restore the locally-pinned Swashbuckle CLI tool ---------------------
Write-Host '=== Restoring dotnet tools (Swashbuckle.AspNetCore.Cli) ==='
Push-Location $repoRoot
try {
    & dotnet tool restore
    if ($LASTEXITCODE -ne 0) { throw "dotnet tool restore failed with $LASTEXITCODE" }
} finally {
    Pop-Location
}

# --- 3. Build the auth service (Release) ------------------------------------
Write-Host ''
Write-Host '=== Building AuthenticationService (Release) ==='
& dotnet build $authProject -c Release --nologo
if ($LASTEXITCODE -ne 0) { throw "dotnet build failed with $LASTEXITCODE" }

if (-not (Test-Path $builtDll)) {
    Write-Error "Expected built assembly not found at $builtDll. Did the project target framework change?"
}

# --- 4. Ensure the output directory exists ----------------------------------
if (-not (Test-Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
    Write-Host "Created output directory: $outputDir"
}

# --- 5. Run the Swashbuckle CLI ---------------------------------------------
Write-Host ''
Write-Host '=== Generating OpenAPI document ==='
# `swagger tofile` arguments:
#   --output  : where to write the doc
#   <dll>     : the built assembly to inspect (must implement IHostBuilder via Program.cs)
#   <docname> : the swagger doc name. Swashbuckle defaults register 'v1'.
#
# IMPORTANT: cwd must be the project directory (where appsettings.json lives).
# The swagger CLI loads the assembly's Program.cs which calls
# `.AddJsonFile("appsettings.json", optional: false, ...)`. WebApplication's
# default content root is the current working directory, so running this from
# the repo root fails with "appsettings.json not found at <repo-root>/...".
# Push into the project dir for the swagger invocation.
Push-Location $authProjectDir
try {
    & dotnet swagger tofile --output $outputJson $builtDll v1
    if ($LASTEXITCODE -ne 0) { throw "swagger CLI failed with $LASTEXITCODE" }
} finally {
    Pop-Location
}

# --- 6. Inline the spec into catalog-info.yaml ------------------------------
# Backstage's $text-placeholder resolution throws "Invalid URL" when the
# catalog file is loaded from a file:/... location (PlaceholderProcessor passes
# the location to `new URL(...)` as a base; node's URL constructor rejects
# anything without a scheme it knows). Inlining the spec into catalog-info.yaml
# between marker comments sidesteps URL resolution entirely.
Write-Host ''
Write-Host '=== Inlining spec into catalog-info.yaml ==='
$catalogPath = Join-Path $repoRoot 'catalog-info.yaml'
$catalogText = Get-Content $catalogPath -Raw

# The block we replace lives between these marker lines (defined in
# catalog-info.yaml as comments inside the REST API entity's spec.definition).
# We rewrite the whole `definition: |` value plus its inlined JSON body.
$beginMarker = '# >>> openapi-injection-begin'
$endMarker = '# >>> openapi-injection-end'

# Read the generated JSON, indent every line by 4 spaces so it nests
# correctly under `definition: |` (which sits at 2-space indent).
$jsonContent = Get-Content $outputJson -Raw
$jsonLines = $jsonContent -split "(`r`n|`n)" | Where-Object { $_ -ne "`n" -and $_ -ne "`r`n" }
$indentedJson = ($jsonLines | ForEach-Object { "    $_" }) -join "`n"

# Pattern matches the entire injected block including markers, captured so we
# can splice in fresh content. (?s) = single-line mode so . matches newlines.
$pattern = "(?s)(  $([regex]::Escape($beginMarker))[^\r\n]*\r?\n)(.*?)(  $([regex]::Escape($endMarker)))"
$replacement = "`$1  definition: |`n$indentedJson`n  `$3"

if ($catalogText -notmatch [regex]::Escape($beginMarker)) {
    Write-Error "catalog-info.yaml is missing the '$beginMarker' marker. The REST API entity's definition block expects markers around the auto-generated content."
}
$updated = [regex]::Replace($catalogText, $pattern, $replacement)
if ($updated -eq $catalogText) {
    Write-Host 'catalog-info.yaml unchanged (markers found but replacement was a no-op -- spec hasn''t changed).'
} else {
    Set-Content -Path $catalogPath -Value $updated -NoNewline
    Write-Host "catalog-info.yaml updated: $catalogPath"
}

# --- 7. Hand off -------------------------------------------------------------
$size = (Get-Item $outputJson).Length
Write-Host ''
Write-Host '----------------------------------------------------------------'
Write-Host "  OpenAPI spec written to: $outputJson"
Write-Host "  ($([math]::Round($size / 1KB, 1)) KB)"
Write-Host ''
Write-Host "  Also inlined into: $catalogPath"
Write-Host "  (between '$beginMarker' and '$endMarker' markers)"
Write-Host ''
Write-Host '  Next: commit both files if they changed. Local Backstage reads'
Write-Host '  the inline copy from catalog-info.yaml directly; the docs/api/'
Write-Host '  openapi.json file is a convenience for direct viewing / linking.'
Write-Host '----------------------------------------------------------------'
