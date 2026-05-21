<#
.SYNOPSIS
  One-time setup: scaffolds a Backstage app, applies our overlay + custom
  Dockerfile, and builds a Docker image tagged 'authentication-service-backstage:local'
  so the Aspire AppHost can launch it via '--with-backstage'.

.DESCRIPTION
  This script runs Backstage's official '@backstage/create-app' to scaffold a
  vanilla Backstage app under 'local-backstage/', then copies two things from
  'AuthenticationService.AppHost/backstage/' into the scaffolded app:

    1. app-config.local.yaml -- our overlay config (catalog source, TechDocs
       builder, SQLite DB, guest auth).
    2. Dockerfile -- a custom multi-stage Dockerfile that does the whole build
       (yarn install + tsc + build:backend) INSIDE the container, so the host
       does not need Python 3 + Visual Studio C++ Build Tools installed for
       Backstage's native modules (better-sqlite3, isolated-vm, cpu-features).

  After this script completes, pick the 'https-with-backstage' launch profile
  (or 'dotnet run --project AuthenticationService.AppHost -- --with-backstage')
  and Aspire will add Backstage to the resource graph at http://localhost:7007.

  The 'local-backstage/' folder is in .gitignore -- the source of truth for our
  customisations lives under AuthenticationService.AppHost/backstage/. Re-run
  this script when:
   - You change the overlay config or our Dockerfile (cheap; skips create-app,
     just rebuilds the image).
   - A new Backstage release lands and you want to pull it (delete
     'local-backstage/' first to force a fresh scaffold).

.NOTES
  Prereqs (host):
   - Node 20 or later  (https://nodejs.org)  -- needed only to run create-app
   - Docker Desktop  (https://www.docker.com/products/docker-desktop/)

  Notably NOT required on the host:
   - yarn (Backstage uses its own corepack-pinned version inside the container)
   - Python / Visual Studio C++ Build Tools (the multi-stage Dockerfile does
     all native compilation inside a Linux container with apt-installed g++)

  First run: ~10 minutes (npx download + docker build with native compilation).
  Subsequent overlay edits: ~2 minutes for the image rebuild.

  ASCII-only on purpose: Windows PowerShell 5.1 reads scripts without a UTF-8
  BOM as the system code page, which mangles unicode (box-drawing chars,
  em-dashes) into byte sequences the parser rejects.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

function Assert-Command($name, $hint) {
    if (-not (Get-Command $name -ErrorAction SilentlyContinue)) {
        Write-Error "Missing prereq: $name. Install via $hint."
    }
}

function Assert-NodeMinVersion($min) {
    $nodeVersion = (& node --version) -replace '^v', ''
    $major = [int]($nodeVersion.Split('.')[0])
    if ($major -lt $min) {
        Write-Error "Node $nodeVersion found but Backstage requires Node $min or later."
    }
}

# --- 1. Prereqs ------------------------------------------------------------
Assert-Command 'node'   'https://nodejs.org (use the LTS -- Node 20 or later)'
Assert-Command 'npx'    'comes with Node'
Assert-Command 'docker' 'https://www.docker.com/products/docker-desktop/'
Assert-NodeMinVersion 20

# --- 2. Paths --------------------------------------------------------------
$repoRoot       = Split-Path -Parent $PSScriptRoot
$backstageDir   = Join-Path $repoRoot 'local-backstage'
$overlayConfig  = Join-Path $repoRoot 'AuthenticationService.AppHost\backstage\app-config.local.yaml'
$customDockerfile = Join-Path $repoRoot 'AuthenticationService.AppHost\backstage\Dockerfile'
$customDockerignore = Join-Path $repoRoot 'AuthenticationService.AppHost\backstage\.dockerignore'
$imageTag       = 'authentication-service-backstage:local'

foreach ($p in @($overlayConfig, $customDockerfile, $customDockerignore)) {
    if (-not (Test-Path $p)) {
        Write-Error "Required file missing at $p. Check AuthenticationService.AppHost\backstage\."
    }
}

# --- 3. Scaffold Backstage if it doesn't already exist ---------------------
if (-not (Test-Path (Join-Path $backstageDir 'package.json'))) {
    Write-Host "`n=== Step 1/3: Scaffolding Backstage via @backstage/create-app (~3 min, downloads ~30MB) ===`n"

    # create-app's `Enter a name for the app [required]` prompt has no CLI flag
    # equivalent, so we pipe an answer through stdin. Extra newlines cover any
    # follow-up prompts. The app name is internal; our overlay app-config sets
    # the user-visible title.
    $appName = 'backstage'
    $stdin = "$appName`n`n`n`n`n`n"

    Push-Location $repoRoot
    try {
        $stdin | & npx --yes '@backstage/create-app@latest' `
            --path local-backstage `
            --skip-install
        if ($LASTEXITCODE -ne 0) {
            throw "create-app exited with $LASTEXITCODE"
        }
    } finally {
        Pop-Location
    }
} else {
    Write-Host "Backstage already scaffolded at $backstageDir -- skipping create-app."
    Write-Host "(Delete the local-backstage/ folder to force a fresh scaffold against the latest Backstage release.)"
}

# --- 4. Copy overlay + custom Dockerfile + .dockerignore into scaffolded app
Write-Host "`n=== Step 2/3: Applying overlay config + custom Dockerfile + .dockerignore ===`n"

$overlayTarget = Join-Path $backstageDir 'app-config.local.yaml'
Copy-Item $overlayConfig $overlayTarget -Force
Write-Host "Overlay copied: $overlayConfig"
Write-Host "             -> $overlayTarget"

# Replace create-app's default Dockerfile with our multi-stage one that
# compiles everything inside the container.
$dockerfileTarget = Join-Path $backstageDir 'packages\backend\Dockerfile'
Copy-Item $customDockerfile $dockerfileTarget -Force
Write-Host "Dockerfile copied: $customDockerfile"
Write-Host "                -> $dockerfileTarget"

# Replace create-app's default .dockerignore. The default excludes
# packages/*/src AND *.local.yaml -- both fatal for a build-inside-container
# flow that needs source AND our overlay config copied in.
$dockerignoreTarget = Join-Path $backstageDir '.dockerignore'
Copy-Item $customDockerignore $dockerignoreTarget -Force
Write-Host ".dockerignore copied: $customDockerignore"
Write-Host "                  -> $dockerignoreTarget"

# --- 5. Docker build (does yarn install + tsc + build:backend INSIDE) ------
Push-Location $backstageDir
try {
    Write-Host "`n=== Step 3/3: Building Docker image (~7 min first run; yarn install + native compile + bundle all happen inside the container) ===`n"

    & docker image build . -f packages\backend\Dockerfile --tag $imageTag
    $buildExitCode = $LASTEXITCODE

    # Verify by tag instead of trusting the CLI's exit code. Docker Desktop /
    # Rancher Desktop on Windows occasionally crash the docker.exe process
    # during the build's finalize phase (Go runtime OOM, Windows named-pipe
    # I/O panic) AFTER BuildKit has already successfully tagged the image.
    # If the image is present we treat the build as successful, regardless
    # of what the CLI's exit code said.
    $tagged = & docker image ls --format '{{.Repository}}:{{.Tag}}' 2>$null | Select-String "^$([regex]::Escape($imageTag))$"
    if (-not $tagged) {
        throw "Image '$imageTag' not present after build (docker exit code: $buildExitCode). See the docker build output above for the underlying error."
    }
    if ($buildExitCode -ne 0) {
        Write-Host ''
        Write-Host "Note: docker CLI exited with $buildExitCode, but image '$imageTag' was successfully tagged."
        Write-Host '(This is a known docker-on-Windows quirk -- the CLI sometimes panics during finalize even though the build itself completed.)'
    }
} finally {
    Pop-Location
}

# --- 6. Hand off -----------------------------------------------------------
Write-Host ''
Write-Host '----------------------------------------------------------------'
Write-Host "  Done. Image '$imageTag' built and tagged."
Write-Host ''
Write-Host '  Run Aspire with Backstage:'
Write-Host '    dotnet run --project AuthenticationService.AppHost -- --with-backstage'
Write-Host ''
Write-Host '  (Or in VS: pick the https-with-backstage launch profile, then F5.)'
Write-Host ''
Write-Host '  Backstage UI will be at http://localhost:7007 once the container'
Write-Host '  reports ready in the Aspire dashboard.'
Write-Host '----------------------------------------------------------------'
