#!/usr/bin/env bash
#
# One-time setup: scaffolds a Backstage app, applies our overlay + custom
# Dockerfile, and builds a Docker image tagged
# 'authentication-service-backstage:local' so the Aspire AppHost can launch it
# via --with-backstage.
#
# Bash equivalent of scripts/setup-local-backstage.ps1. See the .ps1 header
# for the full description -- TL;DR is that the multi-stage Dockerfile shipped
# under AuthenticationService.AppHost/backstage/Dockerfile does all yarn /
# native-compile work inside the container, so the host only needs Node + npx
# (to run create-app) and Docker.

set -euo pipefail

assert_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "ERROR: missing prereq '$1'. Install via $2." >&2
    exit 1
  fi
}

assert_node_min_version() {
  local min=$1
  local v
  v=$(node --version | sed 's/^v//')
  local major=${v%%.*}
  if [ "$major" -lt "$min" ]; then
    echo "ERROR: Node $v found but Backstage requires Node $min or later." >&2
    exit 1
  fi
}

# --- 1. Prereqs -------------------------------------------------------------
assert_command node 'https://nodejs.org (use the LTS -- Node 20 or later)'
assert_command npx 'comes with Node'
assert_command docker 'https://www.docker.com/products/docker-desktop/ (or your distro packages)'
assert_node_min_version 20

# --- 2. Paths ---------------------------------------------------------------
script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd "$script_dir/.." && pwd)
backstage_dir="$repo_root/local-backstage"
overlay_config="$repo_root/AuthenticationService.AppHost/backstage/app-config.local.yaml"
custom_dockerfile="$repo_root/AuthenticationService.AppHost/backstage/Dockerfile"
custom_dockerignore="$repo_root/AuthenticationService.AppHost/backstage/.dockerignore"
image_tag='authentication-service-backstage:local'

for p in "$overlay_config" "$custom_dockerfile" "$custom_dockerignore"; do
  if [ ! -f "$p" ]; then
    echo "ERROR: required file missing at $p" >&2
    exit 1
  fi
done

# --- 3. Scaffold Backstage if it doesn't already exist ----------------------
if [ ! -f "$backstage_dir/package.json" ]; then
  echo
  echo '=== Step 1/3: Scaffolding Backstage via @backstage/create-app (~3 min, downloads ~30MB) ==='
  echo
  # create-app has no CLI flag for the required "Enter a name for the app"
  # prompt. Pipe an answer through stdin; extra newlines cover any follow-up
  # prompts. The app name is internal; our overlay app-config sets the
  # user-visible title.
  ( cd "$repo_root" && printf 'backstage\n\n\n\n\n\n' | npx --yes @backstage/create-app@latest \
      --path local-backstage \
      --skip-install )
else
  echo "Backstage already scaffolded at $backstage_dir -- skipping create-app."
  echo '(Delete the local-backstage/ folder to force a fresh scaffold against the latest Backstage release.)'
fi

# --- 4. Copy overlay + custom Dockerfile + .dockerignore --------------------
echo
echo '=== Step 2/3: Applying overlay config + custom Dockerfile + .dockerignore ==='
echo
cp -f "$overlay_config" "$backstage_dir/app-config.local.yaml"
echo "Overlay copied: $overlay_config"
echo "             -> $backstage_dir/app-config.local.yaml"

cp -f "$custom_dockerfile" "$backstage_dir/packages/backend/Dockerfile"
echo "Dockerfile copied: $custom_dockerfile"
echo "                -> $backstage_dir/packages/backend/Dockerfile"

# create-app's .dockerignore excludes packages/*/src + *.local.yaml -- both
# fatal for a build-inside-container flow. Replace it with ours.
cp -f "$custom_dockerignore" "$backstage_dir/.dockerignore"
echo ".dockerignore copied: $custom_dockerignore"
echo "                  -> $backstage_dir/.dockerignore"

# --- 5. Docker build (yarn install + tsc + build:backend INSIDE container) --
cd "$backstage_dir"

echo
echo '=== Step 3/3: Building Docker image (~7 min first run; yarn install + native compile + bundle all happen inside the container) ==='
echo
docker image build . -f packages/backend/Dockerfile --tag "$image_tag"

# --- 6. Hand off ------------------------------------------------------------
cat <<EOF

----------------------------------------------------------------
  Done. Image '$image_tag' built and tagged.

  Run Aspire with Backstage:
    dotnet run --project AuthenticationService.AppHost -- --with-backstage

  Backstage UI will be at http://localhost:7007 once the container
  reports ready in the Aspire dashboard.
----------------------------------------------------------------
EOF
