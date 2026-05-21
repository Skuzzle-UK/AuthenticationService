#!/usr/bin/env bash
#
# Regenerate docs/api/openapi.json from the auth service's Swashbuckle config.
#
# Bash equivalent of scripts/regen-openapi.ps1. See the .ps1 header for the
# full description.

set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd "$script_dir/.." && pwd)
auth_project_dir="$repo_root/AuthenticationService"
auth_project="$auth_project_dir/AuthenticationService.csproj"
built_dll="$auth_project_dir/bin/Release/net10.0/AuthenticationService.dll"
output_json="$repo_root/docs/api/openapi.json"
output_dir="$(dirname "$output_json")"

# --- 1. Prereq check ---------------------------------------------------------
if ! command -v dotnet >/dev/null 2>&1; then
  echo 'ERROR: .NET SDK not found. Install .NET 10 from https://dotnet.microsoft.com/download.' >&2
  exit 1
fi

# --- 2. Restore the locally-pinned Swashbuckle CLI tool ---------------------
echo '=== Restoring dotnet tools (Swashbuckle.AspNetCore.Cli) ==='
( cd "$repo_root" && dotnet tool restore )

# --- 3. Build the auth service (Release) ------------------------------------
echo
echo '=== Building AuthenticationService (Release) ==='
dotnet build "$auth_project" -c Release --nologo

if [ ! -f "$built_dll" ]; then
  echo "ERROR: Expected built assembly not found at $built_dll. Did the project target framework change?" >&2
  exit 1
fi

# --- 4. Ensure the output directory exists ----------------------------------
mkdir -p "$output_dir"

# --- 5. Run the Swashbuckle CLI ---------------------------------------------
echo
echo '=== Generating OpenAPI document ==='
# cwd must be the project dir (where appsettings.json lives) -- see PS1 for why.
( cd "$auth_project_dir" && dotnet swagger tofile --output "$output_json" "$built_dll" v1 )

# --- 6. Inline the spec into catalog-info.yaml ------------------------------
# See the PS1 script for why we inline rather than $text-reference.
echo
echo '=== Inlining spec into catalog-info.yaml ==='
catalog_path="$repo_root/catalog-info.yaml"
begin_marker='# >>> openapi-injection-begin'
end_marker='# >>> openapi-injection-end'

if ! grep -qF "$begin_marker" "$catalog_path"; then
  echo "ERROR: catalog-info.yaml is missing the '$begin_marker' marker." >&2
  exit 1
fi

# Indent every line of the JSON by 4 spaces so it nests under `definition: |`.
indented_json=$(sed 's/^/    /' "$output_json")

# Compose the new block: keep markers, replace what's between them with a
# fresh `definition: |` + the indented JSON. awk is the path-of-least-pain
# for "replace everything between two marker lines, preserving the markers."
awk -v begin="$begin_marker" \
    -v end="$end_marker" \
    -v new_block="  definition: |
$indented_json" '
  $0 ~ begin { print; printing = 0; print new_block; in_block = 1; next }
  $0 ~ end   { in_block = 0; print; next }
  !in_block  { print }
' "$catalog_path" > "$catalog_path.tmp" && mv "$catalog_path.tmp" "$catalog_path"

echo "catalog-info.yaml updated: $catalog_path"

# --- 7. Hand off -------------------------------------------------------------
size_kb=$(( $(stat -c '%s' "$output_json" 2>/dev/null || stat -f '%z' "$output_json") / 1024 ))
cat <<EOF

----------------------------------------------------------------
  OpenAPI spec written to: $output_json
  (${size_kb} KB)

  Also inlined into: $catalog_path
  (between '$begin_marker' and '$end_marker' markers)

  Next: commit both files if they changed. Local Backstage reads
  the inline copy from catalog-info.yaml directly; the docs/api/
  openapi.json file is a convenience for direct viewing / linking.
----------------------------------------------------------------
EOF
