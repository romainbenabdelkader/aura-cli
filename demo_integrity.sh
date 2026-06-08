#!/usr/bin/env bash
set -u

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
PYTHON_BIN="${PYTHON_BIN:-python3}"
ASSETS_DIR="$ROOT_DIR/assets"
ORIGINAL_ASSET="$ASSETS_DIR/track.wav"
ORIGINAL_MANIFEST="$ASSETS_DIR/track.aura.json"
COPY_ASSET="$ASSETS_DIR/track.copy.wav"
ALTERED_ASSET="$ASSETS_DIR/track.altered.wav"
ALTERED_MANIFEST="$ASSETS_DIR/track.tampered.aura.json"

run_step() {
  local title="$1"
  shift
  printf "\n============================================================\n"
  printf "%s\n" "$title"
  printf "============================================================\n"
  "$@"
  local status=$?
  if [ "$status" -ne 0 ]; then
    printf "(expected failure shown above)\n"
  fi
  return 0
}

mkdir -p "$ASSETS_DIR"

run_step \
  "1. Generate original AURA manifest" \
  "$PYTHON_BIN" "$ROOT_DIR/aura_cli.py" create \
    --asset "$ORIGINAL_ASSET" \
    --out "$ORIGINAL_MANIFEST"

run_step \
  "2. Original file + original manifest = VALID" \
  "$PYTHON_BIN" "$ROOT_DIR/aura_cli.py" verify \
    --asset "$ORIGINAL_ASSET" \
    --manifest "$ORIGINAL_MANIFEST"

cp "$ORIGINAL_ASSET" "$COPY_ASSET"
run_step \
  "3. Identical copy + original manifest = VALID" \
  "$PYTHON_BIN" "$ROOT_DIR/aura_cli.py" verify \
    --asset "$COPY_ASSET" \
    --manifest "$ORIGINAL_MANIFEST"

cp "$ORIGINAL_ASSET" "$ALTERED_ASSET"
printf "\nThis line changes the file bytes.\n" >> "$ALTERED_ASSET"
run_step \
  "4. Actually modified file + original manifest = INVALID" \
  "$PYTHON_BIN" "$ROOT_DIR/aura_cli.py" verify \
    --asset "$ALTERED_ASSET" \
    --manifest "$ORIGINAL_MANIFEST"

"$PYTHON_BIN" - "$ORIGINAL_MANIFEST" "$ALTERED_MANIFEST" <<'PY'
import json
import sys

source, target = sys.argv[1], sys.argv[2]
with open(source, "r", encoding="utf-8") as handle:
    manifest = json.load(handle)

manifest["issuer_name"] = "Tampered Issuer Name"

with open(target, "w", encoding="utf-8") as handle:
    json.dump(manifest, handle, indent=2, ensure_ascii=False)
    handle.write("\n")
PY

run_step \
  "5. Manifest modified after signature = INVALID" \
  "$PYTHON_BIN" "$ROOT_DIR/aura_cli.py" verify \
    --asset "$ORIGINAL_ASSET" \
    --manifest "$ALTERED_MANIFEST"

printf "\nDemo summary:\n"
printf "%s\n" "- original = VALID"
printf "%s\n" "- identical copy = VALID"
printf "%s\n" "- altered file = INVALID"
printf "%s\n" "- altered manifest = INVALID"
