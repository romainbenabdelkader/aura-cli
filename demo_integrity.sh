#!/usr/bin/env bash
set -eu

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
  local expected_status="$2"
  local expected_message="$3"
  local output status
  shift 3
  printf "\n============================================================\n"
  printf "%s\n" "$title"
  printf "============================================================\n"
  if output=$("$@" 2>&1); then
    status=0
  else
    status=$?
  fi
  printf '%s\n' "$output"
  if [ "$status" -ne "$expected_status" ] || [[ "$output" != *"$expected_message"* ]]; then
    printf 'Demo stopped: unexpected result (exit %s; expected %s and "%s").\n' \
      "$status" "$expected_status" "$expected_message" >&2
    exit 1
  fi
}

mkdir -p "$ASSETS_DIR"

run_step \
  "1. Generate original AURA manifest" \
  0 "Created AURA manifest:" \
  "$PYTHON_BIN" "$ROOT_DIR/aura_cli.py" create \
    --asset "$ORIGINAL_ASSET" \
    --out "$ORIGINAL_MANIFEST"

run_step \
  "2. Original file + original manifest = VALID" \
  0 "Verification result: VALID" \
  "$PYTHON_BIN" "$ROOT_DIR/aura_cli.py" verify \
    --asset "$ORIGINAL_ASSET" \
    --manifest "$ORIGINAL_MANIFEST"

cp "$ORIGINAL_ASSET" "$COPY_ASSET"
run_step \
  "3. Identical copy + original manifest = VALID" \
  0 "Verification result: VALID" \
  "$PYTHON_BIN" "$ROOT_DIR/aura_cli.py" verify \
    --asset "$COPY_ASSET" \
    --manifest "$ORIGINAL_MANIFEST"

cp "$ORIGINAL_ASSET" "$ALTERED_ASSET"
printf "\nThis line changes the file bytes.\n" >> "$ALTERED_ASSET"
run_step \
  "4. Actually modified file + original manifest = INVALID" \
  1 "Reason: file hash mismatch" \
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
  1 "Reason: manifest signature mismatch" \
  "$PYTHON_BIN" "$ROOT_DIR/aura_cli.py" verify \
    --asset "$ORIGINAL_ASSET" \
    --manifest "$ALTERED_MANIFEST"

printf "\nDemo summary (all expected results checked):\n"
printf "%s\n" "- original = VALID"
printf "%s\n" "- identical copy = VALID"
printf "%s\n" "- altered file = INVALID"
printf "%s\n" "- altered manifest = INVALID"
