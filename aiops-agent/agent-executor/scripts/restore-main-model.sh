#!/usr/bin/env bash

set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SWITCH_SCRIPT="${SCRIPT_DIR}/switch-main-model.sh"
BACKUP_FILE="${1:-}"

fail() {
  echo "ERROR: $*" >&2
  exit 1
}

read_backup_value() {
  local key="$1"
  local encoded

  encoded="$(
    kubectl create \
      --dry-run=client \
      -f "$BACKUP_FILE" \
      -o "jsonpath={.data.${key}}"
  )"

  [[ -n "$encoded" ]] || fail "backup does not contain ${key}"
  printf '%s' "$encoded" | base64 --decode
}

[[ -n "$BACKUP_FILE" ]] || {
  echo "Usage: $0 /path/to/agent-executor-llm-backup.yaml" >&2
  exit 2
}
[[ -f "$BACKUP_FILE" ]] || fail "backup file not found: $BACKUP_FILE"
[[ -x "$SWITCH_SCRIPT" ]] || fail "switch script is not executable: $SWITCH_SCRIPT"

backup_mode="$(stat -c '%a' "$BACKUP_FILE")"
if (( 10#$backup_mode % 100 != 0 )); then
  fail "backup permissions are too broad: chmod 600 '$BACKUP_FILE'"
fi

model_api_base="$(read_backup_value MODEL_API_BASE)"
model_api_key="$(read_backup_value MODEL_API_KEY)"
model_name="$(read_backup_value MODEL_NAME)"

echo "Restoring main model: ${model_name} at ${model_api_base}"

temporary_config="$(mktemp /tmp/aiops-main-model-restore.XXXXXX)"
chmod 600 "$temporary_config"

cleanup() {
  rm -f "$temporary_config"
  unset model_api_key
}
trap cleanup EXIT

{
  printf 'MODEL_API_BASE=%q\n' "$model_api_base"
  printf 'MODEL_API_KEY=%q\n' "$model_api_key"
  printf 'MODEL_NAME=%q\n' "$model_name"
  printf "MODEL_REQUIRE_TOOL_CALL='true'\n"
} >"$temporary_config"

"$SWITCH_SCRIPT" "$temporary_config"

echo "Main model restored from: $BACKUP_FILE"
