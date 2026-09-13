#!/usr/bin/env bash

set -Eeuo pipefail

NAMESPACE="${NAMESPACE:-aiops}"
DEPLOYMENT="${DEPLOYMENT:-agent-executor}"
SECRET_NAME="${SECRET_NAME:-agent-executor-llm}"
CONFIG_FILE="${1:-/root/.config/aiops/main-model.env}"
BACKUP_DIR="${BACKUP_DIR:-/root/aiops-agent/backups/model-secrets}"
ROLLOUT_TIMEOUT="${ROLLOUT_TIMEOUT:-180s}"
HEALTH_TIMEOUT_SECONDS="${HEALTH_TIMEOUT_SECONDS:-90}"

secret_changed=false
secret_existed=false
old_api_base=""
old_api_key=""
old_model_name=""

fail() {
  echo "ERROR: $*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

decode_secret_key() {
  local key="$1"
  kubectl get secret "$SECRET_NAME" \
    -n "$NAMESPACE" \
    -o "jsonpath={.data.${key}}" | base64 --decode
}

apply_secret() {
  local api_base="$1"
  local api_key="$2"
  local model_name="$3"

  kubectl create secret generic "$SECRET_NAME" \
    -n "$NAMESPACE" \
    --from-literal=MODEL_API_BASE="$api_base" \
    --from-literal=MODEL_API_KEY="$api_key" \
    --from-literal=MODEL_NAME="$model_name" \
    --dry-run=client \
    -o yaml | kubectl apply -f - >/dev/null
}

rollback() {
  local exit_code=$?

  if [[ "$secret_changed" != "true" ]]; then
    exit "$exit_code"
  fi

  set +e
  echo "Switch failed; restoring the previous main-model Secret..." >&2

  if [[ "$secret_existed" == "true" ]]; then
    apply_secret "$old_api_base" "$old_api_key" "$old_model_name"
    kubectl rollout restart deployment/"$DEPLOYMENT" -n "$NAMESPACE" >/dev/null
    kubectl rollout status deployment/"$DEPLOYMENT" \
      -n "$NAMESPACE" \
      --timeout="$ROLLOUT_TIMEOUT"
  else
    kubectl delete secret "$SECRET_NAME" -n "$NAMESPACE" --ignore-not-found
  fi

  echo "Previous main-model configuration restored." >&2
  exit "$exit_code"
}

trap rollback ERR

require_command kubectl
require_command python3
require_command base64

[[ -f "$CONFIG_FILE" ]] || fail "config file not found: $CONFIG_FILE"

config_mode="$(stat -c '%a' "$CONFIG_FILE")"
if (( 10#$config_mode % 100 != 0 )); then
  fail "config file permissions must be 600: chmod 600 '$CONFIG_FILE'"
fi

source "$CONFIG_FILE"

: "${MODEL_API_BASE:?MODEL_API_BASE is required}"
: "${MODEL_API_KEY:?MODEL_API_KEY is required}"
: "${MODEL_NAME:?MODEL_NAME is required}"

MODEL_API_BASE="${MODEL_API_BASE%/}"
MODEL_REQUIRE_TOOL_CALL="${MODEL_REQUIRE_TOOL_CALL:-true}"

if [[ "$MODEL_API_KEY" == "replace-with-your-api-key" ]]; then
  fail "replace the placeholder MODEL_API_KEY before running the script"
fi

echo "Preflight: ${MODEL_NAME} at ${MODEL_API_BASE}"
MODEL_API_BASE="$MODEL_API_BASE" \
MODEL_API_KEY="$MODEL_API_KEY" \
MODEL_NAME="$MODEL_NAME" \
MODEL_REQUIRE_TOOL_CALL="$MODEL_REQUIRE_TOOL_CALL" \
python3 - <<'PY'
import json
import os
from urllib.error import HTTPError
from urllib.request import Request, urlopen

base = os.environ["MODEL_API_BASE"].rstrip("/")
key = os.environ["MODEL_API_KEY"]
model = os.environ["MODEL_NAME"]
require_tool_call = os.environ["MODEL_REQUIRE_TOOL_CALL"].lower() == "true"

payload = {
    "model": model,
    "messages": [
        {
            "role": "user",
            "content": "Call model_switch_probe with value ok.",
        }
    ],
    "temperature": 0,
    "max_tokens": 64,
}

if require_tool_call:
    payload["tools"] = [
        {
            "type": "function",
            "function": {
                "name": "model_switch_probe",
                "description": "Checks function-calling compatibility.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "value": {"type": "string"},
                    },
                    "required": ["value"],
                    "additionalProperties": False,
                },
            },
        }
    ]
    payload["tool_choice"] = {
        "type": "function",
        "function": {"name": "model_switch_probe"},
    }

request = Request(
    f"{base}/chat/completions",
    data=json.dumps(payload).encode("utf-8"),
    headers={
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json",
    },
    method="POST",
)

try:
    with urlopen(request, timeout=45) as response:
        result = json.loads(response.read().decode("utf-8"))
except HTTPError as exc:
    detail = exc.read().decode("utf-8", errors="replace")
    raise SystemExit(f"model preflight failed: HTTP {exc.code}: {detail}")

choices = result.get("choices") or []
if not choices:
    raise SystemExit("model preflight failed: response has no choices")

message = choices[0].get("message") or {}
if require_tool_call and not message.get("tool_calls"):
    raise SystemExit("model preflight failed: function call was not returned")

usage = result.get("usage") or {}
print(
    "Preflight passed; total_tokens=",
    usage.get("total_tokens", "unknown"),
    sep="",
)
PY

mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"

if kubectl get secret "$SECRET_NAME" -n "$NAMESPACE" >/dev/null 2>&1; then
  secret_existed=true
  old_api_base="$(decode_secret_key MODEL_API_BASE)"
  old_api_key="$(decode_secret_key MODEL_API_KEY)"
  old_model_name="$(decode_secret_key MODEL_NAME)"

  backup_file="${BACKUP_DIR}/${SECRET_NAME}-$(date +%Y%m%d-%H%M%S).yaml"
  kubectl get secret "$SECRET_NAME" -n "$NAMESPACE" -o yaml >"$backup_file"
  chmod 600 "$backup_file"
  echo "Base64-encoded Secret backup written to: $backup_file"
fi

apply_secret "$MODEL_API_BASE" "$MODEL_API_KEY" "$MODEL_NAME"
secret_changed=true

kubectl rollout restart deployment/"$DEPLOYMENT" -n "$NAMESPACE" >/dev/null
kubectl rollout status deployment/"$DEPLOYMENT" \
  -n "$NAMESPACE" \
  --timeout="$ROLLOUT_TIMEOUT"

health_payload=""
health_deadline=$((SECONDS + HEALTH_TIMEOUT_SECONDS))

echo "Waiting for the new Agent HTTP endpoint..."
while (( SECONDS < health_deadline )); do
  newest_pod="$(
    kubectl get pods \
      -n "$NAMESPACE" \
      -l app=agent-executor \
      --sort-by=.metadata.creationTimestamp \
      -o jsonpath='{.items[-1].metadata.name}' \
      2>/dev/null || true
  )"

  if [[ -n "$newest_pod" ]] && health_payload="$(
    kubectl exec -n "$NAMESPACE" "$newest_pod" -- \
      python -c \
      "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:9300/healthz', timeout=5).read().decode())" \
      2>/dev/null
  )"; then
    break
  fi

  health_payload=""
  sleep 3
done

if [[ -z "$health_payload" ]]; then
  fail "Agent health endpoint did not become ready within ${HEALTH_TIMEOUT_SECONDS}s"
fi

HEALTH_PAYLOAD="$health_payload" \
EXPECTED_BASE="$MODEL_API_BASE" \
EXPECTED_MODEL="$MODEL_NAME" \
python3 - <<'PY'
import json
import os

health = json.loads(os.environ["HEALTH_PAYLOAD"])
expected_base = os.environ["EXPECTED_BASE"]
expected_model = os.environ["EXPECTED_MODEL"]

if not health.get("model_configured"):
    raise SystemExit("health check failed: model is not configured")
if health.get("model_base") != expected_base:
    raise SystemExit(
        f"health check failed: model_base={health.get('model_base')!r}"
    )
if health.get("model_name") != expected_model:
    raise SystemExit(
        f"health check failed: model_name={health.get('model_name')!r}"
    )

print(json.dumps(health, ensure_ascii=False))
PY

secret_changed=false
unset MODEL_API_KEY old_api_key

echo "Main chat model switched successfully."
echo "Summary model, embedding service, and knowledge service were not changed."
