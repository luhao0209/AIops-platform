#!/usr/bin/env sh

set -eu

DATA_NAMESPACE="${DATA_NAMESPACE:-data-services}"
AIOPS_NAMESPACE="${AIOPS_NAMESPACE:-aiops}"
MONITORING_NAMESPACE="${MONITORING_NAMESPACE:-monitoring}"
GATEWAY_DEPLOYMENT="${GATEWAY_DEPLOYMENT:-biz-gateway}"
INITIAL_STOCK="${INITIAL_STOCK:-1000}"
CONFIRM_TEXT="RESET_SECKILL_BASELINE"

if [ "${CONFIRM_RESET:-}" != "${CONFIRM_TEXT}" ]; then
  echo "Refusing destructive reset."
  echo "Run with: CONFIRM_RESET=${CONFIRM_TEXT} $0"
  exit 2
fi

MYSQL_PASSWORD="${MYSQL_PASSWORD:-}"
if [ -z "${MYSQL_PASSWORD}" ]; then
  MYSQL_PASSWORD="$(
    kubectl get secret mysql-credentials \
      -n "${DATA_NAMESPACE}" \
      -o jsonpath='{.data.MYSQL_ROOT_PASSWORD}' | base64 --decode
  )"
fi
if [ -z "${MYSQL_PASSWORD}" ]; then
  echo "MYSQL_PASSWORD is empty" >&2
  exit 2
fi

original_replicas="$(
  kubectl get deployment "${GATEWAY_DEPLOYMENT}" \
    -n "${DATA_NAMESPACE}" \
    -o jsonpath='{.spec.replicas}'
)"
original_replicas="${original_replicas:-1}"
gateway_stopped="false"

restore_gateway() {
  if [ "${gateway_stopped}" = "true" ]; then
    echo "[*] restoring ${GATEWAY_DEPLOYMENT} replicas=${original_replicas}"
    kubectl scale deployment "${GATEWAY_DEPLOYMENT}" \
      -n "${DATA_NAMESPACE}" \
      --replicas="${original_replicas}"
    kubectl rollout status deployment/"${GATEWAY_DEPLOYMENT}" \
      -n "${DATA_NAMESPACE}" \
      --timeout=180s
    gateway_stopped="false"
  fi
}

trap restore_gateway EXIT INT TERM

echo "[*] stopping gateway writes and in-process counters"
kubectl scale deployment "${GATEWAY_DEPLOYMENT}" \
  -n "${DATA_NAMESPACE}" \
  --replicas=0
gateway_stopped="true"
kubectl rollout status deployment/"${GATEWAY_DEPLOYMENT}" \
  -n "${DATA_NAMESPACE}" \
  --timeout=180s

echo "[*] clearing order records and restoring MySQL inventory"
kubectl exec -n "${DATA_NAMESPACE}" deployment/mysql-dev \
  -c mysql -- \
  env MYSQL_PWD="${MYSQL_PASSWORD}" \
  mysql -uroot aiops_mall -e \
  "TRUNCATE TABLE seckill_orders; UPDATE seckill_inventory SET stock=${INITIAL_STOCK}, version=0;"

echo "[*] clearing Redis seckill keys and warming inventory"
kubectl exec -n "${DATA_NAMESPACE}" deployment/redis-dev \
  -c redis -- redis-cli EVAL \
  'local keys=redis.call("keys","seckill:*"); if #keys > 0 then return redis.call("del",unpack(keys)) else return 0 end' \
  0

kubectl exec -n "${DATA_NAMESPACE}" deployment/redis-dev \
  -c redis -- redis-cli MSET \
  seckill:stock:PROD_618_001 "${INITIAL_STOCK}" \
  seckill:status:PROD_618_001 1 \
  seckill:stock:PROD_618_002 "${INITIAL_STOCK}" \
  seckill:status:PROD_618_002 1 \
  seckill:stock:PROD_618_003 "${INITIAL_STOCK}" \
  seckill:status:PROD_618_003 1 \
  seckill:stock:PROD_618_004 "${INITIAL_STOCK}" \
  seckill:status:PROD_618_004 1 \
  seckill:stock:PROD_618_005 "${INITIAL_STOCK}" \
  seckill:status:PROD_618_005 1

echo "[*] deleting only seckill business series from Prometheus"
kubectl exec -n "${AIOPS_NAMESPACE}" deployment/aiops-agent -- \
  python -c '
import urllib.parse
import urllib.request

base = "http://prometheus.monitoring.svc.cluster.local:9090"
selector = "{__name__=~\"seckill_order_total|seckill_inventory_stock\"}"
query = urllib.parse.urlencode([("match[]", selector)])

delete_request = urllib.request.Request(
    base + "/api/v1/admin/tsdb/delete_series?" + query,
    data=b"",
    method="POST",
)
with urllib.request.urlopen(delete_request, timeout=30) as response:
    print("delete_series", response.status, response.read().decode())

clean_request = urllib.request.Request(
    base + "/api/v1/admin/tsdb/clean_tombstones",
    data=b"",
    method="POST",
)
try:
    with urllib.request.urlopen(clean_request, timeout=120) as response:
        print("clean_tombstones", response.status, response.read().decode())
except (TimeoutError, OSError) as exc:
    print(
        "clean_tombstones warning:",
        exc,
        "(series deletion already succeeded; physical cleanup can finish later)",
    )
'

restore_gateway
trap - EXIT INT TERM

echo "[*] verifying reset"
kubectl exec -n "${DATA_NAMESPACE}" deployment/mysql-dev \
  -c mysql -- \
  env MYSQL_PWD="${MYSQL_PASSWORD}" \
  mysql -uroot aiops_mall -e \
  "SELECT COUNT(*) AS order_count FROM seckill_orders; SELECT product_id, stock, version FROM seckill_inventory ORDER BY product_id;"

kubectl exec -n "${DATA_NAMESPACE}" deployment/redis-dev \
  -c redis -- redis-cli MGET \
  seckill:stock:PROD_618_001 \
  seckill:stock:PROD_618_002 \
  seckill:stock:PROD_618_003 \
  seckill:stock:PROD_618_004 \
  seckill:stock:PROD_618_005

echo "[+] seckill baseline reset completed"
