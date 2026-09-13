#!/usr/bin/env sh

set -eu

DATA_NAMESPACE="${DATA_NAMESPACE:-data-services}"
GATEWAY_DEPLOYMENT="${GATEWAY_DEPLOYMENT:-biz-gateway}"
TARGET_STOCK="${TARGET_STOCK:-10000}"
TARGET_USERS="${TARGET_USERS:-20000}"
QUIESCE_SECONDS="${QUIESCE_SECONDS:-3}"
CONFIRM_TEXT="REFRESH_SECKILL_TEST_DATA"

if [ "${CONFIRM_REFRESH:-}" != "${CONFIRM_TEXT}" ]; then
  echo "Refusing maintenance refresh."
  echo "Stop the load test first, then run:"
  echo "CONFIRM_REFRESH=${CONFIRM_TEXT} TARGET_STOCK=${TARGET_STOCK} $0"
  exit 2
fi

case "${TARGET_STOCK}" in
  ''|*[!0-9]*)
    echo "TARGET_STOCK must be a non-negative integer" >&2
    exit 2
    ;;
esac

case "${TARGET_USERS}" in
  ''|*[!0-9]*)
    echo "TARGET_USERS must be a positive integer" >&2
    exit 2
    ;;
esac

if [ "${TARGET_USERS}" -le 0 ]; then
  echo "TARGET_USERS must be a positive integer" >&2
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

status_file="$(mktemp)"
status_restored="false"

restore_statuses() {
  if [ "${status_restored}" = "false" ] && [ -s "${status_file}" ]; then
    echo "[*] restoring original activity statuses"
    while read -r product_id status; do
      [ -n "${product_id}" ] || continue
      kubectl exec -n "${DATA_NAMESPACE}" deployment/redis-dev \
        -c redis -- redis-cli SET "seckill:status:${product_id}" "${status}" >/dev/null
    done < "${status_file}"
    status_restored="true"
  fi
  rm -f "${status_file}"
}

trap restore_statuses EXIT INT TERM

echo "[*] checking gateway availability"
kubectl rollout status deployment/"${GATEWAY_DEPLOYMENT}" \
  -n "${DATA_NAMESPACE}" --timeout=60s

products="$({
  kubectl exec -n "${DATA_NAMESPACE}" deployment/mysql-dev \
    -c mysql -- \
    env MYSQL_PWD="${MYSQL_PASSWORD}" \
    mysql -N -B -uroot aiops_mall -e \
    "SELECT product_id FROM seckill_inventory ORDER BY product_id;"
} | tr -d '\r')"

if [ -z "${products}" ]; then
  echo "No seckill products found" >&2
  exit 1
fi

echo "[*] pausing seckill activities without restarting biz-gateway"
for product_id in ${products}; do
  status="$(
    kubectl exec -n "${DATA_NAMESPACE}" deployment/redis-dev \
      -c redis -- redis-cli --raw GET "seckill:status:${product_id}" | tr -d '\r'
  )"
  status="${status:-1}"
  printf '%s %s\n' "${product_id}" "${status}" >> "${status_file}"
  kubectl exec -n "${DATA_NAMESPACE}" deployment/redis-dev \
    -c redis -- redis-cli SET "seckill:status:${product_id}" 0 >/dev/null
done

sleep "${QUIESCE_SECONDS}"

echo "[*] ensuring ${TARGET_USERS} users, clearing purchases and setting inventory to ${TARGET_STOCK}"
kubectl exec -n "${DATA_NAMESPACE}" deployment/mysql-dev \
  -c mysql -- \
  env MYSQL_PWD="${MYSQL_PASSWORD}" \
  mysql -uroot aiops_mall -e \
  "INSERT IGNORE INTO users (id, name, status)
   SELECT CONCAT('USER_', IF(seq < 10000, LPAD(seq, 4, '0'), seq)),
          CONCAT('测试用户', IF(seq < 10000, LPAD(seq, 4, '0'), seq)),
          'active'
   FROM (
     SELECT @row := @row + 1 AS seq
     FROM information_schema.columns a
     CROSS JOIN information_schema.columns b
     CROSS JOIN (SELECT @row := 0) vars
     LIMIT ${TARGET_USERS}
   ) AS generated_users;
   TRUNCATE TABLE seckill_orders;
   UPDATE seckill_inventory SET stock=${TARGET_STOCK};"

echo "[*] removing stale Redis order locks only"
kubectl exec -n "${DATA_NAMESPACE}" deployment/redis-dev \
  -c redis -- redis-cli EVAL \
  'local keys=redis.call("keys","seckill:order:*"); if #keys > 0 then return redis.call("del",unpack(keys)) else return 0 end' \
  0

echo "[*] synchronizing Redis inventory"
for product_id in ${products}; do
  kubectl exec -n "${DATA_NAMESPACE}" deployment/redis-dev \
    -c redis -- redis-cli SET "seckill:stock:${product_id}" "${TARGET_STOCK}" >/dev/null
done

restore_statuses
trap - EXIT INT TERM

echo "[*] verifying purchase records and inventory"
kubectl exec -n "${DATA_NAMESPACE}" deployment/mysql-dev \
  -c mysql -- \
  env MYSQL_PWD="${MYSQL_PASSWORD}" \
  mysql -uroot aiops_mall -e \
  "SELECT COUNT(*) AS user_count FROM users;
   SELECT COUNT(*) AS order_count FROM seckill_orders;
   SELECT product_id, stock, version FROM seckill_inventory ORDER BY product_id;"

echo "[*] confirming that Prometheus business metrics were preserved"
echo "No Prometheus delete_series or clean_tombstones operation was executed."
echo "[+] seckill test data refresh completed"
