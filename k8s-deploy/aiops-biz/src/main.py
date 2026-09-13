import asyncio
import os
import sys
import logging
import time
import uuid
from typing import Dict, Any
from fastapi import FastAPI, Depends, Request
from fastapi.responses import Response
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
import redis.asyncio as aioredis
import aiomysql

from metrics import (
    GATEWAY_ACTIVE_REQUESTS,
    GATEWAY_HTTP_LATENCY,
    GATEWAY_HTTP_REQUESTS,
    GATEWAY_HTTP_REQUESTS_STARTED,
    GATEWAY_INFLIGHT_REQUESTS,
    SECKILL_ORDER_COUNT,
)
from database import (
    init_db_pools,
    close_db_pools,
    get_db_conn,
    get_redis,
    get_seckill_status,
    acquire_order_lock,
    release_order_lock,
    deduct_redis_stock,
    rollback_redis_stock,
    get_redis_stock,
    get_user_info,
    has_existing_order,
    deduct_mysql_stock,
    create_order,
    get_inventory_snapshot,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger("aiops.gateway")
GATEWAY_VERSION = "v10"

def log_order_result(result: str, product_id: str, user_id: str, latency_ms: float, **extra: Any) -> None:
    log_payload = {
        "result": result,
        "product_id": product_id,
        "user_id": user_id,
        "latency_ms": round(latency_ms, 2),
    }
    log_payload.update(extra)
    logger.info("seckill order result: %s", log_payload)


app = FastAPI(title="AIOps Gateway")


GATEWAY_ORDER_WORKER_SLOTS = max(
    1,
    int(os.getenv("GATEWAY_ORDER_WORKER_SLOTS", "1000")),
)
GATEWAY_ORDER_PROCESSING_DELAY_SECONDS = max(
    0.0,
    float(os.getenv("GATEWAY_ORDER_PROCESSING_DELAY_MS", "0")) / 1000.0,
)
GATEWAY_ORDER_GATE = asyncio.Semaphore(GATEWAY_ORDER_WORKER_SLOTS)


def _metric_path(path: str) -> str:
    if path == "/api/seckill/order":
        return path
    if path.startswith("/api/seckill/state/"):
        return "/api/seckill/state/{product_id}"
    return "other"


@app.middleware("http")
async def observe_gateway_capacity(request: Request, call_next):
    """Measure real order queueing and end-to-end gateway latency."""
    if request.url.path in {"/metrics", "/healthz", "/webhook/alert"}:
        return await call_next(request)

    started_at = time.perf_counter()
    method = request.method
    path = _metric_path(request.url.path)
    status_code = 500
    GATEWAY_HTTP_REQUESTS_STARTED.labels(method=method, path=path).inc()
    try:
        if path != "/api/seckill/order":
            response = await call_next(request)
            status_code = response.status_code
            return response

        GATEWAY_INFLIGHT_REQUESTS.inc()
        try:
            async with GATEWAY_ORDER_GATE:
                GATEWAY_ACTIVE_REQUESTS.inc()
                try:
                    if GATEWAY_ORDER_PROCESSING_DELAY_SECONDS > 0:
                        await asyncio.sleep(
                            GATEWAY_ORDER_PROCESSING_DELAY_SECONDS
                        )
                    response = await call_next(request)
                    status_code = response.status_code
                    return response
                finally:
                    GATEWAY_ACTIVE_REQUESTS.dec()
        finally:
            GATEWAY_INFLIGHT_REQUESTS.dec()
    finally:
        GATEWAY_HTTP_REQUESTS.labels(
            method=method,
            path=path,
            status_code=str(status_code),
        ).inc()
        GATEWAY_HTTP_LATENCY.labels(method=method, path=path).observe(
            time.perf_counter() - started_at
        )


@app.on_event("startup")
async def startup_event():
    try:
        await init_db_pools()
        logger.info("gateway startup completed, version=%s", GATEWAY_VERSION)
    except Exception as exc:
        logger.exception("db pool init failed")
        sys.exit(1)


@app.on_event("shutdown")
async def shutdown_event():
    await close_db_pools()
    logger.info("gateway shutdown completed")


@app.get("/metrics", summary="Prometheus 监控指标抓取接口")
async def metrics():
    """
    K8s 里的 Prometheus 会定期访问此接口，拉取系统状态。
    这里包含 DB/Redis 埋点以及秒杀接口统计指标。
    """
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.get("/api/seckill/state/{product_id}", summary="查看库存快照")
async def seckill_state(
    product_id: str,
    conn: aiomysql.Connection = Depends(get_db_conn),
    redis: aioredis.Redis = Depends(get_redis),
):
    mysql_snapshot = await get_inventory_snapshot(conn, product_id)
    await conn.rollback()
    redis_stock = await get_redis_stock(redis, product_id)

    logger.info(
        "inventory snapshot queried: product_id=%s mysql_stock=%s redis_stock=%s",
        product_id,
        mysql_snapshot,
        redis_stock,
    )

    return {
        "code": 200,
        "data": {
            "mysql_stock": mysql_snapshot,
            "redis_stock": redis_stock,
        },
    }


@app.post("/api/seckill/order", summary="秒杀下单接口")
async def seckill(
    product_id: str,
    user_id: str,
    conn: aiomysql.Connection = Depends(get_db_conn),
    redis: aioredis.Redis = Depends(get_redis),
):
    """
    更贴近真实业务的一致性链路：
    1. 校验活动状态和用户合法性
    2. 获取 Redis 幂等锁，防止重复下单
    3. Redis 预扣库存，快速削峰
    4. MySQL 事务内校验是否重复下单、扣减真实库存、创建订单
    5. 事务失败时回滚并补偿 Redis
    """
    started_at = time.perf_counter()
    lock_acquired = False
    redis_deducted = False

    try:
        status = await get_seckill_status(redis, product_id)
        if status != "1":
            SECKILL_ORDER_COUNT.labels(result="activity_closed").inc()
            latency_ms = (time.perf_counter() - started_at) * 1000
            log_order_result("activity_closed", product_id, user_id, latency_ms, seckill_status=status)
            return {"code": 403, "msg": "秒杀活动未开启"}

        user = await get_user_info(conn, user_id)
        await conn.rollback()
        if not user:
            SECKILL_ORDER_COUNT.labels(result="user_not_found").inc()
            latency_ms = (time.perf_counter() - started_at) * 1000
            log_order_result("user_not_found", product_id, user_id, latency_ms)
            return {"code": 404, "msg": "用户不存在"}

        lock_acquired = bool(await acquire_order_lock(redis, product_id, user_id))
        if not lock_acquired:
            SECKILL_ORDER_COUNT.labels(result="duplicate_request").inc()
            latency_ms = (time.perf_counter() - started_at) * 1000
            log_order_result("duplicate_request", product_id, user_id, latency_ms)
            return {"code": 409, "msg": "请求处理中，请勿重复下单"}

        redis_stock = await deduct_redis_stock(redis, product_id)
        if redis_stock is None or redis_stock < 0:
            if redis_stock is not None and redis_stock < 0:
                await rollback_redis_stock(redis, product_id)
            SECKILL_ORDER_COUNT.labels(result="sold_out").inc()
            latency_ms = (time.perf_counter() - started_at) * 1000
            log_order_result("sold_out", product_id, user_id, latency_ms, redis_stock=redis_stock)
            return {"code": 400, "msg": "库存不足"}
        redis_deducted = True

        await conn.begin()

        if await has_existing_order(conn, user_id, product_id):
            await conn.rollback()
            await rollback_redis_stock(redis, product_id)
            redis_deducted = False
            SECKILL_ORDER_COUNT.labels(result="duplicate_order").inc()
            latency_ms = (time.perf_counter() - started_at) * 1000
            log_order_result("duplicate_order", product_id, user_id, latency_ms)
            return {"code": 409, "msg": "用户已成功下单，请勿重复购买"}

        stock_updated = await deduct_mysql_stock(conn, product_id)
        if not stock_updated:
            await conn.rollback()
            await rollback_redis_stock(redis, product_id)
            redis_deducted = False
            SECKILL_ORDER_COUNT.labels(result="mysql_sold_out").inc()
            latency_ms = (time.perf_counter() - started_at) * 1000
            log_order_result("mysql_sold_out", product_id, user_id, latency_ms)
            return {"code": 400, "msg": "库存不足，数据库扣减失败"}

        order_no = f"SK{uuid.uuid4().hex[:16].upper()}"
        await create_order(conn, order_no, user_id, product_id)
        await conn.commit()
        redis_deducted = False

        snapshot = await get_inventory_snapshot(conn, product_id)
        await conn.rollback()
        redis_current_stock = await get_redis_stock(redis, product_id)
        SECKILL_ORDER_COUNT.labels(result="success").inc()

        latency_ms = (time.perf_counter() - started_at) * 1000
        log_order_result(
            "success",
            product_id,
            user_id,
            latency_ms,
            order_no=order_no,
            mysql_stock=snapshot,
            redis_stock=redis_current_stock,
            gateway_version=GATEWAY_VERSION,
        )

        return {
            "code": 200,
            "msg": f"恭喜用户 {user_id} 秒杀成功！",
            "data": {
                "order_no": order_no,
                "user": user,
                "mysql_stock": snapshot,
                "redis_stock": redis_current_stock,
                "gateway_version": GATEWAY_VERSION,
            },
        }

    except Exception as exc:
        await conn.rollback()
        if redis_deducted:
            await rollback_redis_stock(redis, product_id)
        SECKILL_ORDER_COUNT.labels(result="system_error").inc()
        latency_ms = (time.perf_counter() - started_at) * 1000
        logger.exception(
            "seckill order exception: product_id=%s user_id=%s latency_ms=%.2f error=%s",
            product_id,
            user_id,
            latency_ms,
            exc,
        )
        return {"code": 500, "msg": f"系统繁忙，请稍后再试: {str(exc)}"}
    finally:
        if lock_acquired:
            await release_order_lock(redis, product_id, user_id)
