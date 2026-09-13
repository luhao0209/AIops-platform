import time
from functools import wraps
from prometheus_client import Counter, Gauge, Histogram


DB_REQUEST_COUNT = Counter(
    "db_request_total",
    "Total database and cache requests",
    ["db_type", "operation", "status"],
)


DB_REQUEST_LATENCY = Histogram(
    "db_request_latency_seconds",
    "Database and cache request latency",
    ["db_type", "operation"],
    buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0],
)


SECKILL_ORDER_COUNT = Counter(
    "seckill_order_total",
    "Total seckill order requests",
    ["result"],
)


GATEWAY_INFLIGHT_REQUESTS = Gauge(
    "gateway_inflight_requests",
    "Gateway requests currently executing or waiting for application capacity",
)

GATEWAY_ACTIVE_REQUESTS = Gauge(
    "gateway_active_requests",
    "Gateway requests currently holding an application capacity slot",
)

GATEWAY_HTTP_REQUESTS_STARTED = Counter(
    "gateway_http_requests_started_total",
    "Gateway HTTP requests accepted before application queueing",
    ["method", "path"],
)

GATEWAY_HTTP_REQUESTS = Counter(
    "gateway_http_requests_total",
    "Completed gateway HTTP requests",
    ["method", "path", "status_code"],
)

GATEWAY_HTTP_LATENCY = Histogram(
    "gateway_http_request_duration_seconds",
    "End-to-end gateway HTTP request duration including application queue time",
    ["method", "path"],
    buckets=[
        0.01,
        0.025,
        0.05,
        0.1,
        0.2,
        0.3,
        0.5,
        0.75,
        1.0,
        2.0,
        5.0,
        10.0,
        20.0,
        30.0,
    ],
)


def monitor_db(db_type: str, operation: str):
    """
    通用数据库操作监控装饰器
    :param db_type: 'mysql' 或 'redis'
    :param operation: 操作类型，如 'select', 'update', 'get', 'decr' 等
    """

    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            start_time = time.time()
            try:
                result = await func(*args, **kwargs)
                DB_REQUEST_COUNT.labels(
                    db_type=db_type, operation=operation, status="success"
                ).inc()
                return result
            except Exception as exc:
                DB_REQUEST_COUNT.labels(
                    db_type=db_type, operation=operation, status="error"
                ).inc()
                raise exc
            finally:
                latency = time.time() - start_time
                DB_REQUEST_LATENCY.labels(
                    db_type=db_type, operation=operation
                ).observe(latency)

        return wrapper

    return decorator
