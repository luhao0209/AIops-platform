import os

import aiomysql
import redis.asyncio as aioredis

from metrics import monitor_db


MYSQL_HOST = os.getenv("MYSQL_HOST", "mysql-service")
MYSQL_USER = os.getenv("MYSQL_USER", "root")
MYSQL_PASSWORD = os.getenv("MYSQL_PASSWORD", "")
MYSQL_DB = os.getenv("MYSQL_DB", "aiops_mall")

REDIS_HOST = os.getenv("REDIS_HOST", "redis-service")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))

mysql_pool = None
redis_client = None


def stock_key(product_id: str) -> str:
    return f"seckill:stock:{product_id}"


def status_key(product_id: str) -> str:
    return f"seckill:status:{product_id}"


def order_lock_key(product_id: str, user_id: str) -> str:
    return f"seckill:order:{product_id}:{user_id}"


@monitor_db(db_type="redis", operation="get")
async def get_seckill_status(redis: aioredis.Redis, product_id: str):
    """获取活动状态，1 表示开启。"""
    return await redis.get(status_key(product_id))


@monitor_db(db_type="redis", operation="set")
async def acquire_order_lock(
    redis: aioredis.Redis,
    product_id: str,
    user_id: str,
    ttl: int = 30,
):
    """基于 Redis 实现用户维度幂等锁，防止重复下单。"""
    return await redis.set(
        order_lock_key(product_id, user_id),
        "1",
        ex=ttl,
        nx=True,
    )


@monitor_db(db_type="redis", operation="delete")
async def release_order_lock(
    redis: aioredis.Redis,
    product_id: str,
    user_id: str,
):
    """释放下单锁。"""
    return await redis.delete(order_lock_key(product_id, user_id))


@monitor_db(db_type="redis", operation="decr")
async def deduct_redis_stock(redis: aioredis.Redis, product_id: str):
    """扣减 Redis 预热库存。"""
    return await redis.decr(stock_key(product_id))


@monitor_db(db_type="redis", operation="incr")
async def rollback_redis_stock(redis: aioredis.Redis, product_id: str):
    """当 MySQL 事务失败时，对 Redis 库存做补偿。"""
    return await redis.incr(stock_key(product_id))


@monitor_db(db_type="redis", operation="get")
async def get_redis_stock(redis: aioredis.Redis, product_id: str):
    """查询 Redis 当前库存。"""
    value = await redis.get(stock_key(product_id))
    return int(value) if value is not None else None


@monitor_db(db_type="mysql", operation="select")
async def get_user_info(conn: aiomysql.Connection, user_id: str):
    """查询用户信息。"""
    async with conn.cursor(aiomysql.DictCursor) as cur:
        await cur.execute(
            "SELECT id, name FROM users "
            "WHERE id=%s AND status='active'",
            (user_id,),
        )
        return await cur.fetchone()


@monitor_db(db_type="mysql", operation="select")
async def has_existing_order(
    conn: aiomysql.Connection,
    user_id: str,
    product_id: str,
):
    """校验用户是否已经成功下单。"""
    async with conn.cursor() as cur:
        await cur.execute(
            """
            SELECT 1
            FROM seckill_orders
            WHERE user_id=%s AND product_id=%s AND status='SUCCESS'
            LIMIT 1
            """,
            (user_id, product_id),
        )
        return await cur.fetchone() is not None


@monitor_db(db_type="mysql", operation="update")
async def deduct_mysql_stock(conn: aiomysql.Connection, product_id: str):
    """事务内扣减真实库存，失败时返回 False。"""
    async with conn.cursor() as cur:
        await cur.execute(
            """
            UPDATE seckill_inventory
            SET stock = stock - 1, version = version + 1
            WHERE product_id=%s AND stock > 0
            """,
            (product_id,),
        )
        return cur.rowcount == 1


@monitor_db(db_type="mysql", operation="insert")
async def create_order(
    conn: aiomysql.Connection,
    order_no: str,
    user_id: str,
    product_id: str,
):
    """创建秒杀订单记录。"""
    async with conn.cursor() as cur:
        await cur.execute(
            """
            INSERT INTO seckill_orders (order_no, user_id, product_id, status)
            VALUES (%s, %s, %s, 'SUCCESS')
            """,
            (order_no, user_id, product_id),
        )


@monitor_db(db_type="mysql", operation="select")
async def get_inventory_snapshot(
    conn: aiomysql.Connection,
    product_id: str,
):
    """查询 MySQL 库存快照，方便接口返回与演示。"""
    async with conn.cursor(aiomysql.DictCursor) as cur:
        await cur.execute(
            """
            SELECT product_id, product_name, stock, version
            FROM seckill_inventory
            WHERE product_id=%s
            """,
            (product_id,),
        )
        return await cur.fetchone()


async def init_db_pools():
    """初始化全局连接池。"""
    global mysql_pool, redis_client

    mysql_pool = await aiomysql.create_pool(
        host=MYSQL_HOST,
        port=3306,
        user=MYSQL_USER,
        password=MYSQL_PASSWORD,
        db=MYSQL_DB,
        minsize=5,
        maxsize=50,
        autocommit=False,
    )

    redis_client = aioredis.Redis(
        host=REDIS_HOST,
        port=REDIS_PORT,
        decode_responses=True,
        max_connections=100,
    )
    print("[+] 数据库与缓存异步连接池初始化完成")


async def close_db_pools():
    """关闭全局连接池。"""
    if mysql_pool:
        mysql_pool.close()
        await mysql_pool.wait_closed()
    if redis_client:
        await redis_client.close()


async def get_db_conn():
    """FastAPI 依赖注入：获取 MySQL 连接。"""
    async with mysql_pool.acquire() as conn:
        yield conn


async def get_redis():
    """FastAPI 依赖注入：获取 Redis 连接。"""
    yield redis_client
