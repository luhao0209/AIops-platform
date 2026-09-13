# 本环境 MySQL / Redis 指标与 PromQL 映射

## 适用场景
Agent 已明确要查询某个 MySQL 或 Redis 指标，但第一次调用 `get_metric_value` / `get_metric_trend` 后出现以下情况之一：

- `result_count = 0`，没有匹配到任何时间序列；
- Prometheus 返回 PromQL 或标签错误；
- 已知 Exporter 正常，但模型不确定本环境实际使用的指标名和标签。

本篇只用于修正查询参数，不是实时数据。拿到映射后最多重试一次现场指标工具；重试仍无数据时，只能报告指标证据不足。

## 0 条时序和真实值 0 的区别

- `result_count = 0`：查询没有匹配到时间序列，可能是指标名、标签、采集目标或时间窗口不对。此时可以查本篇映射并重试一次。
- `result_count > 0` 且 `value = 0`：已经匹配到真实时间序列，当前值就是 0。不要因为数值为 0 再查知识库或改写 PromQL。
- 工具返回 `error` / `timeout`：属于查询失败，不得解释为指标正常，也不得无限重试。

## 业务 MySQL 对象映射

- 逻辑实体：`biz-mysql`
- Kubernetes 命名空间：`data-services`
- 工作负载 Pod 前缀：`mysql-dev-`
- Exporter Service：`mysql-service`
- Exporter 端口：`9104`

MySQL Exporter 指标优先使用 `namespace`、`service`、`instance` 标签。本环境的 Exporter 指标不应擅自增加 `pod=~".*mysql.*"`；该过滤曾导致有效指标变成 0 条时序。

## MySQL 当前连接数

指标：`mysql_global_status_threads_connected`

```promql
mysql_global_status_threads_connected{namespace="data-services",service="mysql-service"}
```

作用：表示当前已经建立的客户端连接数量。判断连接压力时还必须同时查询 `max_connections`，不能只看当前连接数的绝对值。

## MySQL 最大连接数

指标：`mysql_global_variables_max_connections`

```promql
mysql_global_variables_max_connections{namespace="data-services",service="mysql-service"}
```

连接使用率计算：

```text
threads_connected / max_connections * 100%
```

若当前连接数有数据、最大连接数无数据，只报告当前值，不要自行假设上限。

## 业务 Redis 对象映射

- 逻辑实体：`biz-redis`
- Kubernetes 命名空间：`data-services`
- 工作负载 Pod 前缀：`redis-dev-`
- Exporter Service：`redis-service`
- Exporter 端口：`9121`

Redis Exporter 指标优先使用 `namespace`、`service`、`instance` 标签。`pod` 标签适用于 cAdvisor 容器指标，不一定存在于 Redis Exporter 指标中。

## Redis 数据内存

指标：`redis_memory_used_bytes`

```promql
redis_memory_used_bytes{namespace="data-services",service="redis-service"}
```

这是 Redis 内部保存数据及相关结构使用的内存，不等同于容器工作集。容器内存应另外查询 `container_memory_working_set_bytes`。

## Redis 最大内存配置

指标：`redis_memory_max_bytes`

```promql
redis_memory_max_bytes{namespace="data-services",service="redis-service"}
```

匹配到时间序列且值为 0 时，通常表示没有设置 `maxmemory`，不是查询无数据。此时不能计算 Redis 内部内存使用率百分比。

## Redis 最近 5 分钟缓存命中率

指标：`redis_keyspace_hits_total`、`redis_keyspace_misses_total`

```promql
(
  100
  * sum(rate(redis_keyspace_hits_total{namespace="data-services",service="redis-service"}[5m]))
  / clamp_min(
      sum(rate(redis_keyspace_hits_total{namespace="data-services",service="redis-service"}[5m]))
      + sum(rate(redis_keyspace_misses_total{namespace="data-services",service="redis-service"}[5m])),
      1
    )
)
and
(
  sum(rate(redis_keyspace_hits_total{namespace="data-services",service="redis-service"}[5m]))
  + sum(rate(redis_keyspace_misses_total{namespace="data-services",service="redis-service"}[5m]))
  > 0
)
```

命中率必须使用 `rate(...[5m])` 观察近期变化。不要直接用两个累计 Counter 相除解释“当前命中率”；累计值会混入 Redis 启动以来的全部历史请求。无读请求时该查询应视为 NoData，而不是 0% 命中率。

## MySQL Pod 资源使用

MySQL Pod CPU：

```promql
sum(
  rate(container_cpu_usage_seconds_total{
    namespace="data-services",
    pod=~"mysql-dev-.*",
    container!="",
    image!=""
  }[5m])
) by (pod)
```

MySQL Pod 内存：

```promql
sum(
  container_memory_working_set_bytes{
    namespace="data-services",
    pod=~"mysql-dev-.*",
    container!="",
    image!=""
  }
) by (pod)
```

## Redis Pod 资源使用

Redis Pod CPU：

```promql
sum(
  rate(container_cpu_usage_seconds_total{
    namespace="data-services",
    pod=~"redis-dev-.*",
    container!="",
    image!=""
  }[5m])
) by (pod)
```

Redis Pod 内存：

```promql
sum(
  container_memory_working_set_bytes{
    namespace="data-services",
    pod=~"redis-dev-.*",
    container!="",
    image!=""
  }
) by (pod)
```

## 一次性回退流程

1. 第一次调用指标工具，检查 `result_count`、`value` 和 `error`，不要只看 summary。
2. 仅当 `result_count = 0` 或返回错误时，调用 `search_knowledge_base`，检索文本应包含组件、指标目的和“PromQL 标签映射”。
3. 使用命中的本环境映射重写 PromQL，再调用一次原指标工具。
4. 第二次仍无时间序列时停止重试，报告采集、标签或目标可能不匹配，不能断言组件正常或异常。
5. 不要因为 `result_count > 0, value = 0` 触发回退。
