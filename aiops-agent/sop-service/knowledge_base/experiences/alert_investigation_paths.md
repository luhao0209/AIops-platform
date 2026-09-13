# 本环境告警出现后先查什么

## 现象
Alertmanager/界面出现 firing 告警，或用户丢来某个 alertname。

## 本环境事实
- 告警组：`aiops-mall-alerts`
- 告警由 Alertmanager 发送到 Agent 执行器：`http://agent-executor.aiops.svc.cluster.local:9300/api/alerts/webhook`
- 先 `get_alerts` / `get_alert_detail` 确认 alertname 与实例，再选路径
- 先确认 alertname 对应的是节点告警、业务依赖告警，还是业务入口告警，不要只凭名称联想

## 告警名 → 优先路径

### NodeCPUHigh
- 含义：节点 CPU 使用率持续偏高（规则约 >80%）
- 优先：`get_infrastructure_saturation(component_type=node)` → `get_topk_resource_consumers(cpu)` → 必要时 `get_metric_trend` 看是毛刺还是持续
- 若现象已恢复，优先回看趋势，不要只看当前值
- 不要：一上来只查业务成功率

### NodeMemoryHigh
- 含义：节点内存使用率偏高（规则约 >85%）
- 优先：节点饱和度 → 内存 TopK → 看是否空节点系统占用 vs 业务 Pod
- 若现象已恢复，优先回看趋势，不要只看当前值
- 不要：把平台节点内存直接说成秒杀失败根因（除非时间窗与业务失败对齐）

### MySQLLockWait
- 含义：业务 MySQL 行锁等待在增加（秒杀锁冲突靶心）
- 优先：业务结果分布（是否 sold_out/失败激增）+ 业务库相关指标/日志；对象在 data-services，不是 aiops-mysql
- 不要：去 aiops 命名空间查平台库

### RedisHitDrop
- 含义：Redis 命中率掉到约 70% 以下
- 优先：是否缓存击穿/大面积未命中；结合秒杀失败分布与 Redis 侧饱和/错误
- 不要：先当网关 HTTP 自身问题

### GatewayLatency
- 含义：告警名像网关延迟，但规则实际看的是 `db_request_latency_seconds` 平均耗时（约 >0.5s）
- 优先：当「网关访问 Redis/MySQL 变慢」查，用依赖延迟/错误与业务失败是否同期；不要当成通用 HTTP P95 探针
- 不要：只重启网关或只查节点 CPU

## 查不到时
- 告警详情无实例或指标无数据 → 只写证据不足；可核对 Alertmanager 与网关 webhook 是否仍连通
- 若告警有名无实例，先检查告警标签是否缺失，而不是直接判断监控异常
