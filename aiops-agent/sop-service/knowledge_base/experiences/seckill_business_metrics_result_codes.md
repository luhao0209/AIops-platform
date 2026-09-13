# 秒杀业务指标怎么理解

## 现象
成功率下降、失败变多、用户说下单不行，但节点 CPU/内存未必同时报警。

## 本环境事实
- 主指标：`seckill_order_total`，标签 `result`
- 成功：`result="success"`（Agent 业务概览默认也按这个算）
- 业务入口在 `data-services`；网关资源名为 `biz-gateway` / Service `biz-gateway-svc`

## 先看结果分布，再决定像不像故障
1. 调 `get_business_overview`，看各 `result` 占比，不要只看成功率一个数。
2. 再按分布分流：

| 主要 result | 更像什么 | 下一步优先 |
|-------------|----------|------------|
| duplicate_order / duplicate_request | 重复提交/幂等 | 查日志与近期发布，不优先当节点故障 |
| sold_out / mysql_sold_out | 库存 | 业务库存与 MySQL（业务库），不是 aiops-mysql |
| activity_closed / user_not_found | 活动或用户规则 | 业务配置/数据，不是基础设施根因 |
| timeout / system_error / unknown_error 变多 | 链路/依赖异常可能 | 网关日志、Redis/MySQL 延迟与饱和、变更 |

## 继续条件
- 已拿到 result 分布后再分流。
- 若只有成功率总值、没有 result 分布，则只能判断「成功率异常」，不能直接归因为系统故障；先补分布再下结论。

## 查不到时
写明业务指标无样本、标签未命中或拿不到 result 分布；不要用「节点 CPU 正常」推断「下单一定正常」。

## 不要误判
- 成功率低 ≠ 集群坏了
- 不要用 aiops 平台组件状态直接解释秒杀失败
