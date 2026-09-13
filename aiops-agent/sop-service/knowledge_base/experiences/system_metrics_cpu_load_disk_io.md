# 系统指标速查：CPU / Load / 磁盘 IO

## 适用范围
用于节点或机器级异常：告警、负载高、变慢、CPU 飙高。
不用于先解释业务成功率（那走业务指标文档）。

## CPU 指标
### 作用
反映处理器繁忙程度，用于判断算力是否打满、是否突增。

### 典型现象 → 可能问题
- CPU 突然增高并告警 → 可能是毛刺、周期任务、或持续过载

### 应该怎么查
1. 先查该节点近 1h～6h CPU 趋势：调用 `get_metric_trend`（或受控意图 `node_cpu_trend`），window 用 `1h` 或 `6h`
2. 若怀疑某个工作负载：再调 `get_topk_resource_consumers(resource_type='cpu')`

### 结果怎么读
- 尖刺后回落 → 偏毛刺，先观察
- 等间隔反复尖刺 → 偏周期任务
- 持续抬高不回落 → 偏过载，继续 TopK / 变更

### 查不到时
说明证据不足（PromQL、instance 或采集可能不对），不要断言 CPU 正常或异常。

## Load 与 CPU 对比
### 作用
Load 反映排队/等待；和 CPU 对比可区分「在算」还是「在等」（如 IO）。

### 典型现象 → 可能问题
- Load 很高，但 CPU 利用率不高 → 优先怀疑磁盘 IO 或其它等待，而不是纯 CPU 打满

### 应该怎么查
1. 同窗口拉 load 与 CPU 趋势（`get_metric_trend`）
2. 再拉磁盘 IO：util / 读写速率 / IOPS / IO 耗时（`get_metric_trend` + `node_disk_*`；或受控意图 `node_disk_io_overview`）

### 结果怎么读
- Load 高 + CPU 不高 + 磁盘 util/延迟差 → 偏磁盘 IO
- Load 高 + CPU 也高 → 回到 CPU 过载路径
- 磁盘序列无数据 → 只写「IO 证据不足」，并提示核对节点 instance 是否有 node_exporter / `node_disk_*`；禁止写已排除或已确认 IO

## 磁盘 IO 指标
### 作用
反映盘是否忙、读写是否堆积，解释「慢但 CPU 不高」。

### 典型现象 → 可能问题
- 机器慢、Load 高、CPU 不高 → 可能是磁盘 IO 瓶颈

### 应该怎么查
同「Load 与 CPU 对比」第 2 步；有数据再解读，无数据走「查不到时」。

### 查不到时
只报告无磁盘 IO 时间序列、证据不足；可建议核对目标节点是否有 `node_disk_*`，不要编造 IO 结论。

## 不要误判
- 磁盘空间使用率高 ≠ IO 打满（容量看 saturation，IO 看 util/延迟/IOPS）
- 单次采样点不能定根因
- 本篇只处理系统指标；成功率下降先查业务指标文档
