# AIOps Knowledge Templates

本文件用于约定向量知识库的两类知识模板：
- SOP：结构化 JSON，偏 workflow
- 运维经验文档：Markdown，偏 skill

---

## 1. SOP JSON Template

SOP 是项目内工作流型知识，允许包含当前系统环境中的组件名、接口、工具名、命令模板和输出关注点。

```json
{
  "knowledge_id": "SOP-2026-001",
  "knowledge_type": "workflow_sop",
  "title": "aiops-agent 发布后回归检查",
  "summary": "用于 aiops-agent 发布后的最小化回归验证，确认页面、接口、巡检与关键组件状态。",
  "trigger_conditions": [
    "aiops-agent 完成新版本发布",
    "发布后前端页面异常",
    "发布后巡检失败或成功率明显下降"
  ],
  "applicable_components": [
    "aiops-agent",
    "inspection-engine",
    "agent-executor"
  ],
  "tags": [
    "release",
    "verification",
    "aiops-agent"
  ],
  "workflow_steps": [
    {
      "step_order": 1,
      "goal": "确认首页与核心接口可访问",
      "recommended_tool": "get_business_overview",
    "recommended_command": "curl http://<NODE_IP>:30900/api/metrics",
      "output_focus": "确认 success_rate、active_alerts、agent_tokens 字段完整",
      "branch_hint": "如果接口不可达，优先检查 aiops-agent Pod、Service 与发布变更"
    },
    {
      "step_order": 2,
      "goal": "确认最近发布后是否存在异常变更",
      "recommended_tool": "search_change_events",
      "recommended_command": "查询 aiops-agent 最近 30 分钟的镜像、Pod、ReplicaSet 变更",
      "output_focus": "重点看镜像版本变化、Pod 重建、异常 Pending/CrashLoopBackOff",
      "branch_hint": "如果变更与异常时间吻合，进入发布回滚评估"
    },
    {
      "step_order": 3,
      "goal": "执行一次巡检确认系统整体健康度",
      "recommended_tool": "inspection",
      "recommended_command": "POST /api/chat/inspection",
      "output_focus": "重点看成功率、工作负载、关键变更与 AI 分析结论",
      "branch_hint": "如果成功率异常但基础设施正常，转交经验文档做进一步推理"
    }
  ],
  "risk_warnings": [
    "页面可访问不代表后端接口正常",
    "未确认异常根因前不要直接回滚全部组件",
    "生产高峰期优先限流和止血，再做结构性修复"
  ],
  "stabilization_advice": "如确认发布导致异常，可先限流或暂停继续发布，控制影响面。",
  "rollback_advice": "若发布与异常强相关，可回滚到上一稳定镜像版本，并重新执行巡检确认恢复。",
  "status": "approved",
  "created_by": "sre-admin",
  "updated_at": "2026-07-31T10:00:00Z"
}
```

### SOP 字段说明

- `knowledge_id`：唯一标识，建议固定且可读。
- `knowledge_type`：固定写 `workflow_sop`。
- `trigger_conditions`：什么情况下适用这条 SOP。
- `workflow_steps`：推荐的检查顺序，不要求绝对死板，但要有清晰路径。
- `recommended_tool`：推荐 Agent 调用的工具名。
- `recommended_command`：人工或 Agent 可执行的命令/接口提示。
- `output_focus`：重点看回显中的哪部分。
- `branch_hint`：如果这一步发现异常，下一步往哪里走。

### SOP 书写约束

- 可以出现当前项目中的接口、组件名、工具名。
- 可以出现命令模板，但不要写死不必要的环境细节。
- 要强调“推荐流程”和“分支判断”，不要写成僵硬流水线。

---

## 2. 运维经验文档 Markdown Template

运维经验文档是偏 skill 的认知型知识，不应该强绑定某个项目路径、某个页面地址、某个特定服务端口。

```md
# 下单成功率突降的通用排障思路

## 摘要
当系统出现下单成功率明显下降，但基础设施层面未必立刻报错时，优先区分业务失败与系统失败，再决定排查路径。

## 适用问题
- 成功率下降
- timeout 占比升高
- duplicate_order 占比升高
- 页面转圈但服务未完全中断

## 常见原因
- 上游网关到下游服务超时
- 数据库连接拥堵或慢查询增多
- 最近发布引入重试、幂等或流控逻辑异常
- 某些业务规则触发导致“非系统性失败”被误判为故障

## 排查思路
1. 先看结果分布，而不是只看成功率总值。
2. 再看趋势，确认是短时毛刺还是持续恶化。
3. 再核对异常时间窗口内是否有发布、扩缩容、配置变化或依赖抖动。
4. 最后交叉验证日志、指标、变更三条线，确认是否存在共同指向。

## 历史案例
### 案例一：重复订单激增但基础设施正常
某电商系统在活动高峰期成功率突降，初看像服务异常，后来发现 duplicate_order 激增，根因是重试逻辑改动破坏了幂等性。

### 案例二：数据库连接池耗尽导致超时增多
某支付系统出现大量 timeout，节点 CPU 并不高，最终定位为数据库连接长期占用未释放，连接池被打满。

## 经验结论
- 成功率下降不一定是基础设施故障。
- 先做问题分类，比盲目扩大排查范围更重要。
- 当日志、指标、变更在同一时间窗口内互相印证时，根因判断会更稳。

## 注意事项
- 不要把项目内特定路径、页面地址、接口端口写成经验文档核心内容。
- 经验文档强调“怎么想”，不是“具体怎么敲命令”。
```

### 运维经验文档约束

- 可以出现组件类别，如网关、数据库、缓存、消息队列。
- 不要强绑定 `web.html`、`/api/metrics`、固定 IP、固定端口等项目内细节。
- 重点写方法论、故障现象、常见原因、历史案例、判断思路。

---

## 3. 目录建议

建议后续在项目根下建立如下目录：

```text
knowledge_base/
├── sops/
│   ├── aiops_agent_release_check.json
│   ├── mysql_oom_workflow.json
│   └── gateway_timeout_workflow.json
└── experiences/
    ├── order_success_rate_drop.md
    ├── node_notready_diagnosis.md
    └── mysql_connection_pool_exhausted.md
```

---

## 4. 后续同步到向量库的建议

- `sops/*.json`：提取 `title`、`summary`、`trigger_conditions`、`workflow_steps.goal`、`output_focus` 组成检索文本。
- `experiences/*.md`：按 `##` 或 `###` 切块后，再做 embedding。
- 两类知识都应保留原始内容作为 payload，供 Agent 检索后阅读。
