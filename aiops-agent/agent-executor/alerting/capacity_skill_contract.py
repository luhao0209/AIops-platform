from __future__ import annotations


CAPACITY_SCALING_SKILL = "capacity_scaling"
ACTIVATE_CAPACITY_SKILL_TOOL = "activate_capacity_scaling_skill"
REQUEST_SCALE_APPROVAL_TOOL = "request_scale_approval"
CAPACITY_WORKFLOW_TOOL_NAMES = {
    ACTIVATE_CAPACITY_SKILL_TOOL,
    REQUEST_SCALE_APPROVAL_TOOL,
}

CAPACITY_SKILL_INSTRUCTIONS = (
    "已进入 capacity_scaling Skill。接下来只围绕服务实例容量不足假设补证据："
    "确认高并发或请求量持续存在、端到端延迟或处理中请求发生堆积；"
    "对于 GatewayCapacitySaturation，还必须用业务概览确认真实下单计数大于零，"
    "当前 Deployment 副本数、Ready 状态和当前 Pod 所在节点；随后必须针对该节点调用"
    "get_infrastructure_saturation(component_type=node, target_name=节点名)，确认 CPU、"
    "内存和磁盘均未接近饱和，证明节点仍有承载新副本的余量，并排除已观察到的代码异常、发布回归和"
    "下游依赖故障。错误率为零且同窗口无错误日志时，不要为了证明所有依赖绝对健康而"
    "继续做泛化查询；只有已有证据指向具体依赖时才补查。不要把单个瞬时尖峰或单纯 CPU 高直接解释为"
    "需要扩容。节点资源证据缺失，或 CPU >= 80%、内存 >= 85%、磁盘 >= 90% 时，不得申请扩容。"
    "只有证据同时支持流量真实、多个现有实例均在承压、依赖健康、节点有资源余量且"
    "增加一个副本具有明确预期收益时，才调用 request_scale_approval 创建人工审批。"
    "审批目标必须是当前副本数加一；证据反驳容量假设时应退出该方向并继续通用调查。"
)
