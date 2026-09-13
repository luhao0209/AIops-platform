from __future__ import annotations

from copy import deepcopy
from typing import Any


ALERT_ANALYSIS_PROFILES: dict[str, dict[str, Any]] = {
    "NodeCPUHigh": {
        "category": "node_resource",
        "required_evidence": [
            "alert_rule",
            "metric_trend",
            "node_top_pods",
            "pod_resource_trend",
        ],
        "instructions": [
            "确认告警规则和节点 CPU 历史趋势后，查询告警时点的节点 Pod CPU TopK。",
            "TopK 只能提供候选 Pod，必须继续核对候选 Pod 在同一告警窗口内的 CPU 趋势。",
        ],
        "tool_argument_overrides": {},
    },
    "OrderTechnicalAvailabilityLow": {
        "category": "business_reliability",
        "required_evidence": [
            "alert_rule",
            "metric_trend",
            "business_overview",
            "error_logs",
            "recent_changes",
        ],
        "instructions": [
            "查看结果分布时使用 get_business_overview，并保持与告警规则相同的业务拒绝排除口径。",
            "业务结果确认存在技术失败后，应优先查询同一窗口的错误日志与目标对象近期变更。",
            "如果错误日志明确指向 Redis 等 Kubernetes 依赖的连接关闭、拒绝或重置，应优先调用 get_pod_lifecycle 查询该依赖的 Pod 生命周期，再决定是否调查资源饱和。",
            "get_seckill_reliability 只用于补充影响程度，不得挤占错误日志和变更证据的优先级。",
            "不要对按 result 分组的多序列结果直接调用 get_metric_trend，也不要用两次独立查询代替业务概览。",
        ],
        "tool_argument_overrides": {
            "get_business_overview": {
                "namespace": "data-services",
                "window": "$resource_rate_window",
                "success_label": "success",
                "excluded_results": [
                    "activity_closed",
                    "user_not_found",
                    "duplicate_request",
                    "sold_out",
                    "duplicate_order",
                ],
            }
        },
        "recovery_gate": {
            "tool_name": "get_business_overview",
            "arguments": {
                "metric_name": "seckill_order_total",
                "namespace": "data-services",
                "window": "5m",
                "success_label": "success",
                "excluded_results": [
                    "activity_closed",
                    "user_not_found",
                    "duplicate_request",
                    "sold_out",
                    "duplicate_order",
                ],
            },
            "minimum_total_count_exclusive": 20,
            "minimum_success_count": 1,
        },
    },
    "GatewayCapacitySaturation": {
        "category": "service_capacity",
        "required_evidence": [
            "alert_rule",
            "metric_trend",
            "service_golden_signals",
            "business_overview",
            "deployment_status",
            "error_logs",
        ],
        "instructions": [
            "先确认告警窗口内处理中请求或并发持续堆积，同时响应延迟升高，不能只看单个瞬时点。",
            "查询 /api/seckill/order 的服务黄金信号，核对完成吞吐、错误率和 P95 延迟是否同步变化；请求进入速率由告警规则中的 started counter 证明。",
            "调用 get_business_overview 核对同一批真实下单是否进入 seckill_order_total；订单量必须大于零，不能用专用测试接口的流量代替业务影响证据。",
            "黄金信号确认持续堆积后，优先查询 biz-gateway Deployment 的期望、Ready 和 Available 副本数，再查询同一窗口错误日志；不要先用泛化资源工具猜测 Redis 或 MySQL。",
            "错误率为零且同窗口没有代码异常、超时或依赖错误时，可视为暂未观察到故障型证据；只有日志、拓扑或指标明确指向某个下游时才继续查询该依赖。",
            "代码异常、发布回归或明确的下游失败存在时不能用扩容替代根因处理。",
            "容量证据链已经成立、错误率为零且同窗口无错误日志时，不要主动查询历史镜像变更；只有告警窗口本身已出现发布线索时才核对发布。近期存在镜像发布本身不等于发布回归；如果异常只在流量超过两副本容量后出现、日志无代码错误且容量指标随流量堆积，不得仅凭时间相邻切换到 release_regression Skill。",
            "当持续堆积、P95 升高、真实流量、零错误、健康副本数和无错误日志已经形成证据链时，应立即激活 capacity_scaling Skill，不要继续做低区分度查询；申请只能从当前副本数增加一个副本。",
        ],
        "tool_argument_overrides": {
            "get_service_golden_signals": {
                "namespace": "data-services",
                "service_name": "biz-gateway-svc",
                "window": "$resource_rate_window",
                "path": "/api/seckill/order",
            },
            "get_business_overview": {
                "namespace": "data-services",
                "window": "$resource_rate_window",
                "success_label": "success",
                "excluded_results": [
                    "activity_closed",
                    "user_not_found",
                    "duplicate_request",
                    "sold_out",
                    "duplicate_order",
                ],
            },
            "get_deployment_status": {
                "namespace": "data-services",
                "deployment_name": "biz-gateway",
            },
        },
    },
    "PodContainerRestarted": {
        "category": "workload_lifecycle",
        "required_evidence": [
            "alert_rule",
            "pod_lifecycle",
            "previous_container_logs",
            "kubernetes_events",
            "business_impact",
        ],
        "instructions": [
            "本类告警首先调用 get_pod_lifecycle，确认具体容器的 restart_count、上一次退出 reason、exit_code 和退出时间。",
            "不要在取得 Pod 生命周期证据前优先查询当前 CPU 或内存；恢复后的资源快照不能解释过去的重启。",
            "last_state 为 OOMKilled 时，再查询告警窗口内存趋势和节点压力；reason=Completed 且 exit_code=0 时，不得描述为崩溃或 OOM。",
            "生命周期确认后，查询上一个容器在退出时间附近的日志和 Kubernetes Events，区分主动退出、探针失败、运行时异常和资源问题。",
            "业务影响与重启原因分开判断；短暂连接错误可以证明影响路径，但不能单独证明重启原因。",
        ],
        "tool_argument_overrides": {},
    },
}


def get_alert_analysis_profile(
    alert_name: str,
) -> dict[str, Any]:
    profile = ALERT_ANALYSIS_PROFILES.get(
        (alert_name or "").strip()
    )
    return deepcopy(profile) if profile else {}


def get_alert_recovery_gate(alert_name: str) -> dict[str, Any]:
    profile = get_alert_analysis_profile(alert_name)
    gate = profile.get("recovery_gate")
    return deepcopy(gate) if isinstance(gate, dict) else {}


def apply_alert_profile_arguments(
    alert_name: str,
    tool_name: str,
    arguments: dict[str, Any],
    *,
    resource_rate_window: str,
) -> dict[str, Any]:
    scoped = dict(arguments)
    profile = get_alert_analysis_profile(alert_name)
    overrides = (
        profile.get("tool_argument_overrides", {})
        .get(tool_name, {})
    )

    for key, value in overrides.items():
        if value == "$resource_rate_window":
            scoped[key] = resource_rate_window or "15m"
        else:
            scoped[key] = deepcopy(value)

    return scoped


def build_alert_profile_instructions(
    alert_name: str,
) -> str:
    profile = get_alert_analysis_profile(alert_name)
    if not profile:
        return ""

    required = profile.get("required_evidence", [])
    instructions = profile.get("instructions", [])
    lines = [
        f"当前告警类别：{profile.get('category', 'generic')}。",
    ]

    if required:
        lines.append(
            "本类告警优先形成这些证据："
            + "、".join(str(item) for item in required)
            + "。"
        )

    lines.extend(str(item) for item in instructions if item)
    return "".join(lines)
