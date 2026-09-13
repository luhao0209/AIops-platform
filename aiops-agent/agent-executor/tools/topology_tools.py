from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any

from kubernetes import client, config
from kubernetes.config.config_exception import ConfigException

DEFAULT_NAMESPACES = ["aiops", "data-services", "monitoring"]

_CONFIG_LOADED = False


def load_kube_config() -> None:
    global _CONFIG_LOADED
    if _CONFIG_LOADED:
        return

    try:
        config.load_incluster_config()
    except ConfigException:
        config.load_kube_config()

    _CONFIG_LOADED = True


def detect_node_role_hint(node_name: str, labels: dict[str, str]) -> str:
    lower_name = node_name.lower()

    if "worker-ai" in lower_name or "ai" in lower_name:
        return "AI 运维节点"
    if "worker-monitor" in lower_name or "monitor" in lower_name:
        return "监控节点"
    if "worker-biz" in lower_name or "biz" in lower_name:
        return "业务节点"
    if "master" in lower_name or labels.get("node-role.kubernetes.io/control-plane") is not None:
        return "控制平面节点"

    return "通用集群节点"


def detect_workload_role_hint(name: str, namespace: str) -> str:
    lower_name = name.lower()
    lower_ns = namespace.lower()

    if "agent-executor" in lower_name:
        return "AIOps 智能分析"
    if "aiops-agent" in lower_name:
        return "AIOps 智能运维"
    if "inspection-engine" in lower_name:
        return "巡检引擎"
    if "change-watcher" in lower_name:
        return "变更监听"
    if "sop-service" in lower_name:
        return "SOP 知识库"
    if "prometheus" in lower_name:
        return "指标采集与查询"
    if "grafana" in lower_name:
        return "可视化面板"
    if "loki" in lower_name:
        return "日志存储"
    if "promtail" in lower_name:
        return "日志采集"
    if "alertmanager" in lower_name:
        return "告警管理"
    if "mysql" in lower_name:
        return "数据库服务"
    if "redis" in lower_name:
        return "缓存服务"
    if "gateway" in lower_name:
        return "业务接入网关"
    if lower_ns == "monitoring":
        return "监控工作负载"
    if lower_ns == "data-services":
        return "业务工作负载"
    if lower_ns == "aiops":
        return "AIOps 工作负载"

    return "集群工作负载"


def get_node_addresses(addresses: list[Any]) -> tuple[str, str]:
    internal_ip = ""
    external_ip = ""

    for addr in addresses or []:
        if addr.type == "InternalIP" and not internal_ip:
            internal_ip = addr.address
        elif addr.type == "ExternalIP" and not external_ip:
            external_ip = addr.address

    return internal_ip, external_ip


def get_node_status(node: Any) -> str:
    for condition in node.status.conditions or []:
        if condition.type == "Ready":
            return "Ready" if condition.status == "True" else "NotReady"
    return "Unknown"


def extract_owner(owner_references: list[Any] | None) -> tuple[str, str]:
    if not owner_references:
        return "", ""

    owner = owner_references[0]
    return owner.kind or "", owner.name or ""


def get_app_name(pod: Any, owner_name: str) -> str:
    labels = pod.metadata.labels or {}
    return (
        labels.get("app")
        or labels.get("app.kubernetes.io/name")
        or owner_name
        or pod.metadata.name
    )


def selector_matches(selector: dict[str, str], labels: dict[str, str]) -> bool:
    if not selector:
        return False
    return all(labels.get(key) == value for key, value in selector.items())


def normalize_namespaces(target_namespace: str | None = None) -> list[str]:
    if target_namespace:
        return [target_namespace]
    return DEFAULT_NAMESPACES.copy()


def normalize_target_app(target_app: str | None) -> str:
    return (target_app or "").strip().lower()


def workload_matches_app(workload: dict[str, Any], target_app: str) -> bool:
    if not target_app:
        return True

    compare_fields = [
        workload.get("name", ""),
        workload.get("app", ""),
        workload.get("owner_name", ""),
        workload.get("role_hint", ""),
    ]
    return any(target_app in str(value).lower() for value in compare_fields)


def build_service_targets(
    services: list[dict[str, Any]],
    workloads: list[dict[str, Any]],
) -> None:
    for svc in services:
        namespace = svc["namespace"]
        selector = svc["selector"]
        target_pods: list[str] = []

        for workload in workloads:
            if workload["kind"] != "Pod":
                continue
            if workload["namespace"] != namespace:
                continue
            if selector_matches(selector, workload.get("labels", {})):
                target_pods.append(workload["name"])
                workload["service_names"].append(svc["name"])

        svc["target_pods"] = sorted(target_pods)


def filter_services_by_target_app(
    services: list[dict[str, Any]],
    target_app: str,
) -> list[dict[str, Any]]:
    if not target_app:
        return services

    filtered: list[dict[str, Any]] = []
    for svc in services:
        target_pods = svc.get("target_pods", [])
        if any(target_app in pod.lower() for pod in target_pods):
            filtered.append(svc)
            continue
        if target_app in svc["name"].lower():
            filtered.append(svc)

    return filtered


def build_relations(
    nodes: list[dict[str, Any]],
    workloads: list[dict[str, Any]],
    services: list[dict[str, Any]],
) -> list[dict[str, str]]:
    relations: list[dict[str, str]] = []
    node_names = {node["node_name"] for node in nodes}

    for workload in workloads:
        node_name = workload.get("node_name") or ""
        if node_name and node_name in node_names:
            relations.append(
                {
                    "from": f"node:{node_name}",
                    "to": f"pod:{workload['namespace']}/{workload['name']}",
                    "type": "runs_on",
                }
            )

        owner_kind = workload.get("owner_kind") or ""
        owner_name = workload.get("owner_name") or ""
        if owner_kind and owner_name:
            relations.append(
                {
                    "from": f"{owner_kind.lower()}:{workload['namespace']}/{owner_name}",
                    "to": f"pod:{workload['namespace']}/{workload['name']}",
                    "type": "owns",
                }
            )

        for service_name in workload.get("service_names", []):
            relations.append(
                {
                    "from": f"service:{workload['namespace']}/{service_name}",
                    "to": f"pod:{workload['namespace']}/{workload['name']}",
                    "type": "selects",
                }
            )

    return relations


def _collect_topology_data(
    target_namespace: str | None = None,
    target_app: str | None = None,
) -> dict[str, Any]:
    load_kube_config()

    core = client.CoreV1Api()
    apps = client.AppsV1Api()

    target_namespaces = normalize_namespaces(target_namespace)
    target_app_normalized = normalize_target_app(target_app)

    node_items = core.list_node().items
    nodes: list[dict[str, Any]] = []

    for node in node_items:
        node_name = node.metadata.name
        labels = node.metadata.labels or {}
        internal_ip, external_ip = get_node_addresses(node.status.addresses)

        nodes.append(
            {
                "node_name": node_name,
                "role_hint": detect_node_role_hint(node_name, labels),
                "status": get_node_status(node),
                "internal_ip": internal_ip,
                "external_ip": external_ip,
                "pod_count": 0,
            }
        )

    node_pod_count: dict[str, int] = defaultdict(int)
    workloads: list[dict[str, Any]] = []

    for namespace in target_namespaces:
        _ = apps.list_namespaced_deployment(namespace=namespace).items
        pods = core.list_namespaced_pod(namespace=namespace).items

        for pod in pods:
            owner_kind, owner_name = extract_owner(pod.metadata.owner_references)
            node_name = pod.spec.node_name or ""
            labels = pod.metadata.labels or {}
            app_name = get_app_name(pod, owner_name)

            workload = {
                "kind": "Pod",
                "name": pod.metadata.name,
                "namespace": namespace,
                "node_name": node_name,
                "status": pod.status.phase,
                "owner_kind": owner_kind,
                "owner_name": owner_name,
                "app": app_name,
                "service_names": [],
                "role_hint": detect_workload_role_hint(app_name, namespace),
                "labels": labels,
            }

            if not workload_matches_app(workload, target_app_normalized):
                continue

            if node_name:
                node_pod_count[node_name] += 1

            workloads.append(workload)

    for node in nodes:
        node["pod_count"] = node_pod_count.get(node["node_name"], 0)

    active_node_names = {item["node_name"] for item in workloads if item["node_name"]}
    if target_app_normalized:
        nodes = [node for node in nodes if node["node_name"] in active_node_names]

    services: list[dict[str, Any]] = []
    for namespace in target_namespaces:
        svc_items = core.list_namespaced_service(namespace=namespace).items
        for svc in svc_items:
            selector = svc.spec.selector or {}
            ports = []
            for port in svc.spec.ports or []:
                target_port = getattr(port, "target_port", "")
                node_port = getattr(port, "node_port", None)
                if node_port:
                    ports.append(f"{port.port}:{node_port}/TCP")
                elif target_port:
                    ports.append(f"{port.port}->{target_port}/TCP")
                else:
                    ports.append(f"{port.port}/TCP")

            services.append(
                {
                    "name": svc.metadata.name,
                    "namespace": namespace,
                    "type": svc.spec.type,
                    "cluster_ip": svc.spec.cluster_ip or "",
                    "ports": ports,
                    "selector": selector,
                    "target_pods": [],
                }
            )

    build_service_targets(services, workloads)
    services = filter_services_by_target_app(services, target_app_normalized)
    relations = build_relations(nodes, workloads, services)

    return {
        "generated_at": datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S"),
        "cluster": {
            "name": "aiops-demo",
            "node_count": len(nodes),
            "namespace_count": len(target_namespaces),
            "target_namespace": target_namespace or "",
            "target_app": target_app or "",
        },
        "nodes": nodes,
        "workloads": workloads,
        "services": services,
        "relations": relations,
    }


def get_cluster_topology(
    target_namespace: str | None = None,
    target_app: str | None = None,
) -> dict[str, Any]:
    return _collect_topology_data(
        target_namespace=target_namespace,
        target_app=target_app,
    )


def get_cluster_topology_summary(
    target_namespace: str | None = None,
    target_app: str | None = None,
) -> dict[str, Any]:
    data = _collect_topology_data(
        target_namespace=target_namespace,
        target_app=target_app,
    )

    nodes = data["nodes"]
    workloads = data["workloads"]
    services = data["services"]

    namespace_pod_counter = Counter(item["namespace"] for item in workloads)
    namespace_service_counter = Counter(item["namespace"] for item in services)
    node_role_counter = Counter(item["role_hint"] for item in workloads)
    node_workload_counter = defaultdict(list)

    for workload in workloads:
        node_workload_counter[workload["node_name"]].append(workload["app"])

    node_summary = [
        f"{node['node_name']}: {node['role_hint']}，状态 {node['status']}，Pod {node['pod_count']}"
        for node in nodes
    ]

    namespace_summary = []
    namespace_order = data["cluster"].get("target_namespace")
    namespaces = [namespace_order] if namespace_order else DEFAULT_NAMESPACES
    for namespace in namespaces:
        namespace_summary.append(
            f"{namespace}: Pod {namespace_pod_counter.get(namespace, 0)}，Service {namespace_service_counter.get(namespace, 0)}"
        )

    service_summary = []
    for svc in services[:10]:
        targets = ", ".join(svc.get("target_pods", [])[:3]) or "无匹配 Pod"
        service_summary.append(f"{svc['namespace']}/{svc['name']} -> {targets}")

    highlights: list[str] = []
    if node_role_counter:
        main_role, main_count = node_role_counter.most_common(1)[0]
        highlights.append(f"当前工作负载主要集中在：{main_role}（{main_count} 个 Pod）")

    for node_name, apps in node_workload_counter.items():
        if not node_name or not apps:
            continue
        top_apps = Counter(apps).most_common(2)
        app_desc = "、".join(name for name, _ in top_apps)
        highlights.append(f"{node_name} 重点承载：{app_desc}")
        if len(highlights) >= 4:
            break

    if target_app:
        highlights.insert(0, f"当前结果已经按应用过滤：{target_app}")
    if target_namespace:
        highlights.insert(0, f"当前结果已经按命名空间过滤：{target_namespace}")

    return {
        "generated_at": data["generated_at"],
        "cluster": data["cluster"],
        "node_summary": node_summary,
        "namespace_summary": namespace_summary,
        "service_summary": service_summary,
        "highlights": highlights,
    }

TOPOLOGY_TOOLS: list[dict[str, Any]] = [
    {
        "name": "get_cluster_topology_summary",
        "label": "拓扑摘要",
        "spec": {
            "type": "function",
            "function": {
                "name": "get_cluster_topology_summary",
                "description": (
                    "获取 Kubernetes 集群拓扑摘要。适合回答命名空间里有哪些组件、"
                    "节点上跑了哪些服务、当前集群整体结构如何这类问题。"
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target_namespace": {
                            "type": "string",
                            "description": "可选。指定要聚焦的命名空间，如 aiops、data-services、monitoring。",
                        },
                        "target_app": {
                            "type": "string",
                            "description": "可选。指定要聚焦的应用或组件名，如 aiops-agent、agent-executor。",
                        },
                    },
                },
            },
        },
        "handler": get_cluster_topology_summary,
    },
    {
        "name": "get_cluster_topology",
        "label": "完整拓扑",
        "spec": {
            "type": "function",
            "function": {
                "name": "get_cluster_topology",
                "description": (
                    "获取 Kubernetes 集群当前的详细拓扑快照。"
                    "包含节点、Pod、Service 以及它们之间的关系。"
                    "只在用户明确需要更细拓扑详情时调用。"
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target_namespace": {
                            "type": "string",
                            "description": "可选。指定要查询的命名空间。",
                        },
                        "target_app": {
                            "type": "string",
                            "description": "可选。指定要聚焦的应用或组件名。",
                        },
                    },
                },
            },
        },
        "handler": get_cluster_topology,
    },
]
