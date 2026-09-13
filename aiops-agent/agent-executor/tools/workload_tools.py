from __future__ import annotations

import re
from typing import Any


def _apps_api() -> Any:
    from kubernetes import client, config
    from kubernetes.config.config_exception import ConfigException

    try:
        config.load_incluster_config()
    except ConfigException:
        config.load_kube_config()
    return client.AppsV1Api()


def _core_api() -> Any:
    from kubernetes import client, config
    from kubernetes.config.config_exception import ConfigException

    try:
        config.load_incluster_config()
    except ConfigException:
        config.load_kube_config()
    return client.CoreV1Api()


def _time_text(value: Any) -> str:
    if value is None:
        return ""
    isoformat = getattr(value, "isoformat", None)
    return str(isoformat() if callable(isoformat) else value)


def _container_state(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    running = getattr(value, "running", None)
    if running is not None:
        return {
            "state": "running",
            "started_at": _time_text(getattr(running, "started_at", None)),
        }
    waiting = getattr(value, "waiting", None)
    if waiting is not None:
        return {
            "state": "waiting",
            "reason": str(getattr(waiting, "reason", "") or ""),
            "message": str(getattr(waiting, "message", "") or "")[:500],
        }
    terminated = getattr(value, "terminated", None)
    if terminated is not None:
        return {
            "state": "terminated",
            "reason": str(getattr(terminated, "reason", "") or ""),
            "exit_code": int(getattr(terminated, "exit_code", 0) or 0),
            "signal": int(getattr(terminated, "signal", 0) or 0),
            "started_at": _time_text(getattr(terminated, "started_at", None)),
            "finished_at": _time_text(getattr(terminated, "finished_at", None)),
            "message": str(getattr(terminated, "message", "") or "")[:500],
        }
    return {}


def _pod_lifecycle_item(pod: Any) -> dict[str, Any]:
    metadata = pod.metadata
    spec = pod.spec
    status = pod.status
    owner_refs = list(getattr(metadata, "owner_references", None) or [])
    owner = owner_refs[0] if owner_refs else None
    containers = []
    for item in list(getattr(status, "container_statuses", None) or []):
        containers.append(
            {
                "name": str(getattr(item, "name", "") or ""),
                "image": str(getattr(item, "image", "") or ""),
                "image_id": str(getattr(item, "image_id", "") or ""),
                "container_id": str(getattr(item, "container_id", "") or ""),
                "ready": bool(getattr(item, "ready", False)),
                "restart_count": int(getattr(item, "restart_count", 0) or 0),
                "current_state": _container_state(getattr(item, "state", None)),
                "last_state": _container_state(getattr(item, "last_state", None)),
            }
        )
    return {
        "pod_name": str(getattr(metadata, "name", "") or ""),
        "namespace": str(getattr(metadata, "namespace", "") or ""),
        "node_name": str(getattr(spec, "node_name", "") or ""),
        "phase": str(getattr(status, "phase", "") or ""),
        "pod_ip": str(getattr(status, "pod_ip", "") or ""),
        "start_time": _time_text(getattr(status, "start_time", None)),
        "deletion_timestamp": _time_text(
            getattr(metadata, "deletion_timestamp", None)
        ),
        "owner_kind": str(getattr(owner, "kind", "") or ""),
        "owner_name": str(getattr(owner, "name", "") or ""),
        "containers": containers,
    }


def get_pod_lifecycle(
    namespace: str,
    pod_name: str | None = None,
    app_name: str | None = None,
) -> dict[str, Any]:
    """Read container restart and last-termination evidence for a Pod or app."""
    normalized_namespace = (namespace or "").strip()
    normalized_pod = (pod_name or "").strip()
    normalized_app = (app_name or "").strip()
    if not normalized_namespace:
        return {"error": "namespace is required"}
    if not normalized_pod and not normalized_app:
        return {"error": "pod_name or app_name is required"}
    if normalized_app and not re.fullmatch(r"[A-Za-z0-9_.-]+", normalized_app):
        return {"error": "app_name is not a valid Kubernetes label value"}

    core = _core_api()
    try:
        if normalized_pod:
            pods = [core.read_namespaced_pod(normalized_pod, normalized_namespace)]
        else:
            response = core.list_namespaced_pod(
                normalized_namespace,
                label_selector=f"app={normalized_app}",
                watch=False,
            )
            pods = list(getattr(response, "items", None) or [])
    except Exception as exc:
        status = int(getattr(exc, "status", 0) or 0)
        return {
            "error": f"kubernetes pod read failed: {status or 'unknown'}",
            "namespace": normalized_namespace,
            "pod_name": normalized_pod,
            "app_name": normalized_app,
        }

    items = sorted(
        (_pod_lifecycle_item(pod) for pod in pods),
        key=lambda item: item["pod_name"],
    )[:10]
    return {
        "namespace": normalized_namespace,
        "pod_name": normalized_pod,
        "app_name": normalized_app,
        "total": len(items),
        "pods": items,
    }


def get_deployment_status(namespace: str, deployment_name: str) -> dict[str, Any]:
    """Read the current rollout state and container images of one Deployment."""
    normalized_namespace = (namespace or "").strip()
    normalized_name = (deployment_name or "").strip()
    if not normalized_namespace or not normalized_name:
        return {"error": "namespace and deployment_name are required"}

    try:
        deployment = _apps_api().read_namespaced_deployment(
            normalized_name,
            normalized_namespace,
        )
    except Exception as exc:
        status = int(getattr(exc, "status", 0) or 0)
        return {
            "error": f"kubernetes deployment read failed: {status or 'unknown'}",
            "namespace": normalized_namespace,
            "deployment_name": normalized_name,
        }

    spec = deployment.spec
    status = deployment.status
    containers = [
        {"name": str(item.name or ""), "image": str(item.image or "")}
        for item in list(spec.template.spec.containers or [])
    ]
    conditions = [
        {
            "type": str(item.type or ""),
            "status": str(item.status or ""),
            "reason": str(item.reason or ""),
            "message": str(item.message or "")[:500],
        }
        for item in list(status.conditions or [])
    ]
    desired = int(spec.replicas or 0)
    updated = int(status.updated_replicas or 0)
    ready = int(status.ready_replicas or 0)
    available = int(status.available_replicas or 0)
    observed_generation = int(status.observed_generation or 0)
    generation = int(deployment.metadata.generation or 0)
    rollout_complete = (
        observed_generation >= generation
        and updated == desired
        and ready == desired
        and available == desired
        and int(status.unavailable_replicas or 0) == 0
    )
    match_labels = dict(getattr(spec.selector, "match_labels", None) or {})
    label_selector = ",".join(
        f"{key}={value}" for key, value in sorted(match_labels.items())
    )
    scheduled_nodes: list[str] = []
    pod_lookup_error = ""
    if label_selector:
        try:
            pod_response = _core_api().list_namespaced_pod(
                normalized_namespace,
                label_selector=label_selector,
                watch=False,
            )
            scheduled_nodes = sorted(
                {
                    str(getattr(getattr(pod, "spec", None), "node_name", "") or "")
                    for pod in list(getattr(pod_response, "items", None) or [])
                    if getattr(getattr(pod, "metadata", None), "deletion_timestamp", None)
                    is None
                    and str(
                        getattr(getattr(pod, "status", None), "phase", "") or ""
                    )
                    in {"Pending", "Running"}
                    and str(
                        getattr(getattr(pod, "spec", None), "node_name", "") or ""
                    )
                }
            )
        except Exception as exc:
            status_code = int(getattr(exc, "status", 0) or 0)
            pod_lookup_error = (
                f"kubernetes deployment pod read failed: {status_code or 'unknown'}"
            )
    return {
        "namespace": normalized_namespace,
        "deployment_name": normalized_name,
        "generation": generation,
        "observed_generation": observed_generation,
        "desired_replicas": desired,
        "updated_replicas": updated,
        "ready_replicas": ready,
        "available_replicas": available,
        "unavailable_replicas": int(status.unavailable_replicas or 0),
        "rollout_complete": rollout_complete,
        "containers": containers,
        "conditions": conditions,
        "scheduled_nodes": scheduled_nodes,
        "node_selector": dict(
            getattr(spec.template.spec, "node_selector", None) or {}
        ),
        "pod_lookup_error": pod_lookup_error,
    }


WORKLOAD_TOOLS: list[dict[str, Any]] = [
    {
        "name": "get_deployment_status",
        "label": "Deployment 状态",
        "spec": {
            "type": "function",
            "function": {
                "name": "get_deployment_status",
                "description": (
                    "读取一个 Kubernetes Deployment 当前镜像、期望副本、Ready 副本和滚动更新状态。"
                    "适合在发版调查和审批动作执行后核对版本是否切换、工作负载是否就绪。"
                ),
                "parameters": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "namespace": {"type": "string"},
                        "deployment_name": {"type": "string"},
                    },
                    "required": ["namespace", "deployment_name"],
                },
            },
        },
        "handler": get_deployment_status,
    },
    {
        "name": "get_pod_lifecycle",
        "label": "Pod 生命周期",
        "spec": {
            "type": "function",
            "function": {
                "name": "get_pod_lifecycle",
                "description": (
                    "读取 Pod 容器当前状态、重启次数以及上一次退出的 reason、"
                    "exit_code 和时间。适合调查容器重启、OOMKilled、CrashLoopBackOff、"
                    "主动退出和短暂依赖中断；当前资源使用率不能替代该生命周期证据。"
                ),
                "parameters": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "namespace": {"type": "string"},
                        "pod_name": {
                            "type": "string",
                            "description": "可选。精确 Pod 名称。",
                        },
                        "app_name": {
                            "type": "string",
                            "description": "可选。按 app 标签查询一组 Pod。",
                        },
                    },
                    "required": ["namespace"],
                },
            },
        },
        "handler": get_pod_lifecycle,
    },
]
