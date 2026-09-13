from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from kubernetes import client, config
from kubernetes.client.exceptions import ApiException
from kubernetes.config.config_exception import ConfigException


_CONFIG_LOADED = False


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _now_text() -> str:
    return _now_utc().astimezone().strftime("%Y-%m-%d %H:%M:%S")


def _error_payload(message: str, **extra: Any) -> dict[str, Any]:
    payload = {"generated_at": _now_text(), "error": message}
    payload.update(extra)
    return payload


def _load_kube_config() -> None:
    global _CONFIG_LOADED
    if _CONFIG_LOADED:
        return

    try:
        config.load_incluster_config()
    except ConfigException:
        config.load_kube_config()

    _CONFIG_LOADED = True


def _as_utc(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
    return None


def _event_times(event: Any) -> tuple[datetime | None, datetime | None]:
    first_seen = _as_utc(getattr(event, "first_timestamp", None))
    created_at = _as_utc(getattr(event.metadata, "creation_timestamp", None))
    event_time = _as_utc(getattr(event, "event_time", None))
    last_seen = _as_utc(getattr(event, "last_timestamp", None))

    series = getattr(event, "series", None)
    if series is not None:
        last_seen = _as_utc(getattr(series, "last_observed_time", None)) or last_seen

    first_seen = first_seen or created_at or event_time or last_seen
    last_seen = last_seen or event_time or created_at or first_seen
    return first_seen, last_seen


def _iso(value: datetime | None) -> str:
    if value is None:
        return ""
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def get_kubernetes_events(
    namespace: str | None = None,
    involved_object_name: str | None = None,
    involved_object_kind: str | None = None,
    reason: str | None = None,
    event_type: str | None = None,
    since_minutes: int = 30,
    limit: int = 30,
) -> dict[str, Any]:
    namespace_value = (namespace or "").strip()
    object_name = (involved_object_name or "").strip()
    object_kind = (involved_object_kind or "").strip()
    reason_value = (reason or "").strip().lower()
    event_type_value = (event_type or "").strip().lower()

    if event_type_value and event_type_value not in {"normal", "warning"}:
        return _error_payload(
            "unsupported event_type",
            requested_event_type=event_type,
            valid_event_types=["Normal", "Warning"],
        )

    normalized_since = max(1, min(int(since_minutes or 30), 1440))
    normalized_limit = max(1, min(int(limit or 30), 100))
    cutoff = _now_utc() - timedelta(minutes=normalized_since)

    try:
        _load_kube_config()
        api = client.CoreV1Api()
        if namespace_value:
            response = api.list_namespaced_event(namespace=namespace_value, watch=False)
        else:
            response = api.list_event_for_all_namespaces(watch=False)
    except (ApiException, ConfigException) as exc:
        return _error_payload(
            f"kubernetes event query failed: {exc}",
            namespace=namespace_value,
            involved_object_name=object_name,
            involved_object_kind=object_kind,
        )

    items: list[dict[str, Any]] = []
    for event in response.items or []:
        involved = event.involved_object
        current_name = str(getattr(involved, "name", "") or "")
        current_kind = str(getattr(involved, "kind", "") or "")
        current_reason = str(getattr(event, "reason", "") or "")
        current_type = str(getattr(event, "type", "") or "")

        if object_name and current_name != object_name:
            continue
        if object_kind and current_kind.lower() != object_kind.lower():
            continue
        if reason_value and reason_value not in current_reason.lower():
            continue
        if event_type_value and current_type.lower() != event_type_value:
            continue

        first_seen, last_seen = _event_times(event)
        if last_seen is not None and last_seen < cutoff:
            continue

        series = getattr(event, "series", None)
        count = getattr(event, "count", None)
        if series is not None and getattr(series, "count", None) is not None:
            count = series.count

        items.append(
            {
                "namespace": str(getattr(involved, "namespace", "") or namespace_value),
                "object_kind": current_kind,
                "object_name": current_name,
                "reason": current_reason,
                "event_type": current_type,
                "message": str(getattr(event, "message", "") or ""),
                "source_component": str(
                    getattr(getattr(event, "source", None), "component", "") or ""
                ),
                "count": int(count or 1),
                "first_seen_at": _iso(first_seen),
                "last_seen_at": _iso(last_seen),
                "last_seen_sort": last_seen or datetime.min.replace(tzinfo=timezone.utc),
            }
        )

    items.sort(key=lambda item: item["last_seen_sort"], reverse=True)
    items = items[:normalized_limit]
    for item in items:
        item.pop("last_seen_sort", None)

    warnings = sum(1 for item in items if item["event_type"].lower() == "warning")
    scope = object_name or namespace_value or "cluster"
    summary = (
        f"最近 {normalized_since} 分钟在 {scope} 范围内查询到 "
        f"{len(items)} 条 Kubernetes Event，其中 Warning {warnings} 条。"
    )

    return {
        "generated_at": _now_text(),
        "namespace": namespace_value,
        "involved_object_name": object_name,
        "involved_object_kind": object_kind,
        "reason_filter": reason_value,
        "event_type_filter": event_type_value,
        "since_minutes": normalized_since,
        "count": len(items),
        "warning_count": warnings,
        "summary": summary,
        "events": items,
    }


KUBERNETES_EVENT_TOOLS: list[dict[str, Any]] = [
    {
        "name": "get_kubernetes_events",
        "label": "Kubernetes Events",
        "spec": {
            "type": "function",
            "function": {
                "name": "get_kubernetes_events",
                "description": (
                    "查询 Kubernetes 原生 Event，返回调度、探针、OOM、镜像拉取、"
                    "节点和工作负载异常等事件。可按命名空间、对象名称、对象类型、"
                    "reason 和 Warning/Normal 过滤。它不是 Incident 生命周期查询工具。"
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "namespace": {
                            "type": "string",
                            "description": "可选。命名空间；查询 Node 事件时通常不传。",
                        },
                        "involved_object_name": {
                            "type": "string",
                            "description": "可选。事件关联对象名，例如 worker-biz 或某个 Pod 名。",
                        },
                        "involved_object_kind": {
                            "type": "string",
                            "description": "可选。对象类型，例如 Node、Pod、Deployment。",
                        },
                        "reason": {
                            "type": "string",
                            "description": "可选。reason 关键词，例如 FailedScheduling、Unhealthy、OOMKilling。",
                        },
                        "event_type": {
                            "type": "string",
                            "enum": ["Normal", "Warning"],
                            "description": "可选。只查询 Normal 或 Warning。",
                        },
                        "since_minutes": {
                            "type": "integer",
                            "description": "可选。向前查询多少分钟，默认 30，最大 1440。",
                        },
                        "limit": {
                            "type": "integer",
                            "description": "可选。最多返回多少条，默认 30，最大 100。",
                        },
                    },
                },
            },
        },
        "handler": get_kubernetes_events,
    }
]
