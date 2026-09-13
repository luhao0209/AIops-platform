from __future__ import annotations

from typing import Any

from memory import IncidentMemoryStore


INCIDENT_STORE = IncidentMemoryStore()


def _serialize(model: Any) -> dict[str, Any]:
    return model.model_dump(mode="json")


def list_incidents(
    status: str = "",
    alert_name: str = "",
    fingerprint: str = "",
    limit: int = 20,
) -> dict[str, Any]:
    normalized_status = (status or "").strip().lower()

    if normalized_status in {"", "all"}:
        status_value = None
    elif normalized_status in {"firing", "resolved"}:
        status_value = normalized_status
    else:
        return {
            "error": "status must be firing, resolved or all",
            "summary": "Incident 状态参数不正确。",
        }

    incidents = INCIDENT_STORE.list_incidents(
        status=status_value,
        alert_name=(alert_name or "").strip() or None,
        fingerprint=(fingerprint or "").strip() or None,
        limit=max(1, min(int(limit), 100)),
    )

    items = []
    for item in incidents:
        payload = _serialize(item)
        items.append(
            {
                "incident_id": payload["incident_id"],
                "alert_name": payload["alert_name"],
                "severity": payload["severity"],
                "status": payload["status"],
                "namespace": payload["namespace"],
                "target": payload["target"],
                "started_at": payload["started_at"],
                "last_seen_at": payload["last_seen_at"],
                "resolved_at": payload["resolved_at"],
                "notification_count": payload["notification_count"],
                "occurrence_index": payload["occurrence_index"],
            }
        )

    return {
        "total": len(items),
        "status_filter": normalized_status or "all",
        "summary": f"查询到 {len(items)} 条 Incident 记录。",
        "incidents": items,
    }


def get_incident_detail(incident_id: str) -> dict[str, Any]:
    normalized_id = (incident_id or "").strip()
    if not normalized_id:
        return {
            "error": "incident_id is required",
            "summary": "缺少 Incident ID。",
        }

    incident = INCIDENT_STORE.get(normalized_id)
    if incident is None:
        return {
            "error": "incident not found",
            "incident_id": normalized_id,
            "summary": f"未找到 Incident {normalized_id}。",
        }

    occurrence_count = INCIDENT_STORE.count_occurrences(
        incident.fingerprint
    )

    return {
        "summary": (
            f"Incident {incident.incident_id} 当前状态为 "
            f"{incident.status}，对象为 "
            f"{incident.namespace}/{incident.target}。"
        ),
        "incident": _serialize(incident),
        "historical_occurrence_count": occurrence_count,
    }


def get_incident_events(
    incident_id: str,
    limit: int = 100,
) -> dict[str, Any]:
    normalized_id = (incident_id or "").strip()
    if not normalized_id:
        return {
            "error": "incident_id is required",
            "summary": "缺少 Incident ID。",
        }

    incident = INCIDENT_STORE.get(normalized_id)
    if incident is None:
        return {
            "error": "incident not found",
            "incident_id": normalized_id,
            "summary": f"未找到 Incident {normalized_id}。",
        }

    events = INCIDENT_STORE.list_events(
        normalized_id,
        limit=max(1, min(int(limit), 500)),
    )

    return {
        "incident_id": normalized_id,
        "total": len(events),
        "summary": (
            f"Incident {normalized_id} 共查询到 "
            f"{len(events)} 条生命周期事件。"
        ),
        "events": [_serialize(event) for event in events],
    }


INCIDENT_TOOLS: list[dict[str, Any]] = [
    {
        "name": "list_incidents",
        "label": "Incident 列表",
        "spec": {
            "type": "function",
            "function": {
                "name": "list_incidents",
                "description": (
                    "查询已经持久化的 Incident 记录。"
                    "适合查看当前 firing Incident、历史已恢复 Incident，"
                    "以及同类告警过去是否发生过。"
                    "它不同于 get_alerts：get_alerts 是 Alertmanager 当前快照，"
                    "本工具查询的是本系统保存的告警生命周期。"
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "status": {
                            "type": "string",
                            "enum": ["all", "firing", "resolved"],
                            "description": "默认 all。",
                        },
                        "alert_name": {
                            "type": "string",
                            "description": "可选，按 alertname 精确过滤。",
                        },
                        "fingerprint": {
                            "type": "string",
                            "description": "可选，按 fingerprint 精确过滤。",
                        },
                        "limit": {
                            "type": "integer",
                            "minimum": 1,
                            "maximum": 100,
                            "description": "默认返回 20 条。",
                        },
                    },
                },
            },
        },
        "handler": list_incidents,
    },
    {
        "name": "get_incident_detail",
        "label": "Incident 详情",
        "spec": {
            "type": "function",
            "function": {
                "name": "get_incident_detail",
                "description": (
                    "查询单条 Incident 的完整事实，包括 labels、annotations、"
                    "恢复时间和历史发生次数。"
                    "适合在 list_incidents 选定具体 Incident 后深入查看。"
                    "本工具只读，不执行自动归因或处置。"
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "incident_id": {
                            "type": "string",
                            "description": "必填。Incident ID。",
                        },
                    },
                    "required": ["incident_id"],
                },
            },
        },
        "handler": get_incident_detail,
    },
    {
        "name": "get_incident_events",
        "label": "Incident 生命周期事件",
        "spec": {
            "type": "function",
            "function": {
                "name": "get_incident_events",
                "description": (
                    "查询指定 Incident 的生命周期事件时间线，"
                    "例如创建、firing 通知、resolved 通知。"
                    "本工具只读，不执行自动归因或处置。"
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "incident_id": {
                            "type": "string",
                            "description": "必填。Incident ID。",
                        },
                        "limit": {
                            "type": "integer",
                            "minimum": 1,
                            "maximum": 500,
                            "description": "默认返回 100 条。",
                        },
                    },
                    "required": ["incident_id"],
                },
            },
        },
        "handler": get_incident_events,
    },
]
