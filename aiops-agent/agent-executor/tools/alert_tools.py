from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


ALERTMANAGER_BASE_URL = os.getenv(
    "ALERTMANAGER_BASE_URL",
    "http://alertmanager.monitoring.svc.cluster.local:9093",
).rstrip("/")

ALERTMANAGER_TIMEOUT = int(os.getenv("ALERTMANAGER_TIMEOUT", "15"))

PROMETHEUS_BASE_URL = os.getenv(
    "PROMETHEUS_BASE_URL",
    "http://prometheus.monitoring.svc.cluster.local:9090",
).rstrip("/")

PROMETHEUS_TIMEOUT = int(os.getenv("PROMETHEUS_TIMEOUT", "15"))


def _now_text() -> str:
    return datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S")


def _error_payload(message: str, **extra: Any) -> dict[str, Any]:
    payload = {"generated_at": _now_text(), "error": message}
    payload.update(extra)
    return payload


def _alertmanager_get(path: str) -> Any:
    url = f"{ALERTMANAGER_BASE_URL}{path}"
    request = Request(url, method="GET")

    try:
        with urlopen(request, timeout=ALERTMANAGER_TIMEOUT) as response:
            return json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="ignore")
        raise RuntimeError(f"alertmanager http error {exc.code}: {detail}") from exc
    except URLError as exc:
        raise RuntimeError(f"alertmanager connection error: {exc}") from exc


def _prometheus_get(path: str) -> dict[str, Any]:
    url = f"{PROMETHEUS_BASE_URL}{path}"
    request = Request(url, method="GET")

    try:
        with urlopen(request, timeout=PROMETHEUS_TIMEOUT) as response:
            body = json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="ignore")
        raise RuntimeError(f"prometheus http error {exc.code}: {detail}") from exc
    except URLError as exc:
        raise RuntimeError(f"prometheus connection error: {exc}") from exc

    if body.get("status") != "success":
        raise RuntimeError(f"prometheus returned non-success response: {body}")

    return body


def _normalize_alert(alert: dict[str, Any]) -> dict[str, Any]:
    labels = alert.get("labels", {})
    annotations = alert.get("annotations", {})
    status = alert.get("status", {})
    return {
        "alert_name": labels.get("alertname", ""),
        "severity": labels.get("severity", ""),
        "status": {
            "state": status.get("state", ""),
            "silenced_by": status.get("silencedBy", []),
            "inhibited_by": status.get("inhibitedBy", []),
        },
        "starts_at": alert.get("startsAt", ""),
        "ends_at": alert.get("endsAt", ""),
        "generator_url": alert.get("generatorURL", ""),
        "labels": labels,
        "annotations": annotations,
    }


def get_alerts(state: str = "firing") -> dict[str, Any]:
    try:
        alerts = _alertmanager_get("/api/v2/alerts")
    except RuntimeError as exc:
        return _error_payload(str(exc), state=state)

    requested_state = (state or "firing").strip().lower()
    normalized: list[dict[str, Any]] = []

    for item in alerts:
        status_block = item.get("status", {})
        is_active = status_block.get("state") == "active"
        is_silenced = bool(status_block.get("silencedBy"))
        is_inhibited = bool(status_block.get("inhibitedBy"))

        if requested_state == "firing" and not is_active:
            continue
        if requested_state == "silenced" and not is_silenced:
            continue
        if requested_state == "inhibited" and not is_inhibited:
            continue

        normalized.append(_normalize_alert(item))

    return {
        "generated_at": _now_text(),
        "alertmanager_base_url": ALERTMANAGER_BASE_URL,
        "state": requested_state,
        "count": len(normalized),
        "summary": f"当前共查询到 {len(normalized)} 条 {requested_state} 告警。",
        "alerts": normalized,
    }


def get_alert_detail(alert_name: str) -> dict[str, Any]:
    normalized_name = (alert_name or "").strip()
    if not normalized_name:
        return _error_payload("alert_name is required")

    try:
        alerts = _alertmanager_get("/api/v2/alerts")
    except RuntimeError as exc:
        return _error_payload(str(exc), alert_name=normalized_name)

    for item in alerts:
        labels = item.get("labels", {})
        if labels.get("alertname") != normalized_name:
            continue

        alert = _normalize_alert(item)
        summary = (
            f"告警 {normalized_name} 当前级别为 {alert.get('severity') or 'unknown'}，"
            f"开始时间 {alert.get('starts_at') or 'unknown'}。"
        )
        return {
            "generated_at": _now_text(),
            "alertmanager_base_url": ALERTMANAGER_BASE_URL,
            "summary": summary,
            **alert,
        }

    return _error_payload("alert not found", alert_name=normalized_name)


def get_prometheus_alert_rule(alert_name: str) -> dict[str, Any]:
    normalized_name = (alert_name or "").strip()
    if not normalized_name:
        return _error_payload("alert_name is required")

    try:
        body = _prometheus_get("/api/v1/rules?type=alert")
    except RuntimeError as exc:
        return _error_payload(str(exc), alert_name=normalized_name)

    matches: list[dict[str, Any]] = []
    groups = (body.get("data") or {}).get("groups") or []
    for group in groups:
        for rule in group.get("rules") or []:
            if rule.get("type") != "alerting" or rule.get("name") != normalized_name:
                continue

            matches.append(
                {
                    "alert_name": normalized_name,
                    "group_name": group.get("name", ""),
                    "rule_file": group.get("file", ""),
                    "group_interval_seconds": group.get("interval"),
                    "expression": rule.get("query", ""),
                    "for_seconds": rule.get("duration", 0),
                    "keep_firing_for_seconds": rule.get("keepFiringFor", 0),
                    "labels": rule.get("labels") or {},
                    "annotations": rule.get("annotations") or {},
                    "state": rule.get("state", ""),
                    "health": rule.get("health", ""),
                    "last_error": rule.get("lastError", ""),
                    "last_evaluation": rule.get("lastEvaluation", ""),
                    "evaluation_time_seconds": rule.get("evaluationTime"),
                    "active_alert_count": len(rule.get("alerts") or []),
                }
            )

    if not matches:
        return _error_payload(
            "alert rule not found",
            alert_name=normalized_name,
            prometheus_base_url=PROMETHEUS_BASE_URL,
        )

    primary = matches[0]
    summary = (
        f"告警 {normalized_name} 的规则表达式为 {primary['expression']}，"
        f"需要持续 {primary['for_seconds']} 秒后触发，"
        f"当前规则状态 {primary['state'] or 'unknown'}，"
        f"健康状态 {primary['health'] or 'unknown'}。"
    )
    if len(matches) > 1:
        summary += f" Prometheus 中共发现 {len(matches)} 条同名规则，请结合规则组确认。"

    return {
        "generated_at": _now_text(),
        "prometheus_base_url": PROMETHEUS_BASE_URL,
        "alert_name": normalized_name,
        "count": len(matches),
        "summary": summary,
        "rules": matches,
    }

ALERT_TOOLS: list[dict[str, Any]] = [
    {
        "name": "get_alerts",
        "label": "告警列表",
        "spec": {
            "type": "function",
            "function": {
                "name": "get_alerts",
                "description": "从 Alertmanager 查询告警列表。适合回答当前有哪些 firing、silenced、inhibited 告警。",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "state": {
                            "type": "string",
                            "description": "可选。告警状态，可传 firing、silenced、inhibited。默认 firing。",
                        },
                    },
                },
            },
        },
        "handler": get_alerts,
    },
    {
        "name": "get_alert_detail",
        "label": "告警详情",
        "spec": {
            "type": "function",
            "function": {
                "name": "get_alert_detail",
                "description": "查询指定告警的详细信息，包括级别、开始时间、labels、annotations 等。",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "alert_name": {
                            "type": "string",
                            "description": "必填。告警名称，即 alertname。",
                        },
                    },
                    "required": ["alert_name"],
                },
            },
        },
        "handler": get_alert_detail,
    },
    {
        "name": "get_prometheus_alert_rule",
        "label": "告警规则",
        "spec": {
            "type": "function",
            "function": {
                "name": "get_prometheus_alert_rule",
                "description": (
                    "从 Prometheus 查询指定告警的真实规则定义。"
                    "返回 PromQL 表达式、for 持续时间、规则状态、健康状态和所属规则组。"
                    "当需要确认告警阈值、触发条件或告警是否仍满足规则时调用。"
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "alert_name": {
                            "type": "string",
                            "description": "必填。Prometheus 告警规则名称，例如 NodeCPUHigh。",
                        },
                    },
                    "required": ["alert_name"],
                },
            },
        },
        "handler": get_prometheus_alert_rule,
    },
]
