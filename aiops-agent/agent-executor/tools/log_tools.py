from __future__ import annotations

import json
import os
import re
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

from kubernetes import client, config
from kubernetes.config.config_exception import ConfigException


LOKI_BASE_URL = os.getenv(
    "LOKI_BASE_URL",
    "http://loki.monitoring.svc.cluster.local:3100",
).rstrip("/")
LOKI_TIMEOUT = int(os.getenv("LOKI_TIMEOUT", "15"))
DEFAULT_SINCE_MINUTES = 15
MAX_LIMIT = 200

_KUBE_CONFIG_LOADED = False


def load_kube_config() -> None:
    global _KUBE_CONFIG_LOADED
    if _KUBE_CONFIG_LOADED:
        return

    try:
        config.load_incluster_config()
    except ConfigException:
        config.load_kube_config()

    _KUBE_CONFIG_LOADED = True


def _now_text() -> str:
    return datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S")


def _error_payload(message: str, **extra: Any) -> dict[str, Any]:
    payload = {"generated_at": _now_text(), "error": message}
    payload.update(extra)
    return payload


def _escape_loki_value(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _build_selector(filters: dict[str, str]) -> str:
    parts = [
        f'{key}="{_escape_loki_value(value)}"'
        for key, value in filters.items()
        if value
    ]
    return "{" + ",".join(parts) + "}"


def _build_pipeline(keywords: str, level: str) -> list[str]:
    stages: list[str] = []

    if keywords:
        for token in re.split(r"\s+", keywords.strip()):
            if token:
                stages.append(f'|= "{_escape_loki_value(token)}"')

    level_normalized = (level or "").strip().lower()
    if level_normalized == "error":
        stages.append(r'|~ "(?i)(error|exception|traceback|panic|fatal|failed)"')
    elif level_normalized == "warn":
        stages.append(r'|~ "(?i)(warn|warning)"')
    elif level_normalized == "info":
        stages.append(r'|~ "(?i)(info|started|running|ready)"')

    return stages


def _to_loki_ns(value: datetime) -> int:
    return int(value.timestamp() * 1_000_000_000)


def _parse_query_time(value: str, field_name: str) -> datetime:
    text = (value or "").strip()
    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ValueError(
            f"{field_name} must be a valid ISO 8601 datetime"
        ) from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{field_name} must include an explicit timezone")
    return parsed.astimezone(timezone.utc)


def _loki_get(path: str) -> dict[str, Any]:
    request = Request(f"{LOKI_BASE_URL}{path}", method="GET")

    try:
        with urlopen(request, timeout=LOKI_TIMEOUT) as response:
            body = json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="ignore")
        raise RuntimeError(f"loki http error {exc.code}: {detail}") from exc
    except URLError as exc:
        raise RuntimeError(f"loki connection error: {exc}") from exc

    if body.get("status") != "success":
        raise RuntimeError(f"loki returned non-success response: {body}")

    return body


def _normalize_log_line(line: str) -> str:
    text = (line or "").strip()
    if not text:
        return ""

    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        parsed = None

    if isinstance(parsed, dict):
        for key in ("message", "msg", "log", "error"):
            value = parsed.get(key)
            if isinstance(value, str) and value.strip():
                text = value.strip()
                break

    return re.sub(r"\s+", " ", text).strip()


def _extract_pattern(line: str) -> str:
    text = _normalize_log_line(line)
    lowered = text.lower()

    known_patterns = [
        "duplicate_order",
        "timeout",
        "connection refused",
        "permission denied",
        "traceback",
        "exception",
        "panic",
        "fatal",
        "oomkilled",
        "crashloopbackoff",
        "not ready",
        "failed",
        "error",
    ]
    for item in known_patterns:
        if item in lowered:
            return item

    return text[:80] if text else "empty_line"


def _format_loki_timestamp(value: str) -> str:
    try:
        ts = int(value) / 1_000_000_000
        return datetime.fromtimestamp(ts, tz=timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S")
    except (TypeError, ValueError, OSError):
        return value


def _flatten_streams(streams: list[dict[str, Any]], max_lines: int) -> list[dict[str, Any]]:
    flattened: list[dict[str, Any]] = []

    for stream_item in streams:
        labels = stream_item.get("stream", {})
        values = stream_item.get("values", [])
        for raw in values:
            if not isinstance(raw, list) or len(raw) < 2:
                continue
            flattened.append(
                {
                    "timestamp_ns": str(raw[0]),
                    "timestamp": _format_loki_timestamp(str(raw[0])),
                    "labels": labels,
                    "line": raw[1],
                    "normalized_line": _normalize_log_line(str(raw[1])),
                }
            )

    flattened.sort(key=lambda item: item.get("timestamp_ns", ""), reverse=True)
    return flattened[:max_lines]


def _resolve_service_to_app(namespace: str, service_name: str) -> str:
    if not namespace or not service_name:
        return ""

    try:
        load_kube_config()
        core = client.CoreV1Api()
        service = core.read_namespaced_service(service_name, namespace)
    except Exception:
        return ""

    selector = service.spec.selector or {}
    return selector.get("app") or selector.get("app.kubernetes.io/name") or ""


def _query_scope_summary(filters: dict[str, str], since_minutes: int) -> str:
    parts = [f"最近 {since_minutes} 分钟"]
    if filters.get("namespace"):
        parts.append(f"命名空间 {filters['namespace']}")
    if filters.get("app"):
        parts.append(f"应用 {filters['app']}")
    if filters.get("pod"):
        parts.append(f"Pod {filters['pod']}")
    if filters.get("container"):
        parts.append(f"容器 {filters['container']}")
    if filters.get("node"):
        parts.append(f"节点 {filters['node']}")
    return "，".join(parts)


def search_logs(
    namespace: str | None = None,
    app_name: str | None = None,
    service_name: str | None = None,
    pod_name: str | None = None,
    container_name: str | None = None,
    node_name: str | None = None,
    keywords: str | None = None,
    level: str | None = None,
    since_minutes: int = DEFAULT_SINCE_MINUTES,
    limit: int = 20,
    start_at: str | None = None,
    end_at: str | None = None,
) -> dict[str, Any]:
    normalized_since = max(1, int(since_minutes or DEFAULT_SINCE_MINUTES))
    normalized_limit = max(1, min(int(limit or 20), MAX_LIMIT))

    namespace_value = (namespace or "").strip()
    app_name_value = (app_name or "").strip()
    service_name_value = (service_name or "").strip()
    pod_name_value = (pod_name or "").strip()
    container_name_value = (container_name or "").strip()
    node_name_value = (node_name or "").strip()
    keywords_value = (keywords or "").strip()
    level_value = (level or "").strip().lower()

    resolved_app_name = app_name_value
    resolution_note = ""
    if service_name_value and not resolved_app_name:
        resolved_app_name = _resolve_service_to_app(namespace_value, service_name_value)
        if resolved_app_name:
            resolution_note = f"service {service_name_value} 已解析为 app={resolved_app_name}"
        else:
            resolution_note = f"service {service_name_value} 未解析到 app 标签，按原始范围查询"

    filters = {
        "namespace": namespace_value,
        "app": resolved_app_name,
        "pod": pod_name_value,
        "container": container_name_value,
        "node": node_name_value,
    }

    if not any(filters.values()) and not keywords_value and not level_value:
        return _error_payload(
            "log query is too broad",
            message="请至少提供 namespace、app_name、service_name、pod_name、keywords、level 中的一项。",
        )

    selector = _build_selector(filters)
    pipeline = _build_pipeline(keywords_value, level_value)
    query_used = f"{selector} {' '.join(pipeline)}".strip()

    explicit_start = (start_at or "").strip()
    explicit_end = (end_at or "").strip()
    if bool(explicit_start) != bool(explicit_end):
        return _error_payload(
            "start_at and end_at must be provided together",
            query_used=query_used,
        )
    if explicit_start:
        try:
            start_time = _parse_query_time(explicit_start, "start_at")
            end_time = _parse_query_time(explicit_end, "end_at")
        except ValueError as exc:
            return _error_payload(str(exc), query_used=query_used)
        if start_time >= end_time:
            return _error_payload(
                "start_at must be earlier than end_at",
                query_used=query_used,
            )
        if end_time - start_time > timedelta(hours=24):
            return _error_payload(
                "explicit log query range must not exceed 24 hours",
                query_used=query_used,
            )
        scope_text = (
            f"{start_time.isoformat().replace('+00:00', 'Z')} 至 "
            f"{end_time.isoformat().replace('+00:00', 'Z')}"
        )
    else:
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(minutes=normalized_since)
        scope_text = _query_scope_summary(filters, normalized_since)
    encoded_query = quote(query_used, safe="")
    path = (
        f"/loki/api/v1/query_range?query={encoded_query}"
        f"&start={_to_loki_ns(start_time)}"
        f"&end={_to_loki_ns(end_time)}"
        f"&limit={normalized_limit}"
        f"&direction=BACKWARD"
    )

    try:
        body = _loki_get(path)
    except RuntimeError as exc:
        return _error_payload(str(exc), query_used=query_used, loki_base_url=LOKI_BASE_URL)

    data = body.get("data", {})
    streams = data.get("result", [])
    items = _flatten_streams(streams, normalized_limit)

    if not items:
        summary = f"{scope_text}内未检索到符合条件的日志。"
        if keywords_value:
            summary += f" 关键词：{keywords_value}。"
        return {
            "generated_at": _now_text(),
            "loki_base_url": LOKI_BASE_URL,
            "summary": summary,
            "patterns": [],
            "samples": [],
            "query_used": query_used,
            "total_matches": 0,
            "applied_filters": {
                "namespace": namespace_value,
                "app_name": app_name_value,
                "resolved_app_name": resolved_app_name,
                "service_name": service_name_value,
                "pod_name": pod_name_value,
                "container_name": container_name_value,
                "node_name": node_name_value,
                "keywords": keywords_value,
                "level": level_value,
                "since_minutes": normalized_since,
                "start_at": start_time.isoformat().replace("+00:00", "Z"),
                "end_at": end_time.isoformat().replace("+00:00", "Z"),
                "limit": normalized_limit,
            },
            "resolution_note": resolution_note,
        }

    pattern_counter: dict[str, int] = {}
    for item in items:
        pattern = _extract_pattern(item.get("line", ""))
        pattern_counter[pattern] = pattern_counter.get(pattern, 0) + 1

    sorted_patterns = sorted(
        pattern_counter.items(),
        key=lambda pair: pair[1],
        reverse=True,
    )
    patterns = [
        {"pattern": name, "count": count}
        for name, count in sorted_patterns[:5]
    ]

    samples = [
        {
            "timestamp": item["timestamp"],
            "pod": item["labels"].get("pod", ""),
            "container": item["labels"].get("container", ""),
            "node": item["labels"].get("node", ""),
            "line": item["normalized_line"] or item["line"],
        }
        for item in items[:5]
    ]

    scope = scope_text
    top_pattern_text = "、".join(
        [f"{item['pattern']}({item['count']})" for item in patterns[:3]]
    )
    summary = f"{scope}内共命中 {len(items)} 条日志。"
    if top_pattern_text:
        summary += f" 主要模式：{top_pattern_text}。"
    if resolution_note:
        summary += f" {resolution_note}。"

    return {
        "generated_at": _now_text(),
        "loki_base_url": LOKI_BASE_URL,
        "summary": summary,
        "patterns": patterns,
        "samples": samples,
        "query_used": query_used,
        "total_matches": len(items),
        "applied_filters": {
            "namespace": namespace_value,
            "app_name": app_name_value,
            "resolved_app_name": resolved_app_name,
            "service_name": service_name_value,
            "pod_name": pod_name_value,
            "container_name": container_name_value,
            "node_name": node_name_value,
            "keywords": keywords_value,
            "level": level_value,
            "since_minutes": normalized_since,
            "start_at": start_time.isoformat().replace("+00:00", "Z"),
            "end_at": end_time.isoformat().replace("+00:00", "Z"),
            "limit": normalized_limit,
        },
        "resolution_note": resolution_note,
    }


LOG_TOOLS: list[dict[str, Any]] = [
    {
        "name": "search_logs",
        "label": "日志检索",
        "spec": {
            "type": "function",
            "function": {
                "name": "search_logs",
                "description": (
                    "统一查询 Loki 日志。"
                    "适合回答最近有什么报错、某个 Pod 最近日志如何、"
                    "是否出现 duplicate_order、timeout、exception 这类问题。"
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "namespace": {
                            "type": "string",
                            "description": "可选。按命名空间过滤，如 aiops、data-services、monitoring。",
                        },
                        "app_name": {
                            "type": "string",
                            "description": "可选。按应用标签 app 过滤，如 aiops-agent、agent-executor、biz-gateway（业务网关，namespace=data-services；历史名 aiops-gateway）。",
                        },
                        "service_name": {
                            "type": "string",
                            "description": "可选。按 Service 名过滤，会优先尝试解析为 app 标签再查询。",
                        },
                        "pod_name": {
                            "type": "string",
                            "description": "可选。按 Pod 名过滤。",
                        },
                        "container_name": {
                            "type": "string",
                            "description": "可选。按容器名过滤。",
                        },
                        "node_name": {
                            "type": "string",
                            "description": "可选。按节点名过滤。",
                        },
                        "keywords": {
                            "type": "string",
                            "description": "可选。关键字模糊搜索，例如 duplicate_order、timeout、error。",
                        },
                        "level": {
                            "type": "string",
                            "description": "可选。日志级别，可传 error、warn、info。",
                        },
                        "since_minutes": {
                            "type": "integer",
                            "description": "可选。查询最近多少分钟内的日志，默认 15。",
                        },
                        "start_at": {
                            "type": "string",
                            "description": (
                                "可选。带时区的 ISO 8601 开始时间；告警分析应与 end_at 一起传入。"
                            ),
                        },
                        "end_at": {
                            "type": "string",
                            "description": (
                                "可选。带时区的 ISO 8601 结束时间；显式窗口最长 24 小时。"
                            ),
                        },
                        "limit": {
                            "type": "integer",
                            "description": "可选。最多返回多少条匹配日志用于摘要分析，默认 20，最大 200。",
                        },
                    },
                },
            },
        },
        "handler": search_logs,
    },
]
