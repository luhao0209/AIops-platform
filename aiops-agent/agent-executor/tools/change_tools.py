from __future__ import annotations

import json
import os
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any


DEFAULT_DATA_DIR = os.getenv("AIOPS_DATA_DIR", "/app/data")
CHANGE_EVENTS_FILE = os.getenv(
    "AIOPS_CHANGE_EVENTS_FILE",
    str(Path(DEFAULT_DATA_DIR) / "change_events.json"),
)
MAX_LIMIT = 50


def _now_text() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _error_payload(message: str, **extra: Any) -> dict[str, Any]:
    payload = {"generated_at": _now_text(), "error": message}
    payload.update(extra)
    return payload


def _load_change_events() -> list[dict[str, Any]]:
    path = Path(CHANGE_EVENTS_FILE)
    if not path.exists():
        raise RuntimeError(f"change events file not found: {path}")

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"change events json decode error: {exc}") from exc

    if not isinstance(data, list):
        raise RuntimeError("change events payload is not a list")

    return [item for item in data if isinstance(item, dict)]


def _parse_event_time(value: str) -> datetime | None:
    text = (value or "").strip()
    if not text:
        return None

    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%SZ"):
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    return None


def _contains_keyword(source: str, keyword: str) -> bool:
    return keyword.lower() in source.lower()


def search_change_events(
    limit: int = 10,
    namespace: str | None = None,
    resource_name: str | None = None,
    resource_kind: str | None = None,
    event_type: str | None = None,
    since_minutes: int | None = None,
    keywords: str | None = None,
) -> dict[str, Any]:
    try:
        events = _load_change_events()
    except RuntimeError as exc:
        return _error_payload(str(exc), change_events_file=CHANGE_EVENTS_FILE)

    normalized_limit = max(1, min(int(limit or 10), MAX_LIMIT))
    namespace_value = (namespace or "").strip()
    resource_name_value = (resource_name or "").strip()
    resource_kind_value = (resource_kind or "").strip()
    event_type_value = (event_type or "").strip()
    keywords_value = (keywords or "").strip()

    since_threshold: datetime | None = None
    if since_minutes is not None:
        try:
            normalized_since = max(1, int(since_minutes))
        except (TypeError, ValueError):
            return _error_payload(
                "since_minutes must be a positive integer",
                since_minutes=since_minutes,
            )
        since_threshold = datetime.now() - timedelta(minutes=normalized_since)

    filtered: list[dict[str, Any]] = []
    for item in events:
        if namespace_value and item.get("namespace", "") != namespace_value:
            continue
        if resource_name_value and item.get("resource_name", "") != resource_name_value:
            continue
        if resource_kind_value and item.get("resource_kind", "") != resource_kind_value:
            continue
        if event_type_value and item.get("event_type", "") != event_type_value:
            continue

        if since_threshold is not None:
            event_time = _parse_event_time(str(item.get("event_time", "")))
            if event_time is None or event_time < since_threshold:
                continue

        if keywords_value:
            haystack = " ".join(
                [
                    str(item.get("summary", "")),
                    str(item.get("resource_name", "")),
                    str(item.get("resource_kind", "")),
                    str(item.get("after_value", "")),
                ]
            )
            if not _contains_keyword(haystack, keywords_value):
                continue

        filtered.append(item)

    filtered.sort(
        key=lambda item: _parse_event_time(str(item.get("event_time", ""))) or datetime.min,
        reverse=True,
    )

    selected = filtered[:normalized_limit]
    compact_items = [
        {
            "event_time": str(item.get("event_time", "")),
            "summary": str(item.get("summary", "")),
            "after_value": str(item.get("after_value", "")),
        }
        for item in selected
    ]

    full_items = [
        {
            "event_id": str(item.get("event_id", "")),
            "event_time": str(item.get("event_time", "")),
            "event_type": str(item.get("event_type", "")),
            "namespace": str(item.get("namespace", "")),
            "resource_kind": str(item.get("resource_kind", "")),
            "resource_name": str(item.get("resource_name", "")),
            "before_value": str(item.get("before_value", "")),
            "after_value": str(item.get("after_value", "")),
            "summary": str(item.get("summary", "")),
            "operator": str(item.get("operator", "")),
            "source": str(item.get("source", "")),
            "during_incident": bool(item.get("during_incident", False)),
        }
        for item in selected
    ]

    return {
        "generated_at": _now_text(),
        "change_events_file": CHANGE_EVENTS_FILE,
        "total": len(filtered),
        "returned": len(selected),
        "applied_filters": {
            "limit": normalized_limit,
            "namespace": namespace_value,
            "resource_name": resource_name_value,
            "resource_kind": resource_kind_value,
            "event_type": event_type_value,
            "since_minutes": since_minutes,
            "keywords": keywords_value,
        },
        "items": compact_items,
        "full_items": full_items,
    }

CHANGE_TOOLS: list[dict[str, Any]] = [
    {
        "name": "search_change_events",
        "label": "变更检索",
        "spec": {
            "type": "function",
            "function": {
                "name": "search_change_events",
                "description": (
                    "统一检索 Change Archive 变更记录。"
                    "适合回答最近改了什么、某个资源最近发生了什么变更、"
                    "有没有镜像版本变化、有没有扩缩容、有没有配置修改这类问题。"
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "limit": {
                            "type": "integer",
                            "description": "可选。返回条数，默认 10，最大 50。",
                        },
                        "namespace": {
                            "type": "string",
                            "description": "可选。按命名空间过滤，如 aiops、infra、data-services。",
                        },
                        "resource_name": {
                            "type": "string",
                            "description": "可选。按资源名过滤，如 aiops-agent、worker-ai。",
                        },
                        "resource_kind": {
                            "type": "string",
                            "description": "可选。按资源类型过滤，如 Deployment、Pod、Node、ConfigMap。",
                        },
                        "event_type": {
                            "type": "string",
                            "description": "可选。按变更类型过滤，如 image、scale、topology、config、node_discovery。",
                        },
                        "since_minutes": {
                            "type": "integer",
                            "description": "可选。只看最近多少分钟内的变更。",
                        },
                        "keywords": {
                            "type": "string",
                            "description": "可选。按 summary 模糊匹配关键词，如 镜像版本、扩容、配置修改。",
                        },
                    },
                },
            },
        },
        "handler": search_change_events,
    },
]
