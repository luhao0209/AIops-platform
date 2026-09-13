from __future__ import annotations

import json
import os
from datetime import datetime
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


KNOWLEDGE_API_BASE = os.getenv(
    "KNOWLEDGE_API_BASE",
    "http://sop-service.aiops.svc.cluster.local:9200",
).rstrip("/")
KNOWLEDGE_TIMEOUT = int(os.getenv("KNOWLEDGE_TIMEOUT", "20"))
MAX_TOP_K = 10


def _now_text() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _error_payload(message: str, **extra: Any) -> dict[str, Any]:
    payload = {"generated_at": _now_text(), "error": message}
    payload.update(extra)
    return payload


def _post_json(path: str, payload: dict[str, Any]) -> dict[str, Any]:
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    request = Request(
        f"{KNOWLEDGE_API_BASE}{path}",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urlopen(request, timeout=KNOWLEDGE_TIMEOUT) as response:
            return json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="ignore")
        raise RuntimeError(f"knowledge http error {exc.code}: {detail}") from exc
    except URLError as exc:
        raise RuntimeError(f"knowledge connection error: {exc}") from exc


def _build_summary(
    symptom_query: str,
    total: int,
    items: list[dict[str, Any]],
    knowledge_type: str,
    component_tag: str,
) -> str:
    type_text = knowledge_type or "全部知识"
    component_text = f"，组件过滤 {component_tag}" if component_tag else ""

    if not items:
        return f"知识库中未检索到与“{symptom_query}”相关的{type_text}片段{component_text}。"

    top_labels = "、".join(
        [
            f"{item.get('title') or item.get('knowledge_id') or ''}#{item.get('section') or ''}".strip("#")
            for item in items[:3]
        ]
    ).strip("、")

    return (
        f"已从知识库中检索到 {total} 条与“{symptom_query}”相关的{type_text}片段"
        f"{component_text}。最相关的是：{top_labels}。"
    )


def search_knowledge_base(
    symptom_query: str,
    component_tag: str | None = None,
    top_k: int = 3,
    knowledge_type: str | None = None,
) -> dict[str, Any]:
    query_value = (symptom_query or "").strip()
    component_value = (component_tag or "").strip()
    knowledge_type_value = (knowledge_type or "").strip()

    if not query_value:
        return _error_payload("symptom_query is required")

    normalized_top_k = max(1, min(int(top_k or 3), MAX_TOP_K))

    request_payload = {
        "symptom_query": query_value,
        "component_tag": component_value or None,
        "top_k": normalized_top_k,
        "knowledge_type": knowledge_type_value or None,
    }

    try:
        response = _post_json("/api/knowledge/search", request_payload)
    except RuntimeError as exc:
        return _error_payload(
            str(exc),
            knowledge_api_base=KNOWLEDGE_API_BASE,
            request_payload=request_payload,
        )

    items = response.get("items", [])
    if not isinstance(items, list):
        items = []

    normalized_items: list[dict[str, Any]] = []
    for item in items:
        if not isinstance(item, dict):
            continue

        normalized_items.append(
            {
                "knowledge_id": str(item.get("knowledge_id", "")),
                "doc_id": str(item.get("doc_id", "")),
                "title": str(item.get("title", "")),
                "doc_type": str(item.get("doc_type", "")),
                "type_label": str(item.get("type_label", "")),
                "section": str(item.get("section", "")),
                "section_index": int(item.get("section_index", 0) or 0),
                "chunk_id": str(item.get("chunk_id", "")),
                "chunk_type": str(item.get("chunk_type", "")),
                "chunk_text": str(item.get("chunk_text", "")),
                "relative_path": str(item.get("relative_path", "")),
                "file_name": str(item.get("file_name", "")),
                "score": float(item.get("score", 0) or 0),
                "tags": item.get("tags", []) if isinstance(item.get("tags", []), list) else [],
                "applicable_components": (
                    item.get("applicable_components", [])
                    if isinstance(item.get("applicable_components", []), list)
                    else []
                ),
            }
        )

    summary = _build_summary(
        symptom_query=query_value,
        total=len(normalized_items),
        items=normalized_items,
        knowledge_type=knowledge_type_value,
        component_tag=component_value,
    )

    return {
        "generated_at": _now_text(),
        "knowledge_api_base": KNOWLEDGE_API_BASE,
        "summary": summary,
        "query_used": json.dumps(request_payload, ensure_ascii=False),
        "total": len(normalized_items),
        "items": normalized_items,
        "applied_filters": {
            "symptom_query": query_value,
            "component_tag": component_value,
            "top_k": normalized_top_k,
            "knowledge_type": knowledge_type_value,
        },
    }


KNOWLEDGE_TOOLS: list[dict[str, Any]] = [
    {
        "name": "search_knowledge_base",
        "label": "知识库检索",
        "spec": {
            "type": "function",
            "function": {
                "name": "search_knowledge_base",
                "description": (
                    "检索项目内运维知识库（SOP / 经验），用于补充“何时查、查什么、怎么读”，不是实时数据源。"
                    "优先根据现象摘要进行全库检索，不要过早添加 knowledge_type 或 component_tag 过滤；若无命中，再按信息不足处理。"
                    "适用："
                    "1) 已有部分现场工具结果，但仍无法确定原因、结论或下一步该查哪类指标/工具时；"
                    "2) 暂时不知道该调用哪个现场工具时，可用当前现象摘要来检索；若无相关命中，按信息不足处理，不要编造根因。"
                    "3) get_metric_value / get_metric_trend 首次返回 0 条时序或 PromQL/标签错误时，"
                    "可检索“组件 + 指标目的 + PromQL 标签映射”，使用本环境映射后最多重试一次；"
                    "真实序列的 value=0 不属于该场景。"
                    "不适用："
                    "- 用户只要当前数值/状态，且下一步工具已经明确时，直接调现场工具，不要先查知识库；"
                    "- 不要用本工具代替指标、日志、告警、拓扑等实时查询。"
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "symptom_query": {
                            "type": "string",
                            "description": (
                                "必须提供。这是唯一用于向量匹配的查询文本，由你根据用户问题或本轮已确认的现场现象概括生成。"
                                "要求写具体现象或矛盾信号，便于命中对应知识片段；不要把尚未证实的结论（如具体指标名、阈值）塞进检索式。"
                                "好的例子：GatewayLatency 告警规则看什么，排查重点是什么；"
                                "节点负载高但 CPU 利用率不高，下一步该看什么；"
                                "成功率下降且 timeout 占比升高该如何分流。"
                                "不好的例子：系统有问题、帮我看看、排查一下；"
                                "GatewayLatency告警排查方法，规则看什么指标，P95延迟阈值。"
                            ),
                        },
                        "component_tag": {
                            "type": "string",
                            "description": (
                                "可选过滤条件。只有当组件已经非常明确，且你希望缩小搜索范围时才填写。"
                                "默认应留空，避免因为组件标签不全或命名不一致而漏掉正确知识片段。"
                            ),
                        },
                        "top_k": {
                            "type": "integer",
                            "description": "可选。返回最相关的几条知识，默认 3，最大 10。",
                        },
                        "knowledge_type": {
                            "type": "string",
                            "enum": ["official_sop", "incident_experience", "postmortem"],
                            "description": (
                                "可选过滤条件。只有当你非常确定只需要某一类知识时才填写。"
                                "默认应留空，让系统先按现象在整个知识库中检索。"
                                "若问题是告警解释、规则含义、指标解释、排查思路、下一步该查什么，通常不要填写。"
                            ),
                        },
                    },
                    "required": ["symptom_query"],
                },
            },
        },
        "handler": search_knowledge_base,
    },
]
