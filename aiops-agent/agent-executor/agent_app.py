from __future__ import annotations

import asyncio
import json
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Literal
from urllib.error import HTTPError, URLError
from urllib.request import Request as UrlRequest, urlopen

from fastapi import (
    BackgroundTasks,
    FastAPI,
    HTTPException,
    Query,
    Request,
)
from pydantic import BaseModel, Field

from alerting import (
    IncidentAnalysisAgent,
    IncidentAnalysisRunner,
    IncidentRecheckScheduler,
    ingest_alertmanager_payload,
)
from alerting.remediation_executor import (
    execute_rollback_deployment,
    execute_scale_deployment,
)
from entity_resolver import build_default_entity_resolver
from guardrails import (
    Claim,
    ClaimEnvelope,
    EvidenceRecord,
    ResponseGuardResult,
    build_evidence_record,
    compile_claims,
    render_guarded_response,
    validate_claims,
)
from memory import (
    ChatMemoryStore,
    ChatSessionStore,
    ChatSummaryStore,
    EntityMemory,
    IncidentAnalysisStore,
    IncidentMemoryStore,
    KnowledgeChunkMemory,
    PendingEntityClarification,
    RemediationStore,
    ToolMemory,
    UserCorrectionMemory,
    build_chat_memory_context,
    build_chat_summary_context,
    maybe_update_chat_summary,
    parse_utc_datetime,
    utc_now,
)
from token_usage_store import (
    add_tokens,
    empty_usage,
    get_bucket_all_time,
    get_bucket_today,
    merge_usage,
    normalize_chat_usage,
    today_date,
)
from tool_runtime import parse_tool_arguments
from tools import (
    ALL_TOOL_SPECS,
    INCIDENT_TOOL_SPECS,
    execute_tool_call,
    get_business_success_rate_context,
)
from tools.topology_tools import (
    get_cluster_topology,
    get_cluster_topology_summary,
)

app = FastAPI(title="AIOps Agent Executor")

MODEL_API_BASE = os.getenv("MODEL_API_BASE", "").rstrip("/")
MODEL_API_KEY = os.getenv("MODEL_API_KEY", "")
MODEL_NAME = os.getenv("MODEL_NAME", "")
MODEL_TEMPERATURE = float(os.getenv("MODEL_TEMPERATURE", "0.2"))
MODEL_TIMEOUT = int(os.getenv("MODEL_TIMEOUT", "60"))

CHAT_RESPONSE_GUARD_MODE = (
    os.getenv(
        "CHAT_RESPONSE_GUARD_MODE",
        "off",
    )
    .strip()
    .lower()
)
if CHAT_RESPONSE_GUARD_MODE not in {
    "off",
    "observe",
    "single_pass",
    "enforce",
}:
    CHAT_RESPONSE_GUARD_MODE = "off"

MAX_TOOL_ROUNDS = 4
MAX_TOOL_CALLS_PER_CHAT = 5
MAX_COARSE_TOOL_CALLS = 2
MAX_COMPANION_TOOL_CALLS = 1

CLAIM_RESPONSE_TOOL_NAME = "submit_evidence_claims"
CLAIM_RESPONSE_TOOL_SPEC = {
    "type": "function",
    "function": {
        "name": CLAIM_RESPONSE_TOOL_NAME,
        "description": (
            "当现有工具证据已经足以回答用户问题时，"
            "调用此工具提交最终结构化结论并结束查询。"
            "这不是查询工具，不会获取新数据。"
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "claims": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "text": {
                                "type": "string",
                            },
                            "type": {
                                "type": "string",
                                "enum": [
                                    "fact",
                                    "hypothesis",
                                    "recommendation",
                                    "unknown",
                                ],
                            },
                            "evidence_refs": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "properties": {
                                        "evidence_id": {
                                            "type": "string",
                                        },
                                        "field_path": {
                                            "type": "string",
                                        },
                                        "expected_value": {},
                                        "unit": {
                                            "type": "string",
                                        },
                                    },
                                    "required": [
                                        "evidence_id",
                                    ],
                                },
                            },
                        },
                        "required": [
                            "text",
                            "type",
                            "evidence_refs",
                        ],
                    },
                },
            },
            "required": ["claims"],
        },
    },
}

RELIABILITY_TOOL_NAME = "get_seckill_reliability"
BUSINESS_SUCCESS_CONTEXT_TOOL_NAME = "get_business_success_rate_context"
KNOWLEDGE_TOOL_NAME = "search_knowledge_base"
RELIABILITY_KNOWLEDGE_TOP_K = 2

COARSE_TOOL_NAMES = {
    "get_cluster_topology_summary",
    "get_business_overview",
    "get_business_success_rate_context",
    "get_alerts",
    "get_topk_resource_consumers",
    "get_infrastructure_saturation",
    "search_change_events",
    "search_knowledge_base",
}

TOOL_MEMORY_TTL_SECONDS = {
    "get_alerts": 120,
    "get_alert_detail": 120,
    "get_business_overview": 300,
    "get_business_success_rate_context": 300,
    "get_service_golden_signals": 300,
    "get_infrastructure_saturation": 300,
    "get_topk_resource_consumers": 300,
    "get_metric_trend": 300,
    "search_logs": 300,
    "get_cluster_topology": 600,
    "get_cluster_topology_summary": 600,
    "search_change_events": 900,
    "search_knowledge_base": 3600,
}

DEFAULT_TOOL_MEMORY_TTL_SECONDS = 300


def get_tool_memory_expiry(tool_name: str) -> datetime:
    ttl_seconds = TOOL_MEMORY_TTL_SECONDS.get(
        tool_name,
        DEFAULT_TOOL_MEMORY_TTL_SECONDS,
    )
    return datetime.now(timezone.utc) + timedelta(
        seconds=ttl_seconds
    )


def execute_chat_tool_call(
    tool_name: str,
    arguments: dict[str, Any],
    *,
    tool_call_id: str = "",
) -> tuple[dict[str, Any], EvidenceRecord]:
    """执行普通对话工具并附加证据元数据。"""

    try:
        raw_result = execute_tool_call(
            tool_name,
            arguments,
        )
    except Exception as exc:
        raw_result = {
            "error": str(exc),
            "trace": {
                "tool_name": tool_name,
                "arguments": arguments,
                "status": "failed",
            },
        }

    if isinstance(raw_result, dict):
        result = raw_result
    else:
        result = {
            "result": raw_result,
        }

    ttl_seconds = TOOL_MEMORY_TTL_SECONDS.get(
        tool_name,
        DEFAULT_TOOL_MEMORY_TTL_SECONDS,
    )

    evidence = build_evidence_record(
        tool_name=tool_name,
        arguments=arguments,
        result=result,
        tool_call_id=tool_call_id,
        ttl_seconds=ttl_seconds,
    )


    result["_evidence"] = evidence.model_dump(
        mode="json",
        exclude={"data"},
    )

    trace = result.get("trace")
    if isinstance(trace, dict):
        trace["evidence_id"] = evidence.evidence_id
        trace["evidence_status"] = evidence.status
        trace["evidence_expires_at"] = (
            evidence.expires_at.isoformat()
        )

    return result, evidence


TOOL_SPEC_BY_NAME = {
    item.get("function", {}).get("name", ""): item
    for item in ALL_TOOL_SPECS
    if isinstance(item, dict)
}

ENTITY_RESOLVER = build_default_entity_resolver()
CHAT_MEMORY_STORE = ChatMemoryStore()
CHAT_SESSION_STORE = ChatSessionStore()
CHAT_SUMMARY_STORE = ChatSummaryStore()
INCIDENT_MEMORY_STORE = IncidentMemoryStore()
INCIDENT_ANALYSIS_STORE = IncidentAnalysisStore()
REMEDIATION_STORE = RemediationStore()

INCIDENT_ANALYSIS_RUNNER = IncidentAnalysisRunner(
    INCIDENT_MEMORY_STORE,
    INCIDENT_ANALYSIS_STORE,
    recovery_verifier=execute_tool_call,
)

_INCIDENT_RECHECK_STOP_EVENT: asyncio.Event | None = None
_INCIDENT_RECHECK_TASK: asyncio.Task[None] | None = None


class InspectionStep(BaseModel):
    title: str
    detail: str
    status: str
    timestamp: str | None = None


class ClusterPodSummary(BaseModel):
    namespace: str
    total: int
    running: int
    pending: int = 0
    failed: int = 0


class ClusterDeploymentItem(BaseModel):
    name: str
    desired: int = 0
    ready: int = 0
    available: int = 0
    images: list[str] = Field(default_factory=list)


class ClusterDeploymentSummary(BaseModel):
    namespace: str
    total: int
    available: int
    items: list[ClusterDeploymentItem] = Field(default_factory=list)


class ClusterNodeSummary(BaseModel):
    total: int
    ready: int
    not_ready: int = 0


class ClusterSummary(BaseModel):
    pods: list[ClusterPodSummary] = Field(default_factory=list)
    deployments: list[ClusterDeploymentSummary] = Field(default_factory=list)
    nodes: ClusterNodeSummary | None = None


class ChangeEvent(BaseModel):
    event_id: str
    event_time: str
    event_type: str
    namespace: str
    resource_kind: str
    resource_name: str
    before_value: str = ""
    after_value: str = ""
    summary: str
    operator: str = ""
    source: str = ""
    during_incident: bool = False


class InspectionResult(BaseModel):
    summary: str = ""
    level: str = "info"
    analysis_input: str = ""
    cluster_summary: ClusterSummary | dict[str, Any] = Field(default_factory=dict)
    related_changes: list[ChangeEvent] = Field(default_factory=list)


class InspectionPayload(BaseModel):
    inspection_id: str
    status: str
    created_at: str
    updated_at: str
    stop_requested: bool = False
    steps: list[InspectionStep] = Field(default_factory=list)
    result: InspectionResult


class ChatHistoryItem(BaseModel):
    role: str
    content: str


class ChatRequestPayload(BaseModel):
    message: str
    mode: str = "chat"
    history: list[ChatHistoryItem] = Field(default_factory=list)
    context: dict[str, Any] = Field(default_factory=dict)
    current_incident: dict[str, Any] | None = None


class CreateChatSessionPayload(BaseModel):
    title: str = "新对话"


class RemediationDecisionPayload(BaseModel):
    decided_by: str = Field(default="web-sre", min_length=1, max_length=80)
    comment: str = Field(default="", max_length=500)


def is_model_configured() -> bool:
    return bool(MODEL_API_BASE and MODEL_API_KEY and MODEL_NAME)


def normalize_message_content(content: Any) -> str:
    if isinstance(content, str):
        return content.strip()

    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if isinstance(item, dict):
                if item.get("type") == "text":
                    parts.append(item.get("text", ""))
                elif "text" in item:
                    parts.append(str(item.get("text", "")))
            elif isinstance(item, str):
                parts.append(item)
        return "".join(parts).strip()

    return str(content or "").strip()


def call_model_raw(
    messages: list[dict[str, Any]],
    tools: list[dict[str, Any]] | None = None,
    tool_choice: str | dict[str, Any] | None = None,
    *,
    record: bool = True,
) -> dict[str, Any]:
    if not is_model_configured():
        raise RuntimeError("model is not configured")

    url = f"{MODEL_API_BASE}/chat/completions"
    payload: dict[str, Any] = {
        "model": MODEL_NAME,
        "messages": messages,
        "temperature": MODEL_TEMPERATURE,
    }
    if tools:
        payload["tools"] = tools
        payload["tool_choice"] = tool_choice or "auto"

    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    request = UrlRequest(
        url,
        data=data,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {MODEL_API_KEY}",
        },
        method="POST",
    )

    try:
        with urlopen(request, timeout=MODEL_TIMEOUT) as response:
            body = json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="ignore")
        raise RuntimeError(f"model http error {exc.code}: {detail}") from exc
    except URLError as exc:
        raise RuntimeError(f"model connection error: {exc}") from exc

    choices = body.get("choices", [])
    if not choices:
        raise RuntimeError(f"model returned empty choices: {body}")

    message = choices[0].get("message", {})
    if not isinstance(message, dict):
        raise RuntimeError(f"model returned invalid message: {body}")

    fallback_chars = len(json.dumps(messages, ensure_ascii=False)) + len(
        json.dumps(message, ensure_ascii=False)
    )
    usage = normalize_chat_usage(body.get("usage"), fallback_chars=fallback_chars)
    if record and usage.get("total_tokens"):
        add_tokens("main", int(usage["total_tokens"]), estimated=bool(usage.get("estimated")))

    return {
        "message": message,
        "usage": usage,
    }


def build_incident_analysis_agent() -> IncidentAnalysisAgent:
    return IncidentAnalysisAgent(
        model_caller=call_model_raw,
        tool_executor=execute_tool_call,
        tool_specs=INCIDENT_TOOL_SPECS,




        max_tool_calls=10,
        max_tool_rounds=10,
    )


def run_incident_first_round_in_background(
    incident_id: str,
) -> None:
    result = INCIDENT_ANALYSIS_RUNNER.run_first_round(
        incident_id,
        build_incident_analysis_agent(),
    )

    if result.get("error"):
        print(
            "[incident-analysis] first round failed: "
            f"incident_id={incident_id}, "
            f"error={result.get('error')}"
        )
    else:
        print(
            "[incident-analysis] first round finished: "
            f"incident_id={incident_id}, "
            f"analysis_id={result.get('analysis_id')}, "
            f"status={result.get('status')}, "
            f"tool_calls={result.get('tool_calls_used', 0)}"
        )

    INCIDENT_ANALYSIS_RUNNER.complete_if_resolved(incident_id)


def run_incident_recheck_in_background(
    analysis_id: str,
) -> dict[str, Any]:
    result = INCIDENT_ANALYSIS_RUNNER.run_recheck(
        analysis_id,
        build_incident_analysis_agent(),
    )

    if result.get("error"):
        print(
            "[incident-recheck] failed: "
            f"analysis_id={analysis_id}, "
            f"error={result.get('error')}"
        )
    elif result.get("executed"):
        print(
            "[incident-recheck] finished: "
            f"analysis_id={analysis_id}, "
            f"status={result.get('status')}, "
            f"current_round={result.get('current_round')}"
        )

    incident_id = str(result.get("incident_id") or "").strip()
    if not incident_id:
        run = INCIDENT_ANALYSIS_STORE.get_run(analysis_id)
        if run is not None:
            incident_id = run.incident_id

    if incident_id:
        INCIDENT_ANALYSIS_RUNNER.complete_if_resolved(incident_id)

    return result


def recover_stale_incident_analysis(
    analysis_id: str,
) -> dict[str, Any]:
    result = INCIDENT_ANALYSIS_RUNNER.recover_stale_running(
        analysis_id,
    )
    if result.get("recovered"):
        print(
            "[incident-recheck] recovered stale running analysis: "
            f"analysis_id={analysis_id}, "
            f"status={result.get('status')}"
        )
    return result


INCIDENT_RECHECK_SCHEDULER = IncidentRecheckScheduler(
    INCIDENT_ANALYSIS_STORE,
    run_incident_recheck_in_background,
    stale_run_callback=recover_stale_incident_analysis,
    stale_after_seconds=180,
    poll_interval_seconds=15,
    batch_size=10,
)


@app.on_event("startup")
async def start_incident_recheck_scheduler() -> None:
    global _INCIDENT_RECHECK_STOP_EVENT, _INCIDENT_RECHECK_TASK

    if _INCIDENT_RECHECK_TASK is not None and not _INCIDENT_RECHECK_TASK.done():
        return

    _INCIDENT_RECHECK_STOP_EVENT = asyncio.Event()
    _INCIDENT_RECHECK_TASK = asyncio.create_task(
        INCIDENT_RECHECK_SCHEDULER.run_forever(_INCIDENT_RECHECK_STOP_EVENT),
        name="incident-recheck-scheduler",
    )
    print("[incident-recheck] scheduler started")


@app.on_event("shutdown")
async def stop_incident_recheck_scheduler() -> None:
    global _INCIDENT_RECHECK_STOP_EVENT, _INCIDENT_RECHECK_TASK

    if _INCIDENT_RECHECK_STOP_EVENT is not None:
        _INCIDENT_RECHECK_STOP_EVENT.set()

    if _INCIDENT_RECHECK_TASK is not None:
        try:
            await asyncio.wait_for(_INCIDENT_RECHECK_TASK, timeout=5)
        except asyncio.TimeoutError:
            _INCIDENT_RECHECK_TASK.cancel()
            try:
                await _INCIDENT_RECHECK_TASK
            except asyncio.CancelledError:
                pass
        _INCIDENT_RECHECK_TASK = None

    _INCIDENT_RECHECK_STOP_EVENT = None
    print("[incident-recheck] scheduler stopped")


def queue_incident_first_round(
    incident_id: str,
    background_tasks: BackgroundTasks,
) -> tuple[dict[str, Any], bool]:
    started = INCIDENT_ANALYSIS_RUNNER.ensure_started(incident_id)

    queued = bool(
        started.get("started")
        and started.get("status") == "running"
    )
    if queued:
        background_tasks.add_task(
            run_incident_first_round_in_background,
            incident_id,
        )

    return started, queued


def call_model(messages: list[dict[str, Any]]) -> str:
    result = call_model_raw(messages)
    message = result["message"]
    content = normalize_message_content(message.get("content", ""))
    if not content:
        raise RuntimeError(f"model returned empty content: {message}")
    return content


def build_system_prompt() -> str:
    return (
        "你是 AIOps 运维助手，面向 SRE/运维工程师，用中文简洁回答。"
        "需要实时运行状态时，应先调用合适的工具。"
        "回答必须区分已确认事实、推断和待确认内容。"
        "只有工具直接支持的内容才能作为已确认事实。"
        "证据不足、查询失败、返回空结果或超时时，必须明确说明信息不足，不得想象补全。"
        "没有完整证据链时，不得宣称已经确认根因。"
    )


def build_context_block_for_chat(payload: ChatRequestPayload) -> str:
    return "\n".join(
        [
            f"当前模式: {payload.mode}",
            f"当前 incident: {json.dumps(payload.current_incident, ensure_ascii=False) if payload.current_incident else 'null'}",
            f"当前上下文(JSON): {json.dumps(payload.context or {}, ensure_ascii=False)}",
            "如果用户的问题需要集群结构、组件分布、节点承载、命名空间组件清单等事实信息，请优先考虑调用拓扑工具。",
            "如果用户明确在问 CPU、内存、磁盘、负载、最占资源、TopK 等资源使用问题，必须优先调用资源类工具，不能先用拓扑工具代替资源判断。",
        ]
    )


def build_memory_block_for_chat(
    session_id: str,
    resolution: dict[str, Any] | None = None,
) -> str:
    memory = CHAT_MEMORY_STORE.get_or_create(session_id)

    current_entity = extract_entity_memory(resolution)
    if current_entity is not None:
        memory.resolved_entity = current_entity

    compact_memory_context = build_chat_memory_context(memory)

    rolling_summary = CHAT_SUMMARY_STORE.get(session_id)
    rolling_summary_context = build_chat_summary_context(rolling_summary)

    sections: list[str] = []

    if rolling_summary_context:
        sections.append(
            "滚动会话摘要：\n"
            f"{rolling_summary_context}"
        )

    if compact_memory_context:
        sections.append(
            "结构化短期记忆：\n"
            f"{compact_memory_context}"
        )

    return "\n\n".join(sections)


def build_resolved_entity_user_prefix(resolution: dict[str, Any] | None) -> str:
    if not resolution or resolution.get("status") != "resolved":
        return ""

    entity = resolution.get("entity") or {}
    if not isinstance(entity, dict):
        return ""

    name = str(entity.get("name") or "")
    namespace = str(entity.get("namespace") or "null")
    plane = str(entity.get("plane") or "")
    notes = str(entity.get("notes") or "")

    prefix = f"【本轮已解析对象】{name} | namespace={namespace} | plane={plane}"
    if notes:
        prefix += f" | {notes}"

    return prefix


def build_context_block_for_inspection(payload: InspectionPayload) -> str:
    result = payload.result
    cluster_summary = result.cluster_summary
    if isinstance(cluster_summary, ClusterSummary):
        cluster_summary_data = cluster_summary.model_dump()
    else:
        cluster_summary_data = cluster_summary

    change_lines = []
    for item in result.related_changes[-5:]:
        change_lines.append(f"- {item.event_time} | {item.event_type} | {item.summary}")

    return "\n".join(
        [
            "当前模式: inspection",
            f"巡检任务ID: {payload.inspection_id}",
            f"巡检状态: {payload.status}",
            "",
            "巡检摘要:",
            result.analysis_input or "暂无巡检摘要",
            "",
            f"巡检结论: {result.summary or '暂无'}",
            f"结论等级: {result.level}",
            "",
            "集群结构化概况(JSON):",
            json.dumps(cluster_summary_data, ensure_ascii=False),
            "",
            "最近变更:",
            "\n".join(change_lines) if change_lines else "无",
            "",
            "当前组件判断规则:",
            "- 集群结构化概况中的 deployments.items 是本次巡检采集到的当前工作负载清单。",
            "- 不得把清单中不存在的历史组件、实体目录旧项或会话记忆写成当前依赖或待确认项。",
            "- 只有当前清单或本次工具证据明确出现的组件，才能进入当前健康结论；历史组件仅在用户明确询问历史时提及。",
            "",
            "请基于这些信息进行分析，重点说明：",
            "1. 当前最值得关注的点",
            "2. 你对问题性质的判断",
            "3. 建议下一步排查方向",
        ]
    )


def build_chat_messages(
    payload: ChatRequestPayload,
    resolution: dict[str, Any] | None = None,
    memory_context: str = "",
) -> list[dict[str, Any]]:
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": build_system_prompt()},
        {"role": "system", "content": build_context_block_for_chat(payload)},
    ]
    if CHAT_RESPONSE_GUARD_MODE == "single_pass":
        messages.append(
            {
                "role": "system",
                "content": (
                    build_single_pass_claim_instruction()
                ),
            }
        )
    if memory_context:
        messages.append({"role": "system", "content": f"会话记忆:\n{memory_context}"})

    for item in payload.history[-8:]:
        role = item.role if item.role in {"user", "assistant", "system", "tool"} else "user"
        messages.append({"role": role, "content": item.content})

    resolved_prefix = build_resolved_entity_user_prefix(resolution)
    user_content = payload.message
    if resolved_prefix:
        user_content = f"{resolved_prefix}\n用户问题：{payload.message}"

    messages.append({"role": "user", "content": user_content})
    return messages


def build_inspection_messages(payload: InspectionPayload) -> list[dict[str, Any]]:
    return [
        {"role": "system", "content": build_system_prompt()},
        {"role": "system", "content": build_context_block_for_inspection(payload)},
        {
            "role": "user",
            "content": "请根据本次巡检结果直接给出运维分析，不要照抄输入原文。",
        },
    ]


def extract_tool_calls(message: dict[str, Any]) -> list[dict[str, Any]]:
    tool_calls = message.get("tool_calls") or []
    return tool_calls if isinstance(tool_calls, list) else []


def filter_tool_specs(tool_names: list[str]) -> list[dict[str, Any]]:
    specs: list[dict[str, Any]] = []
    for name in tool_names:
        spec = TOOL_SPEC_BY_NAME.get(name)
        if spec:
            specs.append(spec)
    return specs


def choose_initial_tool_specs(payload: ChatRequestPayload) -> list[dict[str, Any]]:
    return ALL_TOOL_SPECS


def choose_followup_tool_specs(payload: ChatRequestPayload) -> list[dict[str, Any]]:
    return ALL_TOOL_SPECS


def should_prefetch_business_success_context(
    payload: ChatRequestPayload,
) -> bool:
    text = payload.message.strip().lower()
    technical_reliability_markers = (
        "burn rate",
        "burnrate",
        "燃烧率",
        "发布风险",
        "技术slo",
        "技术 slo",
        "技术sli",
        "技术 sli",
    )
    if any(marker in text for marker in technical_reliability_markers):
        return False

    business_success_markers = (
        "业务成功率",
        "成功率如何计算",
        "成功率怎么计算",
        "成功率口径",
        "成功率不一致",
        "sli",
        "slo",
        "30天sli",
        "30天 sli",
        "slo目标",
        "slo 目标",
        "错误预算",
    )
    return any(marker in text for marker in business_success_markers)


def without_tool_spec(
    tool_specs: list[dict[str, Any]],
    excluded_tool_name: str,
) -> list[dict[str, Any]]:
    return [
        spec
        for spec in tool_specs
        if str((spec.get("function") or {}).get("name") or "")
        != excluded_tool_name
    ]


def looks_like_tool_markup(text: str) -> bool:
    if not text:
        return False

    markers = [
        "<｜｜DSML｜｜tool_calls>",
        "<｜｜DSML｜｜invoke",
        "</｜｜DSML｜｜tool_calls>",
        "tool_calls",
        "\"tool_calls\"",
    ]
    return any(marker in text for marker in markers)


def rewrite_tool_markup_to_final_answer(messages: list[dict[str, Any]], draft: str) -> tuple[str, dict[str, Any]]:
    rewrite_messages = list(messages)
    rewrite_messages.append(
        {
            "role": "system",
            "content": (
                "你上一条输出包含了内部工具调用标记或中间推理痕迹。"
                "现在必须把它改写为面向用户的最终自然语言答案。"
                "禁止输出任何 tool_calls、DSML、invoke、XML、JSON 工具结构、伪代码或中间推理。"
                "只能输出中文最终答复。"
                "回答时仍需区分：已确认事实、推断、待确认项。"
            ),
        }
    )
    rewrite_messages.append(
        {
            "role": "assistant",
            "content": draft,
        }
    )
    rewrite_messages.append(
        {
            "role": "user",
            "content": "请去掉所有工具调用标记和中间过程，只保留最终答复。",
        }
    )
    result = call_model_raw(rewrite_messages)
    content = normalize_message_content(result["message"].get("content", ""))
    if not content:
        raise RuntimeError(f"model returned empty content: {result['message']}")
    return content, result.get("usage") or empty_usage()


def force_final_answer(messages: list[dict[str, Any]]) -> tuple[str, dict[str, Any]]:
    final_messages = list(messages)
    final_messages.append(
        {
            "role": "system",
            "content": (
                "你当前必须停止继续调用工具，基于现有证据直接回答。"
                "禁止继续申请工具，禁止输出任何 tool_calls、DSML、invoke、XML、JSON 工具结构、伪代码或中间推理。"
                "你现在只能输出给用户看的最终中文答复。"
                "请明确区分：已确认事实、推断、待确认项。"
                "如果证据不足，必须明确写出证据不足和建议下一步。"
            ),
        }
    )

    result = call_model_raw(final_messages)
    final_text = normalize_message_content(result["message"].get("content", ""))
    session_usage = result.get("usage") or empty_usage()
    if not final_text:
        raise RuntimeError(f"model returned empty content: {result['message']}")

    if looks_like_tool_markup(final_text):
        final_text, rewrite_usage = rewrite_tool_markup_to_final_answer(messages, final_text)
        session_usage = merge_usage(session_usage, rewrite_usage)

    return final_text, session_usage


def append_tool_skip_result(
    messages: list[dict[str, Any]],
    tool_call: dict[str, Any],
    reason: str,
) -> None:
    function_block = tool_call.get("function") or {}
    tool_name = str(function_block.get("name", ""))
    tool_id = str(tool_call.get("id", ""))
    messages.append(
        {
            "role": "tool",
            "tool_call_id": tool_id,
            "name": tool_name,
            "content": json.dumps(
                {
                    "status": "skipped",
                    "reason": reason,
                },
                ensure_ascii=False,
            ),
        }
    )


def should_run_reliability_knowledge_companion(
    tool_name: str,
    requested_tool_names: set[str],
    companion_tool_calls: int,
) -> bool:
    return (
        tool_name == RELIABILITY_TOOL_NAME
        and KNOWLEDGE_TOOL_NAME not in requested_tool_names
        and companion_tool_calls < MAX_COMPANION_TOOL_CALLS
    )


def build_reliability_knowledge_query(
    user_message: str,
    reliability_result: dict[str, Any],
) -> str:
    short_window = reliability_result.get("short_window") or {}
    long_window = reliability_result.get("long_window") or {}
    return (
        f"{user_message.strip()}；秒杀业务技术 SLO、错误预算、Burn Rate 和发布风险如何解释；"
        f"当前综合状态={reliability_result.get('reliability_status') or 'unknown'}，"
        f"数据状态={reliability_result.get('status') or 'unknown'}，"
        f"5分钟窗口={short_window.get('status') or 'unknown'}，"
        f"1小时窗口={long_window.get('status') or 'unknown'}"
    )


def compact_reliability_knowledge_result(
    knowledge_result: dict[str, Any],
) -> dict[str, Any]:
    if knowledge_result.get("error"):
        return {
            "status": "unavailable",
            "role": "interpretation_only",
            "source_of_truth": RELIABILITY_TOOL_NAME,
            "message": "Knowledge retrieval failed; use the reliability result without inventing project rules.",
        }

    items = knowledge_result.get("items")
    if not isinstance(items, list):
        items = []

    compact_items: list[dict[str, Any]] = []
    for item in items[:RELIABILITY_KNOWLEDGE_TOP_K]:
        if not isinstance(item, dict):
            continue
        compact_items.append(
            {
                "knowledge_id": item.get("knowledge_id", ""),
                "title": item.get("title", ""),
                "section": item.get("section", ""),
                "chunk_id": item.get("chunk_id", ""),
                "chunk_text": item.get("chunk_text", ""),
                "score": item.get("score"),
            }
        )

    return {
        "status": "available" if compact_items else "no_match",
        "role": "interpretation_only",
        "source_of_truth": RELIABILITY_TOOL_NAME,
        "summary": knowledge_result.get("summary", ""),
        "items": compact_items,
    }


def attach_reliability_knowledge_context(
    payload: ChatRequestPayload,
    reliability_result: dict[str, Any],
) -> dict[str, Any]:
    query = build_reliability_knowledge_query(
        payload.message,
        reliability_result,
    )
    knowledge_result, _ = execute_chat_tool_call(
        KNOWLEDGE_TOOL_NAME,
        {
            "symptom_query": query,
            "top_k": RELIABILITY_KNOWLEDGE_TOP_K,
        },
        tool_call_id="reliability-knowledge-companion",
    )
    reliability_result["interpretation_knowledge"] = (
        compact_reliability_knowledge_result(knowledge_result)
    )
    return knowledge_result


def get_chat_session_id(payload: ChatRequestPayload) -> str:
    context = payload.context or {}
    for key in ("session_id", "chat_session_id", "conversation_id", "thread_id"):
        value = context.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()

    if payload.current_incident:
        incident_id = payload.current_incident.get("incident_id")
        if isinstance(incident_id, str) and incident_id.strip():
            return f"incident:{incident_id.strip()}"

    return "default-chat"


def save_chat_message(
    session_id: str,
    role: str,
    content: str,
    metadata: dict[str, Any] | None = None,
) -> None:
    try:
        CHAT_SESSION_STORE.append_message(
            session_id=session_id,
            role=role,
            content=content,
            metadata=metadata or {},
        )
    except Exception as exc:

        print(
            f"[chat-session] failed to save message: "
            f"session_id={session_id}, role={role}, error={exc}"
        )


def update_chat_summary_in_background(
    session_id: str,
) -> None:
    try:
        result = maybe_update_chat_summary(
            session_id=session_id,
            session_store=CHAT_SESSION_STORE,
            summary_store=CHAT_SUMMARY_STORE,
        )
    except Exception as exc:
        print(
            "[chat-summary] unexpected failure: "
            f"session_id={session_id}, error={exc}"
        )
        return

    reason = str(result.get("reason") or "")

    if result.get("updated"):
        print(
            "[chat-summary] updated: "
            f"session_id={session_id}, "
            f"message_count="
            f"{result.get('summarized_batch_count')}, "
            f"marker="
            f"{result.get('summarized_until_message_id')}"
        )
        return

    if reason in {
        "summary_failed",
        "summary_model_not_configured",
    }:
        print(
            "[chat-summary] skipped: "
            f"session_id={session_id}, "
            f"reason={reason}, "
            f"error={result.get('error', '')}"
        )


def extract_entity_memory(resolution: dict[str, Any] | None) -> EntityMemory | None:
    if not resolution or resolution.get("status") != "resolved":
        return None

    entity = resolution.get("entity") or {}
    if not isinstance(entity, dict):
        return None

    return EntityMemory(
        entity_id=str(entity.get("entity_id") or ""),
        entity_type=str(entity.get("kind") or ""),
        name=str(entity.get("name") or ""),
        namespace=entity.get("namespace"),
        plane=str(entity.get("plane") or ""),
    )


def extract_knowledge_chunks_from_trace(
    trace: dict[str, Any],
    result: dict[str, Any],
) -> list[KnowledgeChunkMemory]:
    if trace.get("tool_name") != "search_knowledge_base":
        return []

    items = result.get("items")
    if not isinstance(items, list):
        return []

    chunks: list[KnowledgeChunkMemory] = []
    for item in items[:5]:
        if not isinstance(item, dict):
            continue
        chunks.append(
            KnowledgeChunkMemory(
                document_id=str(item.get("doc_id") or item.get("knowledge_id") or ""),
                chunk_id=item.get("chunk_id"),
                title=str(item.get("title") or ""),
                summary=str(item.get("chunk_text") or item.get("summary") or ""),
            )
        )
    return chunks


def is_explicit_user_correction(message: str) -> bool:
    text = message.strip()
    if not text:
        return False

    correction_markers = (
        "纠正一下",
        "更正一下",
        "准确地说",
        "我说的是",
        "不是这个意思",
        "不是这样",
        "而是",
        "请记住",
        "以后不要",
        "以后请",
    )
    return any(marker in text for marker in correction_markers) or is_style_only_correction(text)


def is_style_only_correction(message: str) -> bool:
    text = message.strip()
    if not text:
        return False

    style_markers = (
        "回答",
        "表达",
        "格式",
        "措辞",
        "括号",
        "标题",
        "称呼",
    )
    correction_markers = (
        "不要",
        "不需要",
        "不用",
        "改成",
        "写成",
        "请用",
    )
    return (
        any(marker in text for marker in style_markers)
        and any(marker in text for marker in correction_markers)
    )


def update_chat_memory_after_reply(
    session_id: str,
    resolution: dict[str, Any] | None,
    payload: ChatRequestPayload,
    reply: str,
    tool_results: list[dict[str, Any]],
    tool_traces: list[dict[str, Any]],
) -> None:
    memory = CHAT_MEMORY_STORE.get_or_create(session_id)

    entity_memory = extract_entity_memory(resolution)
    if entity_memory is not None:
        memory.resolved_entity = entity_memory

    for trace, result in zip(tool_traces, tool_results):
        summary = str(
            trace.get("summary")
            or result.get("summary")
            or result.get("message")
            or ""
        ).strip()
        tool_name = str(trace.get("tool_name") or "")
        memory.recent_tools.append(
            ToolMemory(
                tool_name=tool_name,
                arguments=trace.get("arguments") or {},
                result_summary=summary[:300],
                expires_at=get_tool_memory_expiry(tool_name),
            )
        )
        memory.last_knowledge_chunks.extend(
            extract_knowledge_chunks_from_trace(trace, result)
        )

    if is_explicit_user_correction(payload.message):
        memory.user_corrections.append(
            UserCorrectionMemory(
                original="",
                corrected=payload.message.strip(),
            )
        )

    CHAT_MEMORY_STORE.save(memory)


def build_chat_evidence_meta(
    tool_results: list[dict[str, Any]],
) -> dict[str, Any]:
    evidence_items: list[dict[str, Any]] = []

    for result in tool_results:
        if not isinstance(result, dict):
            continue

        evidence = result.get("_evidence")
        if not isinstance(evidence, dict):
            continue

        evidence_items.append(
            {
                "evidence_id": str(
                    evidence.get("evidence_id") or ""
                ),
                "tool_name": str(
                    evidence.get("tool_name") or ""
                ),
                "status": str(
                    evidence.get("status") or ""
                ),
                "observed_at": evidence.get(
                    "observed_at"
                ),
                "expires_at": evidence.get(
                    "expires_at"
                ),
            }
        )

    status_by_mode = {
        "off": "disabled",
        "observe": "observe_evidence_only",
        "single_pass": "single_pass_fallback",
    }
    status = status_by_mode.get(
        CHAT_RESPONSE_GUARD_MODE,
        "observe_evidence_only",
    )

    return {
        "status": status,
        "mode": CHAT_RESPONSE_GUARD_MODE,
        "claims": [],
        "guard": {
            "claims": [],
            "accepted_count": 0,
            "rejected_count": 0,
        },
        "evidence_count": len(evidence_items),
        "evidence": evidence_items,
        "rendering": {
            "status": "draft_preserved",
        },
    }


def build_single_pass_claim_instruction() -> str:
    return (
        "你正在执行受证据约束的最终回答。"
        "如果现有工具结果仍不足以回答用户问题，"
        "继续调用合适的查询工具；"
        f"当 {CLAIM_RESPONSE_TOOL_NAME} 工具可用且证据已经足够时，"
        "禁止直接输出自然语言答案，必须单独调用该工具。"
        "fact 必须引用工具结果 _evidence.evidence_id，"
        "field_path 必须相对于该证据的 data 字段填写，"
        "数字事实必须填写 expected_value。"
        "hypothesis 必须明确使用可能、推测等非确定表达；"
        "recommendation 和 unknown 可以不引用证据。"
    )


def with_claim_response_tool(
    tool_specs: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    if any(
        str((item.get("function") or {}).get("name") or "")
        == CLAIM_RESPONSE_TOOL_NAME
        for item in tool_specs
    ):
        return tool_specs

    return [*tool_specs, CLAIM_RESPONSE_TOOL_SPEC]


def should_require_claim_response(
    tool_results: list[dict[str, Any]],
) -> bool:
    """Only live operational evidence requires strict claim output."""

    evidence_tool_names: set[str] = set()

    for result in tool_results:
        if not isinstance(result, dict):
            continue
        evidence = result.get("_evidence")
        if not isinstance(evidence, dict):
            continue
        tool_name = str(
            evidence.get("tool_name") or ""
        ).strip()
        if tool_name:
            evidence_tool_names.add(tool_name)

    return any(
        tool_name != KNOWLEDGE_TOOL_NAME
        for tool_name in evidence_tool_names
    )


def finalize_single_pass_claims(
    raw_arguments: Any,
    tool_results: list[dict[str, Any]],
) -> tuple[str, dict[str, Any]]:
    claim_meta = build_chat_evidence_meta(
        tool_results
    )

    try:
        arguments = parse_tool_arguments(
            raw_arguments
        )
        raw_claims = arguments.get("claims")
        if not isinstance(raw_claims, list):
            raise ValueError("claims must be an array")

        valid_claims: list[Claim] = []
        invalid_claim_errors: list[str] = []
        for index, raw_claim in enumerate(raw_claims):
            try:
                valid_claims.append(
                    Claim.model_validate(raw_claim)
                )
            except Exception as exc:
                invalid_claim_errors.append(
                    f"claims[{index}]: {exc}"
                )

        if not valid_claims:
            raise ValueError(
                "no valid claims in response"
            )

        envelope = ClaimEnvelope(
            claims=valid_claims
        )
        guard_result = validate_claims(
            envelope=envelope,
            tool_results=tool_results,
        )
        final_text = render_guarded_response(
            guard_result
        ).strip()
    except Exception as exc:
        claim_meta.update(
            {
                "status": "failed",
                "mode": "single_pass",
                "error": str(exc),
                "rendering": {
                    "status": "failed",
                    "reason": (
                        "single_pass_claim_validation_failed"
                    ),
                },
            }
        )
        return (
            "当前证据不足，暂时无法形成"
            "经过验证的确定结论。",
            claim_meta,
        )

    claim_meta.update(
        {
            "status": "validated",
            "mode": "single_pass",
            "claims": envelope.model_dump(
                mode="json"
            )["claims"],
            "guard": guard_result.model_dump(
                mode="json"
            ),
            "rendering": {
                "status": "rendered",
            },
            "invalid_claim_count": len(
                invalid_claim_errors
            ),
            "invalid_claim_errors": (
                invalid_claim_errors
            ),
        }
    )

    if not final_text:
        claim_meta["rendering"] = {
            "status": "failed",
            "reason": "empty_rendered_text",
        }
        final_text = (
            "当前证据不足，暂时无法形成"
            "经过验证的确定结论。"
        )

    return final_text, claim_meta


def compile_chat_claims(
    draft: str,
    tool_results: list[dict[str, Any]],
) -> tuple[dict[str, Any], dict[str, Any]]:
    has_evidence = any(
        isinstance(result.get("_evidence"), dict)
        for result in tool_results
        if isinstance(result, dict)
    )

    if not has_evidence:
        return {
            "status": "not_applicable",
            "claims": [],
            "guard": {
                "claims": [],
                "accepted_count": 0,
                "rejected_count": 0,
            },
        }, empty_usage()

    try:
        envelope, usage = compile_claims(
            draft=draft,
            tool_results=tool_results,
            model_caller=call_model_raw,
        )

        guard_result = validate_claims(
            envelope=envelope,
            tool_results=tool_results,
        )
    except Exception as exc:
        return {
            "status": "failed",
            "claims": [],
            "guard": {
                "claims": [],
                "accepted_count": 0,
                "rejected_count": 0,
            },
            "error": str(exc),
        }, empty_usage()

    return {
        "status": "validated",
        "claims": envelope.model_dump(
            mode="json"
        )["claims"],
        "guard": guard_result.model_dump(
            mode="json"
        ),
    }, usage


def finalize_chat_run(
    draft: str,
    used_tools: list[str],
    tool_traces: list[dict[str, Any]],
    tool_results: list[dict[str, Any]],
    session_usage: dict[str, Any],
) -> tuple[
    str,
    list[str],
    list[dict[str, Any]],
    dict[str, Any],
    dict[str, Any],
]:
    if CHAT_RESPONSE_GUARD_MODE in {
        "off",
        "observe",
        "single_pass",
    }:
        claim_meta = build_chat_evidence_meta(
            tool_results
        )
        if CHAT_RESPONSE_GUARD_MODE == "single_pass":
            if should_require_claim_response(
                tool_results
            ):
                claim_meta["rendering"] = {
                    "status": "draft_preserved",
                    "reason": "response_tool_not_used",
                }
            else:
                claim_meta["status"] = "not_applicable"
                claim_meta["rendering"] = {
                    "status": "draft_preserved",
                    "reason": (
                        "no_live_operational_evidence"
                    ),
                }
        return (
            draft,
            used_tools,
            tool_traces,
            dict(session_usage),
            claim_meta,
        )

    claim_meta, claim_usage = compile_chat_claims(
        draft,
        tool_results,
    )

    final_text = draft
    compilation_status = claim_meta.get("status")

    if compilation_status == "validated":
        try:
            guard_result = (
                ResponseGuardResult.model_validate(
                    claim_meta.get("guard") or {}
                )
            )

            if (
                not guard_result.claims
                or guard_result.accepted_count <= 0
            ):
                claim_meta["rendering"] = {
                    "status": "fallback_to_draft",
                    "reason": (
                        "empty_or_all_rejected_claims"
                    ),
                }
            else:
                rendered = render_guarded_response(
                    guard_result
                ).strip()

                if rendered:
                    final_text = rendered
                    claim_meta["rendering"] = {
                        "status": "rendered",
                    }
                else:
                    claim_meta["rendering"] = {
                        "status": "fallback_to_draft",
                        "reason": "empty_rendered_text",
                    }

        except Exception as exc:
            claim_meta["rendering"] = {
                "status": "fallback_to_draft",
                "reason": "renderer_failed",
                "error": str(exc),
            }

    elif compilation_status == "failed":
        claim_meta["rendering"] = {
            "status": "fallback_to_draft",
            "reason": "claim_compilation_failed",
        }

    else:

        claim_meta["rendering"] = {
            "status": "not_applicable",
        }

    return (
        final_text,
        used_tools,
        tool_traces,
        merge_usage(
            session_usage,
            claim_usage,
        ),
        claim_meta,
    )


def run_chat_with_tools(
    payload: ChatRequestPayload,
    resolution: dict[str, Any] | None = None,
) -> tuple[
    str,
    list[str],
    list[dict[str, Any]],
    dict[str, Any],
    dict[str, Any],
]:
    session_id = get_chat_session_id(payload)
    memory_context = build_memory_block_for_chat(
        session_id,
        resolution,
    )
    messages = build_chat_messages(
        payload,
        resolution=resolution,
        memory_context=memory_context,
    )
    used_tools: list[str] = []
    tool_traces: list[dict[str, Any]] = []
    tool_results: list[dict[str, Any]] = []
    total_tool_calls = 0
    coarse_tool_calls = 0
    companion_tool_calls = 0
    session_usage = empty_usage()
    prefetched_tool_names: set[str] = set()

    if should_prefetch_business_success_context(payload):
        prefetch_tool_name = BUSINESS_SUCCESS_CONTEXT_TOOL_NAME
        prefetch_tool_id = "prefetch-business-success-context"
        prefetch_arguments: dict[str, Any] = {}
        prefetch_result, _ = execute_chat_tool_call(
            prefetch_tool_name,
            prefetch_arguments,
            tool_call_id=prefetch_tool_id,
        )
        prefetched_tool_names.add(prefetch_tool_name)
        used_tools.append(prefetch_tool_name)
        total_tool_calls += 1

        messages.insert(
            2,
            {
                "role": "system",
                "content": (
                    "应用层已预取以下权威购买成功率与技术SLI口径。"
                    "回答必须区分购买成功率KPI、30天技术可用性SLI和错误预算；"
                    "如需调查原因，仍可继续调用其他工具。\n"
                    f"tool={prefetch_tool_name}\n"
                    f"result={json.dumps(prefetch_result, ensure_ascii=False)}"
                ),
            },
        )

        if isinstance(prefetch_result, dict):
            prefetch_trace = prefetch_result.get("trace")
            if isinstance(prefetch_trace, dict):
                tool_traces.append(
                    {
                        **prefetch_trace,
                        "tool_call_id": prefetch_tool_id,
                        "prefetched": True,
                    }
                )
            tool_results.append(prefetch_result)

    for round_index in range(MAX_TOOL_ROUNDS):
        available_tools = (
            choose_initial_tool_specs(payload)
            if round_index == 0
            else choose_followup_tool_specs(payload)
        )
        for prefetched_tool_name in prefetched_tool_names:
            available_tools = without_tool_spec(
                available_tools,
                prefetched_tool_name,
            )

        if (
            CHAT_RESPONSE_GUARD_MODE == "single_pass"
            and should_require_claim_response(
                tool_results
            )
        ):
            available_tools = with_claim_response_tool(
                available_tools
            )

        model_result = call_model_raw(
            messages,
            tools=available_tools,
            tool_choice="auto",
        )
        assistant_message = model_result["message"]
        session_usage = merge_usage(session_usage, model_result.get("usage"))
        tool_calls = extract_tool_calls(assistant_message)
        requested_tool_names = {
            str((item.get("function") or {}).get("name") or "")
            for item in tool_calls
            if isinstance(item, dict)
        }
        content = normalize_message_content(assistant_message.get("content", ""))

        if (
            len(tool_calls) == 1
            and str(
                (
                    tool_calls[0].get("function")
                    or {}
                ).get("name")
                or ""
            )
            == CLAIM_RESPONSE_TOOL_NAME
        ):
            function_block = (
                tool_calls[0].get("function")
                or {}
            )
            final_text, claim_meta = (
                finalize_single_pass_claims(
                    function_block.get("arguments"),
                    tool_results,
                )
            )
            update_chat_memory_after_reply(
                session_id,
                resolution,
                payload,
                final_text,
                tool_results,
                tool_traces,
            )
            return (
                final_text,
                used_tools,
                tool_traces,
                session_usage,
                claim_meta,
            )

        if not tool_calls:
            if content:
                update_chat_memory_after_reply(
                    session_id,
                    resolution,
                    payload,
                    content,
                    tool_results,
                    tool_traces,
                )
                return finalize_chat_run(
                    content,
                    used_tools,
                    tool_traces,
                    tool_results,
                    session_usage,
                )
            raise RuntimeError(f"model returned neither content nor tool calls: {assistant_message}")

        if total_tool_calls >= MAX_TOOL_CALLS_PER_CHAT:
            final_text, final_usage = force_final_answer(messages)
            update_chat_memory_after_reply(
                session_id,
                resolution,
                payload,
                final_text,
                tool_results,
                tool_traces,
            )
            return finalize_chat_run(
                final_text,
                used_tools,
                tool_traces,
                tool_results,
                merge_usage(session_usage, final_usage),
            )

        messages.append(
            {
                "role": "assistant",
                "content": assistant_message.get("content") or "",
                "tool_calls": tool_calls,
            }
        )

        for index, tool_call in enumerate(tool_calls):
            if total_tool_calls >= MAX_TOOL_CALLS_PER_CHAT:
                for leftover in tool_calls[index:]:
                    append_tool_skip_result(
                        messages,
                        leftover,
                        "tool call budget exceeded",
                    )
                final_text, final_usage = force_final_answer(messages)
                update_chat_memory_after_reply(
                    session_id,
                    resolution,
                    payload,
                    final_text,
                    tool_results,
                    tool_traces,
                )
                return finalize_chat_run(
                    final_text,
                    used_tools,
                    tool_traces,
                    tool_results,
                    merge_usage(session_usage, final_usage),
                )

            function_block = tool_call.get("function") or {}
            tool_name = function_block.get("name", "")
            tool_id = tool_call.get("id", "")
            arguments = parse_tool_arguments(function_block.get("arguments"))

            if tool_name == CLAIM_RESPONSE_TOOL_NAME:
                append_tool_skip_result(
                    messages,
                    tool_call,
                    "response tool must be called alone",
                )
                continue

            if tool_name in COARSE_TOOL_NAMES:
                if coarse_tool_calls >= MAX_COARSE_TOOL_CALLS and total_tool_calls > 0:
                    append_tool_skip_result(
                        messages,
                        tool_call,
                        "coarse tool budget exceeded",
                    )
                    continue
                coarse_tool_calls += 1

            result, _ = execute_chat_tool_call(
                tool_name,
                arguments,
                tool_call_id=str(tool_id),
            )
            used_tools.append(tool_name)
            total_tool_calls += 1

            if isinstance(result, dict):
                trace = result.get("trace")
                if isinstance(trace, dict):
                    tool_traces.append(
                        {
                            **trace,
                            "tool_call_id": tool_id,
                        }
                    )
                    tool_results.append(result)

            if (
                isinstance(result, dict)
                and should_run_reliability_knowledge_companion(
                    tool_name,
                    requested_tool_names,
                    companion_tool_calls,
                )
            ):
                knowledge_result = attach_reliability_knowledge_context(
                    payload,
                    result,
                )
                companion_tool_calls += 1
                used_tools.append(KNOWLEDGE_TOOL_NAME)
                knowledge_trace = knowledge_result.get("trace")
                if isinstance(knowledge_trace, dict):
                    tool_traces.append(
                        {
                            **knowledge_trace,
                            "tool_call_id": f"{tool_id}:companion",
                            "companion_of": tool_id,
                        }
                    )
                    tool_results.append(knowledge_result)

            messages.append(
                {
                    "role": "tool",
                    "tool_call_id": tool_id,
                    "name": tool_name,
                    "content": json.dumps(result, ensure_ascii=False),
                }
            )

        if total_tool_calls >= MAX_TOOL_CALLS_PER_CHAT:
            final_text, final_usage = force_final_answer(messages)
            update_chat_memory_after_reply(
                session_id,
                resolution,
                payload,
                final_text,
                tool_results,
                tool_traces,
            )
            return finalize_chat_run(
                final_text,
                used_tools,
                tool_traces,
                tool_results,
                merge_usage(session_usage, final_usage),
            )

    final_text, final_usage = force_final_answer(messages)
    update_chat_memory_after_reply(
        session_id,
        resolution,
        payload,
        final_text,
        tool_results,
        tool_traces,
    )
    return finalize_chat_run(
        final_text,
        used_tools,
        tool_traces,
        tool_results,
        merge_usage(session_usage, final_usage),
    )


def resolve_chat_entities(payload: ChatRequestPayload) -> dict[str, Any]:
    try:
        return ENTITY_RESOLVER.resolve(payload.message)
    except Exception as exc:
        return {
            "status": "resolver_error",
            "query": payload.message,
            "error": str(exc),
            "matches": [],
        }


def select_pending_entity(
    message: str,
    candidates: list[dict[str, Any]],
) -> dict[str, Any] | None:
    text = message.strip().lower()
    if not text or not candidates:
        return None

    ordinal_markers = {
        0: ("第一个", "第1个", "第 1 个", "1号", "一号"),
        1: ("第二个", "第2个", "第 2 个", "2号", "二号"),
    }
    for index, markers in ordinal_markers.items():
        if index < len(candidates) and any(marker in text for marker in markers):
            return candidates[index]

    plane_markers = {
        "business": ("业务的", "业务侧"),
        "platform": ("平台的", "平台侧"),
    }
    for plane, markers in plane_markers.items():
        if any(marker in text for marker in markers):
            plane_matches = [
                item
                for item in candidates
                if str(item.get("plane") or "") == plane
            ]
            if len(plane_matches) == 1:
                return plane_matches[0]

    namespace_matches = [
        item
        for item in candidates
        if item.get("namespace")
        and str(item["namespace"]).lower() in text
    ]
    if len(namespace_matches) == 1:
        return namespace_matches[0]

    matched: list[dict[str, Any]] = []
    for candidate in candidates:
        selectors = [
            str(candidate.get("entity_id") or ""),
            str(candidate.get("name") or ""),
        ]
        if any(selector and selector.lower() in text for selector in selectors):
            matched.append(candidate)

    unique_matches = {
        str(item.get("entity_id") or ""): item
        for item in matched
        if item.get("entity_id")
    }
    if len(unique_matches) == 1:
        return next(iter(unique_matches.values()))
    return None


def is_pending_clarification_cancelled(message: str) -> bool:
    text = message.strip()
    return any(
        marker in text
        for marker in (
            "算了",
            "不用查了",
            "先不查",
            "取消查询",
            "换个问题",
        )
    )


def apply_pending_entity_clarification(
    session_id: str,
    payload: ChatRequestPayload,
    resolution: dict[str, Any],
) -> dict[str, Any]:
    memory = CHAT_MEMORY_STORE.get_or_create(session_id)
    pending = memory.pending_entity_clarification

    if pending is not None:
        if pending.expires_at and pending.expires_at <= datetime.now(timezone.utc):
            memory.pending_entity_clarification = None
            CHAT_MEMORY_STORE.save(memory)
            pending = None
        elif is_pending_clarification_cancelled(payload.message):
            memory.pending_entity_clarification = None
            CHAT_MEMORY_STORE.save(memory)
            return resolution
        else:
            selected = select_pending_entity(payload.message, pending.candidates)
            if selected is not None:
                selected_resolution = {
                    "status": "resolved",
                    "query": payload.message,
                    "entity": selected,
                    "matches": [selected],
                }
                memory.pending_entity_clarification = None
                memory.resolved_entity = extract_entity_memory(
                    selected_resolution
                )
                CHAT_MEMORY_STORE.save(memory)
                return selected_resolution

            if resolution.get("status") == "resolved":
                memory.pending_entity_clarification = None
                CHAT_MEMORY_STORE.save(memory)
                return resolution

            return {
                "status": "pending_clarification",
                "query": payload.message,
                "original_query": pending.original_query,
                "matches": pending.candidates,
            }

    if resolution.get("status") == "ambiguous":
        candidates = resolution.get("matches") or []
        memory.resolved_entity = None
        memory.pending_entity_clarification = PendingEntityClarification(
            original_query=payload.message.strip(),
            candidates=candidates,
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
        )
        CHAT_MEMORY_STORE.save(memory)
        return resolution

    return resolution


def build_ambiguous_entity_reply(resolution: dict[str, Any]) -> str:
    matches = resolution.get("matches", [])
    if not isinstance(matches, list):
        matches = []

    if not matches:
        return "你的问题里可能包含一个未明确的对象，但我暂时无法完成识别，请补充更具体的组件名称、命名空间或节点名称。"

    if resolution.get("status") == "pending_clarification":
        lines = [
            "上一轮对象仍未明确，因此我暂不查询或分析。",
            "仍需从以下候选对象中选择：",
        ]
    else:
        lines = [
            "我先不直接分析，因为你提到的对象存在歧义。",
            "当前匹配到的候选对象有：",
        ]

    for item in matches:
        name = str(item.get("name", ""))
        kind = str(item.get("kind", ""))
        namespace = item.get("namespace")
        plane = str(item.get("plane", ""))
        notes = str(item.get("notes", ""))

        desc_parts = [f"{name}（{kind}"]
        if namespace:
            desc_parts.append(f" / namespace={namespace}")
        if plane:
            desc_parts.append(f" / plane={plane}")
        desc_parts.append("）")
        line = "".join(desc_parts)

        if notes:
            line += f"：{notes}"

        lines.append(f"- {line}")

    lines.append("请你明确指定其中一个对象，我再继续查询和分析。")
    return "\n".join(lines)


@app.get("/healthz")
def healthz() -> dict[str, Any]:
    return {
        "status": "ok",
        "service": "agent-executor",
        "model_configured": is_model_configured(),
        "model_name": MODEL_NAME or "",
        "model_base": MODEL_API_BASE or "",
    }


@app.get("/")
def root() -> dict[str, str]:
    return {
        "message": "AIOps Agent Executor is running",
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


@app.get("/api/executor/topology/summary")
def executor_topology_summary(
    target_namespace: str | None = Query(default=None),
    target_app: str | None = Query(default=None),
) -> dict[str, Any]:
    try:
        return get_cluster_topology_summary(
            target_namespace=target_namespace,
            target_app=target_app,
        )
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"topology summary failed: {exc}")


@app.get("/api/executor/topology")
def executor_topology(
    target_namespace: str | None = Query(default=None),
    target_app: str | None = Query(default=None),
) -> dict[str, Any]:
    try:
        return get_cluster_topology(
            target_namespace=target_namespace,
            target_app=target_app,
        )
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"topology query failed: {exc}")


@app.post("/api/analyze/inspection")
def analyze_inspection(payload: InspectionPayload) -> dict[str, Any]:
    if not is_model_configured():
        raise HTTPException(
            status_code=503,
            detail="LLM is not configured. Please set MODEL_API_BASE, MODEL_API_KEY and MODEL_NAME.",
        )

    messages = build_inspection_messages(payload)

    try:
        analysis_text = call_model(messages)
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    return {
        "inspection_id": payload.inspection_id,
        "source_status": payload.status,
        "analysis_type": "inspection_summary",
        "analysis_text": analysis_text,
        "used_inputs": {
            "mode": "inspection",
            "steps": len(payload.steps),
            "has_change_events": bool(payload.result.related_changes),
            "has_cluster_summary": bool(payload.result.cluster_summary),
            "model_name": MODEL_NAME,
        },
    }


@app.get("/api/token-usage/today")
def token_usage_today() -> dict[str, Any]:
    main_today = get_bucket_today("main")
    main_all_time = get_bucket_all_time("main")

    return {
        "date": today_date(),
        "main_agent": int(main_today.get("total_tokens") or 0),
        "main_agent_total": int(main_all_time.get("total_tokens") or 0),
        "vector_agent": 0,
        "vector_agent_total": 0,
        "total": int(main_today.get("total_tokens") or 0),
        "total_all_time": int(main_all_time.get("total_tokens") or 0),
        "estimated": bool(main_today.get("estimated")) or bool(main_all_time.get("estimated")),
        "calls": int(main_today.get("calls") or 0),
        "buckets": {
            "main_today": main_today,
            "main_all_time": main_all_time,
        },
    }


@app.get("/api/metrics/business-success-context")
def business_success_context(
    namespace: str | None = Query(default=None),
) -> dict[str, Any]:
    """Expose the same purchase-rate and technical-SLI policy used by tools."""
    return get_business_success_rate_context(namespace=namespace)


@app.get("/api/memory/chat/{session_id}")
def get_chat_memory(session_id: str) -> dict[str, Any]:
    normalized_session_id = session_id.strip()
    if not normalized_session_id:
        raise HTTPException(status_code=400, detail="session_id is empty")

    memory = CHAT_MEMORY_STORE.get(normalized_session_id)
    if memory is None:
        raise HTTPException(status_code=404, detail="chat memory not found")

    return {
        "session_id": normalized_session_id,
        "memory": memory.model_dump(mode="json"),
        "context_preview": build_chat_memory_context(memory),
    }


@app.post("/api/chat/sessions")
def create_chat_session(
    payload: CreateChatSessionPayload,
) -> dict[str, Any]:
    session = CHAT_SESSION_STORE.create_session(
        title=payload.title,
    )
    return {
        "session": session.model_dump(mode="json"),
    }


@app.get("/api/chat/sessions")
def list_chat_sessions(
    limit: int = Query(default=50, ge=1, le=100),
) -> dict[str, Any]:
    sessions = CHAT_SESSION_STORE.list_sessions(limit=limit)
    return {
        "total": len(sessions),
        "sessions": [
            session.model_dump(mode="json")
            for session in sessions
        ],
    }


@app.get("/api/chat/sessions/{session_id}")
def get_chat_session(
    session_id: str,
    message_limit: int = Query(default=200, ge=1, le=500),
) -> dict[str, Any]:
    session = CHAT_SESSION_STORE.get_session(session_id)
    if session is None:
        raise HTTPException(
            status_code=404,
            detail="chat session not found",
        )

    messages = CHAT_SESSION_STORE.list_messages(
        session_id,
        limit=message_limit,
    )

    return {
        "session": session.model_dump(mode="json"),
        "messages": [
            message.model_dump(mode="json")
            for message in messages
        ],
    }


@app.delete("/api/chat/sessions/{session_id}")
def delete_chat_session(
    session_id: str,
) -> dict[str, Any]:
    normalized_session_id = session_id.strip()
    if not normalized_session_id:
        raise HTTPException(
            status_code=400,
            detail="session_id is empty",
        )

    session_deleted = CHAT_SESSION_STORE.delete_session(
        normalized_session_id
    )
    memory_deleted = CHAT_MEMORY_STORE.delete(
        normalized_session_id
    )
    summary_deleted = CHAT_SUMMARY_STORE.delete(
        normalized_session_id
    )

    if not (
        session_deleted
        or memory_deleted
        or summary_deleted
    ):
        raise HTTPException(
            status_code=404,
            detail="chat session not found",
        )

    return {
        "success": True,
        "session_id": normalized_session_id,
        "session_deleted": session_deleted,
        "memory_deleted": memory_deleted,
        "summary_deleted": summary_deleted,
    }


@app.post("/api/alerts/webhook")
def receive_alertmanager_webhook(
    payload: dict[str, Any],
    background_tasks: BackgroundTasks,
    request: Request,
) -> dict[str, Any]:
    try:
        webhook_source = (
            request.client.host
            if request.client
            else ""
        )
        result = ingest_alertmanager_payload(
            payload,
            INCIDENT_MEMORY_STORE,
            webhook_source=webhook_source,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail=f"incident persistence failed: {exc}",
        ) from exc

    queued_incident_ids: list[str] = []
    completed_incident_ids: list[str] = []
    for item in result.items:
        if item.status != "accepted" or not item.incident_id:
            continue

        incident = INCIDENT_MEMORY_STORE.get(item.incident_id)
        if incident is None:
            continue

        if incident.status == "firing":
            _, queued = queue_incident_first_round(
                item.incident_id,
                background_tasks,
            )
            if queued:
                queued_incident_ids.append(item.incident_id)
        elif incident.status == "resolved":
            recovery = INCIDENT_ANALYSIS_RUNNER.complete_if_resolved(
                incident.incident_id
            )
            if recovery.get("completed"):
                completed_incident_ids.append(incident.incident_id)

    return {
        "success": True,
        "result": result.model_dump(mode="json"),
        "analysis_queued": queued_incident_ids,
        "analysis_completed_on_resolve": completed_incident_ids,
    }


@app.get("/api/incidents")
def list_incidents(
    status: Literal["firing", "resolved"] | None = Query(default=None),
    fingerprint: str | None = Query(default=None),
    alert_name: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
) -> dict[str, Any]:
    incidents = INCIDENT_MEMORY_STORE.list_incidents(
        status=status,
        fingerprint=(fingerprint or "").strip() or None,
        alert_name=(alert_name or "").strip() or None,
        limit=limit,
    )
    return {
        "total": len(incidents),
        "incidents": [
            incident.model_dump(mode="json")
            for incident in incidents
        ],
    }


@app.get("/api/incidents/{incident_id}")
def get_incident(incident_id: str) -> dict[str, Any]:
    normalized_incident_id = incident_id.strip()
    if not normalized_incident_id:
        raise HTTPException(status_code=400, detail="incident_id is empty")

    incident = INCIDENT_MEMORY_STORE.get(normalized_incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="incident not found")

    return {
        "incident": incident.model_dump(mode="json"),
        "historical_occurrence_count": (
            INCIDENT_MEMORY_STORE.count_occurrences(incident.fingerprint)
        ),
    }


@app.get("/api/incidents/{incident_id}/events")
def get_incident_events(
    incident_id: str,
    limit: int = Query(default=500, ge=1, le=1000),
) -> dict[str, Any]:
    normalized_incident_id = incident_id.strip()
    incident = INCIDENT_MEMORY_STORE.get(normalized_incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="incident not found")

    events = INCIDENT_MEMORY_STORE.list_events(
        normalized_incident_id,
        limit=limit,
    )
    return {
        "incident_id": normalized_incident_id,
        "total": len(events),
        "events": [
            event.model_dump(mode="json")
            for event in events
        ],
    }


@app.get("/api/incidents/{incident_id}/analysis")
def get_incident_analysis(incident_id: str) -> dict[str, Any]:
    normalized_id = (incident_id or "").strip()

    incident = INCIDENT_MEMORY_STORE.get(normalized_id)
    if incident is None:
        raise HTTPException(
            status_code=404,
            detail="incident not found",
        )

    analysis = INCIDENT_ANALYSIS_STORE.get_run_by_incident(normalized_id)

    if analysis is None:
        return {
            "incident_id": normalized_id,
            "analysis": None,
            "events": [],
            "message": "analysis not started",
        }

    events = INCIDENT_ANALYSIS_STORE.list_events(
        analysis.analysis_id,
        limit=500,
    )

    return {
        "incident_id": normalized_id,
        "analysis": analysis.model_dump(mode="json"),
        "events": [
            event.model_dump(mode="json")
            for event in events
        ],
    }


@app.get("/api/incident-analyses/{analysis_id}/events")
def get_incident_analysis_events(
    analysis_id: str,
    after_sequence: int = Query(default=0, ge=0),
    limit: int = Query(default=200, ge=1, le=500),
) -> dict[str, Any]:
    normalized_id = (analysis_id or "").strip()

    analysis = INCIDENT_ANALYSIS_STORE.get_run(normalized_id)
    if analysis is None:
        raise HTTPException(
            status_code=404,
            detail="analysis not found",
        )

    events = INCIDENT_ANALYSIS_STORE.list_events(
        normalized_id,
        after_sequence=after_sequence,
        limit=limit,
    )

    return {
        "analysis_id": normalized_id,
        "status": analysis.status,
        "current_round": analysis.current_round,
        "next_recheck_at": (
            analysis.next_recheck_at.isoformat()
            if analysis.next_recheck_at
            else None
        ),
        "total": len(events),
        "events": [
            event.model_dump(mode="json")
            for event in events
        ],
        "last_sequence": (
            events[-1].sequence_no
            if events
            else after_sequence
        ),
    }


@app.post(
    "/api/incidents/{incident_id}/analysis/start",
    status_code=202,
)
def start_incident_analysis(
    incident_id: str,
    background_tasks: BackgroundTasks,
) -> dict[str, Any]:
    normalized_id = (incident_id or "").strip()

    started, queued = queue_incident_first_round(
        normalized_id,
        background_tasks,
    )

    if started.get("error") == "incident not found":
        raise HTTPException(
            status_code=404,
            detail="incident not found",
        )

    if started.get("error"):
        raise HTTPException(
            status_code=400,
            detail=started["error"],
        )

    if queued:
        return {
            **started,
            "accepted": True,
            "message": "first analysis round queued",
        }

    return {
        **started,
        "accepted": False,
        "message": "analysis was not queued again",
    }


@app.get("/api/incidents/{incident_id}/remediations")
def list_incident_remediations(incident_id: str) -> dict[str, Any]:
    normalized_id = (incident_id or "").strip()
    if INCIDENT_MEMORY_STORE.get(normalized_id) is None:
        raise HTTPException(status_code=404, detail="incident not found")
    actions = REMEDIATION_STORE.list_for_incident(normalized_id)
    return {
        "incident_id": normalized_id,
        "total": len(actions),
        "actions": [action.model_dump(mode="json") for action in actions],
    }


@app.post("/api/remediations/{action_id}/approve")
def approve_remediation(
    action_id: str,
    payload: RemediationDecisionPayload,
) -> dict[str, Any]:
    normalized_action_id = (action_id or "").strip()
    pending = REMEDIATION_STORE.get(normalized_action_id)
    if pending is None:
        raise HTTPException(status_code=404, detail="remediation action not found")
    if pending.status != "pending_approval":
        raise HTTPException(
            status_code=409,
            detail=f"remediation action is already {pending.status}",
        )

    incident = INCIDENT_MEMORY_STORE.get(pending.incident_id)
    if incident is None or incident.status != "firing":
        try:
            REMEDIATION_STORE.reject(
                normalized_action_id,
                decided_by="system",
                comment="incident is no longer firing",
            )
        except ValueError:
            pass
        raise HTTPException(status_code=409, detail="incident is no longer firing")

    requested_at = parse_utc_datetime(pending.requested_at)
    if requested_at is None or utc_now() - requested_at > timedelta(minutes=30):
        try:
            REMEDIATION_STORE.reject(
                normalized_action_id,
                decided_by="system",
                comment="approval request expired",
            )
        except ValueError:
            pass
        raise HTTPException(status_code=409, detail="approval request expired")

    try:
        action = REMEDIATION_STORE.claim_approval(
            normalized_action_id,
            decided_by=payload.decided_by.strip(),
            comment=payload.comment.strip(),
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    run = INCIDENT_ANALYSIS_STORE.get_run(action.analysis_id)
    if run is None:
        REMEDIATION_STORE.finish(
            action.action_id,
            succeeded=False,
            result={"error": "analysis run not found"},
        )
        raise HTTPException(status_code=409, detail="analysis run not found")

    is_scale = action.action_type == "scale_deployment"
    if is_scale:
        approval_title = "扩容申请已批准"
        approval_content = (
            f"{payload.decided_by.strip()} 已批准将 "
            f"`{action.namespace}/{action.target_name}` 从 "
            f"{action.current_replicas} 个副本扩到 {action.target_replicas} 个副本。"
        )
    else:
        approval_title = "回滚申请已批准"
        approval_content = (
            f"{payload.decided_by.strip()} 已批准将 "
            f"`{action.namespace}/{action.target_name}` 从 "
            f"`{action.current_image}` 回滚到 `{action.target_image}`。"
        )

    INCIDENT_ANALYSIS_STORE.append_event(
        run.analysis_id,
        "approval_result",
        approval_title,
        content_md=approval_content,
        round_index=run.current_round,
        evidence={
            "action_id": action.action_id,
            "action_type": action.action_type,
            "decision": "approved",
            "decided_by": payload.decided_by.strip(),
        },
    )

    try:
        execution_result = (
            execute_scale_deployment(action)
            if is_scale
            else execute_rollback_deployment(action)
        )
    except Exception as exc:
        failed = REMEDIATION_STORE.finish(
            action.action_id,
            succeeded=False,
            result={"error": str(exc)},
        )
        INCIDENT_ANALYSIS_STORE.append_event(
            run.analysis_id,
            "action_result",
            "扩容执行失败" if is_scale else "回滚执行失败",
            content_md=(
                f"受控处置工具未能修改 `{action.namespace}/{action.target_name}`：{exc}。"
                "系统不会盲目重复执行，将保留证据并继续调查。"
            ),
            round_index=run.current_round,
            evidence={
                "action_id": action.action_id,
                "action_type": action.action_type,
                "status": "failed",
                "error": str(exc),
            },
        )
        INCIDENT_ANALYSIS_STORE.update_run(
            run.analysis_id,
            status="waiting_recheck",
            phase="collecting_evidence",
            next_recheck_at=utc_now() + timedelta(minutes=1),
        )
        raise HTTPException(status_code=503, detail=failed.result.get("error")) from exc

    completed = REMEDIATION_STORE.finish(
        action.action_id,
        succeeded=True,
        result=execution_result,
    )
    if is_scale:
        result_title = "已提交 Deployment 扩容"
        result_content = (
            f"受控扩容工具已将 `{action.namespace}/{action.target_name}` 从 "
            f"{action.current_replicas} 个副本调整为 {action.target_replicas} 个副本。"
            "这只表示 Kubernetes 已接受变更，不代表容量问题已经解决。"
            "系统将在一分钟后检查新副本 Ready 状态、实际流量、吞吐和响应延迟；"
            "若指标没有改善，将重新检查瓶颈位置，不会继续盲目扩容。"
        )
    else:
        result_title = "已提交 Deployment 回滚"
        result_content = (
            f"受控回滚工具已将 `{action.namespace}/{action.target_name}` 的 "
            f"`{action.container_name}` 容器目标镜像改为 `{action.target_image}`。"
            "这只表示 Kubernetes 已接受变更，不代表业务已经恢复。"
            "系统将在一分钟后先检查版本和 Pod，再结合日志、成功订单和技术可用性继续观察；"
            "5 分钟滚动指标可能存在恢复滞后。"
        )
    INCIDENT_ANALYSIS_STORE.append_event(
        run.analysis_id,
        "action_result",
        result_title,
        content_md=result_content,
        round_index=run.current_round,
        evidence={
            "action_id": action.action_id,
            "action_type": action.action_type,
            "status": completed.status,
            **execution_result,
        },
    )
    updated = INCIDENT_ANALYSIS_STORE.update_run(
        run.analysis_id,
        status="waiting_recheck",
        phase="collecting_evidence",
        next_recheck_at=utc_now() + timedelta(minutes=1),
    )
    return {
        "action": completed.model_dump(mode="json"),
        "analysis_status": updated.status,
        "next_recheck_at": (
            updated.next_recheck_at.isoformat()
            if updated.next_recheck_at
            else None
        ),
    }


@app.post("/api/remediations/{action_id}/reject")
def reject_remediation(
    action_id: str,
    payload: RemediationDecisionPayload,
) -> dict[str, Any]:
    try:
        action = REMEDIATION_STORE.reject(
            (action_id or "").strip(),
            decided_by=payload.decided_by.strip(),
            comment=payload.comment.strip(),
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    run = INCIDENT_ANALYSIS_STORE.get_run(action.analysis_id)
    if run is not None:
        is_scale = action.action_type == "scale_deployment"
        if is_scale:
            rejection_title = "扩容申请已拒绝"
            rejection_content = (
                f"{payload.decided_by.strip()} 已拒绝将 "
                f"`{action.namespace}/{action.target_name}` 从 "
                f"{action.current_replicas} 个副本扩到 {action.target_replicas} 个副本。"
                "系统不会执行该动作，将继续保留告警证据。"
            )
        else:
            rejection_title = "回滚申请已拒绝"
            rejection_content = (
                f"{payload.decided_by.strip()} 已拒绝将 "
                f"`{action.namespace}/{action.target_name}` 回滚到 "
                f"`{action.target_image}`。系统不会执行该动作，将继续保留告警证据。"
            )
        INCIDENT_ANALYSIS_STORE.append_event(
            run.analysis_id,
            "approval_result",
            rejection_title,
            content_md=rejection_content,
            round_index=run.current_round,
            evidence={
                "action_id": action.action_id,
                "action_type": action.action_type,
                "decision": "rejected",
                "decided_by": payload.decided_by.strip(),
            },
        )
        INCIDENT_ANALYSIS_STORE.update_run(
            run.analysis_id,
            status="waiting_recheck",
            phase="collecting_evidence",
            next_recheck_at=utc_now() + timedelta(minutes=5),
        )
    return {"action": action.model_dump(mode="json")}


@app.post("/api/chat")
def chat(
    payload: ChatRequestPayload,
    background_tasks: BackgroundTasks,
) -> dict[str, Any]:
    if not payload.message.strip():
        raise HTTPException(status_code=400, detail="message is empty")

    session_id = get_chat_session_id(payload)

    save_chat_message(
        session_id,
        "user",
        payload.message.strip(),
        {
            "mode": payload.mode,
        },
    )

    resolution = resolve_chat_entities(payload)
    resolution = apply_pending_entity_clarification(
        session_id,
        payload,
        resolution,
    )

    if resolution.get("status") in {
        "ambiguous",
        "pending_clarification",
    }:
        reply = build_ambiguous_entity_reply(resolution)
        if (
            resolution.get("status") == "pending_clarification"
            and is_style_only_correction(payload.message)
        ):
            memory = CHAT_MEMORY_STORE.get_or_create(session_id)
            memory.user_corrections.append(
                UserCorrectionMemory(
                    original="",
                    corrected=payload.message.strip(),
                )
            )
            CHAT_MEMORY_STORE.save(memory)
            reply = (
                "收到，这是一条回答格式纠正，我已记录；本轮不会调用工具。\n\n"
                f"{reply}"
            )

        save_chat_message(
            session_id,
            "assistant",
            reply,
            {
                "entity_status": resolution.get("status"),
                "used_tools": [],
                "tool_traces": [],
            },
        )
        background_tasks.add_task(
            update_chat_summary_in_background,
            session_id,
        )

        return {
            "message_type": "agent_reply",
            "content": reply,
            "meta": {
                "mode": payload.mode,
                "used_tools": [],
                "tool_traces": [],
                "entity_resolution": resolution,
                "current_incident": payload.current_incident,
                "model_name": MODEL_NAME,
                "token_usage": empty_usage(),
                "session_id": session_id,
            },
        }

    if not is_model_configured():
        raise HTTPException(
            status_code=503,
            detail=(
                "LLM is not configured. Please set MODEL_API_BASE, "
                "MODEL_API_KEY and MODEL_NAME."
            ),
        )

    try:
        (
            reply,
            used_tools,
            tool_traces,
            token_usage,
            claim_compilation,
        ) = run_chat_with_tools(
            payload,
            resolution=resolution,
        )
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    entity = resolution.get("entity") or {}

    save_chat_message(
        session_id,
        "assistant",
        reply,
        {
            "used_tools": used_tools,
            "tool_traces": tool_traces,
            "entity_status": resolution.get("status", ""),
            "entity_id": entity.get("entity_id", ""),
            "token_usage": token_usage,
            "claim_compilation": claim_compilation,
        },
    )
    background_tasks.add_task(
        update_chat_summary_in_background,
        session_id,
    )

    return {
        "message_type": "agent_reply",
        "content": reply,
        "meta": {
            "mode": payload.mode,
            "used_tools": used_tools,
            "tool_traces": tool_traces,
            "entity_resolution": resolution,
            "current_incident": payload.current_incident,
            "model_name": MODEL_NAME,
            "token_usage": token_usage,
            "session_id": session_id,
            "claim_compilation": claim_compilation,
        },
    }
