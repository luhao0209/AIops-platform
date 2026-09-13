from __future__ import annotations

from datetime import datetime, timezone

from memory.models import (
    ChatMemory,
    ChatSummary,
    ToolMemory,
)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def is_tool_memory_fresh(tool_memory: ToolMemory) -> bool:
    if tool_memory.expires_at is None:
        return False
    return tool_memory.expires_at > _now()


def build_chat_memory_context(
    memory: ChatMemory,
    *,
    max_tools: int = 5,
    max_facts: int = 10,
    max_questions: int = 5,
    max_chunks: int = 3,
    max_corrections: int = 5,
) -> str:
    lines: list[str] = []

    if memory.resolved_entity and memory.resolved_entity.name:
        entity = memory.resolved_entity
        namespace = entity.namespace or "-"
        plane = entity.plane or "-"
        lines.append(
            f"当前对象：{entity.name} | entity_id={entity.entity_id or '-'} | "
            f"type={entity.entity_type or '-'} | namespace={namespace} | plane={plane}"
        )

    fresh_tools = [item for item in memory.recent_tools if is_tool_memory_fresh(item)]
    if fresh_tools:
        lines.append("最近工具结果：")
        for item in fresh_tools[-max_tools:]:
            summary = item.result_summary.strip() or "无摘要"
            lines.append(f"- {item.tool_name}：{summary}")

    if memory.confirmed_facts:
        lines.append("已确认事实：")
        for fact in memory.confirmed_facts[-max_facts:]:
            source = fact.source or "unknown"
            lines.append(f"- {fact.content}（来源：{source}）")

    if memory.open_questions:
        lines.append("待确认项：")
        for question in memory.open_questions[-max_questions:]:
            lines.append(f"- {question}")

    if memory.last_knowledge_chunks:
        lines.append("最近知识库命中：")
        for chunk in memory.last_knowledge_chunks[-max_chunks:]:
            title = chunk.title or chunk.document_id
            summary = chunk.summary.strip() or "无摘要"
            chunk_id = chunk.chunk_id or "-"
            lines.append(f"- {title} | chunk={chunk_id} | {summary}")

    if memory.user_corrections:
        lines.append("用户纠正：")
        for correction in memory.user_corrections[-max_corrections:]:
            if correction.original:
                lines.append(
                    f"- 原说法：{correction.original} -> 修正为：{correction.corrected}"
                )
            else:
                lines.append(f"- 修正：{correction.corrected}")

    if not lines:
        return "暂无可用会话记忆。"

    lines.append(
        "注意：会话记忆仅用于保持上下文；涉及实时系统状态时，应根据时效性决定是否重新调用工具。"
    )
    return "\n".join(lines)


def build_chat_summary_context(
    summary: ChatSummary | None,
) -> str:
    if summary is None:
        return ""

    lines: list[str] = []

    if summary.conversation_goal:
        lines.append(f"当前对话目标：{summary.conversation_goal}")

    if summary.discussion_summary:
        lines.append("历史讨论摘要：")
        lines.append(summary.discussion_summary)

    if summary.confirmed_context:
        lines.append("已确认的稳定背景：")
        for item in summary.confirmed_context:
            lines.append(f"- {item}")

    if summary.hypotheses:
        lines.append("尚未证实的历史判断：")
        for item in summary.hypotheses:
            lines.append(f"- {item}")

    if summary.open_questions:
        lines.append("尚未解决的问题：")
        for item in summary.open_questions:
            lines.append(f"- {item}")

    if summary.user_corrections:
        lines.append("用户明确纠正：")
        for item in summary.user_corrections:
            lines.append(f"- {item}")

    if not lines:
        return ""

    lines.append(
        "注意：滚动摘要只用于保持对话连续性；"
        "实时指标、告警、日志和资源状态仍应根据"
        "有效期决定是否重新调用工具。"
    )

    return "\n".join(lines)
