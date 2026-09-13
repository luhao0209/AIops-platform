from __future__ import annotations

import json
import os
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from memory.models import (
    ChatMessage,
    ChatSummary,
)


SUMMARY_MODEL_API_BASE = os.getenv(
    "SUMMARY_MODEL_API_BASE",
    "",
).rstrip("/")

SUMMARY_MODEL_API_KEY = os.getenv(
    "SUMMARY_MODEL_API_KEY",
    "",
)

SUMMARY_MODEL_NAME = os.getenv(
    "SUMMARY_MODEL_NAME",
    "deepseek-chat",
)

SUMMARY_MODEL_TIMEOUT = int(
    os.getenv("SUMMARY_MODEL_TIMEOUT", "30")
)

SUMMARY_MODEL_TEMPERATURE = float(
    os.getenv("SUMMARY_MODEL_TEMPERATURE", "0.1")
)


SUMMARY_SYSTEM_PROMPT = """
你是会话记忆压缩器，只负责压缩对话，不负责回答用户问题。

请把旧滚动摘要和新增对话合并为一份结构化摘要。

硬性要求：
1. 不得创造对话中没有出现的事实。
2. 不得把模型推断写入 confirmed_context。
3. 实时 CPU、内存、告警、Pod 状态等数值不要写入长期摘要。
4. 未证实判断放入 hypotheses。
5. 尚未解决的问题放入 open_questions。
6. 用户明确纠正的内容放入 user_corrections。
7. 保留项目对象、命名消歧和当前讨论目标。
8. 内容使用中文，保持简洁。
9. 只输出 JSON，不要输出 Markdown 或解释。

输出结构必须为：
{
  "conversation_goal": "",
  "discussion_summary": "",
  "confirmed_context": [],
  "hypotheses": [],
  "open_questions": [],
  "user_corrections": []
}
""".strip()


def is_summary_model_configured() -> bool:
    return bool(
        SUMMARY_MODEL_API_BASE
        and SUMMARY_MODEL_API_KEY
        and SUMMARY_MODEL_NAME
    )


def build_summary_messages(
    previous_summary: ChatSummary | None,
    new_messages: list[ChatMessage],
) -> list[dict[str, str]]:
    previous_payload: dict[str, Any]

    if previous_summary is None:
        previous_payload = {
            "conversation_goal": "",
            "discussion_summary": "",
            "confirmed_context": [],
            "hypotheses": [],
            "open_questions": [],
            "user_corrections": [],
        }
    else:
        previous_payload = {
            "conversation_goal": previous_summary.conversation_goal,
            "discussion_summary": previous_summary.discussion_summary,
            "confirmed_context": previous_summary.confirmed_context,
            "hypotheses": previous_summary.hypotheses,
            "open_questions": previous_summary.open_questions,
            "user_corrections": previous_summary.user_corrections,
        }

    message_payload = [
        {
            "message_id": message.message_id,
            "role": message.role,
            "content": message.content,
        }
        for message in new_messages
    ]

    user_payload = {
        "previous_summary": previous_payload,
        "new_messages": message_payload,
    }

    return [
        {
            "role": "system",
            "content": SUMMARY_SYSTEM_PROMPT,
        },
        {
            "role": "user",
            "content": json.dumps(
                user_payload,
                ensure_ascii=False,
            ),
        },
    ]


def _extract_json_object(content: str) -> dict[str, Any]:
    text = content.strip()

    if text.startswith("```"):
        lines = text.splitlines()

        if lines:
            lines = lines[1:]

        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]

        text = "\n".join(lines).strip()

    start = text.find("{")
    end = text.rfind("}")

    if start < 0 or end < start:
        raise RuntimeError(
            "summary model returned no JSON object"
        )

    payload = json.loads(text[start : end + 1])

    if not isinstance(payload, dict):
        raise RuntimeError(
            "summary model JSON is not an object"
        )

    return payload


def call_summary_model(
    messages: list[dict[str, str]],
) -> tuple[dict[str, Any], dict[str, Any]]:
    if not is_summary_model_configured():
        raise RuntimeError(
            "summary model is not configured"
        )

    request_payload = {
        "model": SUMMARY_MODEL_NAME,
        "messages": messages,
        "temperature": SUMMARY_MODEL_TEMPERATURE,
        "max_tokens": 1200,
        "response_format": {
            "type": "json_object",
        },
    }

    request = Request(
        f"{SUMMARY_MODEL_API_BASE}/chat/completions",
        data=json.dumps(
            request_payload,
            ensure_ascii=False,
        ).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {SUMMARY_MODEL_API_KEY}",
            "Content-Type": "application/json",
        },
        method="POST",
    )

    try:
        with urlopen(
            request,
            timeout=SUMMARY_MODEL_TIMEOUT,
        ) as response:
            response_payload = json.loads(
                response.read().decode("utf-8")
            )
    except HTTPError as exc:
        detail = exc.read().decode(
            "utf-8",
            errors="ignore",
        )
        raise RuntimeError(
            f"summary model HTTP {exc.code}: {detail}"
        ) from exc
    except URLError as exc:
        raise RuntimeError(
            f"summary model unavailable: {exc}"
        ) from exc

    choices = response_payload.get("choices") or []

    if not choices:
        raise RuntimeError(
            "summary model returned no choices"
        )

    message = choices[0].get("message") or {}
    content = message.get("content") or ""

    if not isinstance(content, str) or not content.strip():
        raise RuntimeError(
            "summary model returned empty content"
        )

    return (
        _extract_json_object(content),
        response_payload.get("usage") or {},
    )


def generate_chat_summary(
    session_id: str,
    previous_summary: ChatSummary | None,
    new_messages: list[ChatMessage],
) -> tuple[ChatSummary, dict[str, Any]]:
    if not new_messages:
        raise ValueError(
            "new_messages must not be empty"
        )

    summary_payload, usage = call_summary_model(
        build_summary_messages(
            previous_summary,
            new_messages,
        )
    )

    message_ids = [
        message.message_id
        for message in new_messages
        if message.message_id is not None
    ]

    if not message_ids:
        raise ValueError(
            "new_messages have no message_id"
        )

    previous_count = (
        previous_summary.summarized_message_count
        if previous_summary
        else 0
    )

    summary_data = {
        **summary_payload,
        "session_id": session_id,
        "summarized_until_message_id": max(message_ids),
        "summarized_message_count": (
            previous_count + len(new_messages)
        ),
        "summary_version": (
            previous_summary.summary_version
            if previous_summary
            else 1
        ),
    }

    if previous_summary is not None:
        summary_data["created_at"] = (
            previous_summary.created_at
        )

    summary = ChatSummary.model_validate(summary_data)

    return summary, usage
