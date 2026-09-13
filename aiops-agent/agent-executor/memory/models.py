from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def ensure_utc(value: datetime) -> datetime:
    """Reject ambiguous datetimes and normalize aware values to UTC."""
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("datetime must include an explicit timezone")
    return value.astimezone(timezone.utc)


def parse_utc_datetime(value: datetime | str | None) -> datetime | None:
    if value is None or isinstance(value, datetime):
        return ensure_utc(value) if value is not None else None

    text = value.strip()
    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"
    return ensure_utc(datetime.fromisoformat(text))


def format_utc_datetime(value: datetime | None) -> str | None:
    if value is None:
        return None
    return ensure_utc(value).isoformat().replace("+00:00", "Z")


class EntityMemory(BaseModel):
    entity_id: str = ""
    entity_type: str = ""
    name: str = ""
    namespace: str | None = None
    plane: str = ""


class ToolMemory(BaseModel):
    tool_name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    result_summary: str = ""
    called_at: datetime = Field(default_factory=utc_now)
    expires_at: datetime | None = None


class FactMemory(BaseModel):
    content: str
    source: str = "tool"
    created_at: datetime = Field(default_factory=utc_now)


class KnowledgeChunkMemory(BaseModel):
    document_id: str
    chunk_id: str | None = None
    title: str = ""
    summary: str = ""
    retrieved_at: datetime = Field(default_factory=utc_now)


class UserCorrectionMemory(BaseModel):
    original: str = ""
    corrected: str
    created_at: datetime = Field(default_factory=utc_now)


class PendingEntityClarification(BaseModel):
    original_query: str = ""
    candidates: list[dict[str, Any]] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=utc_now)
    expires_at: datetime | None = None


class ChatMemory(BaseModel):
    session_id: str
    resolved_entity: EntityMemory | None = None
    pending_entity_clarification: PendingEntityClarification | None = None
    recent_tools: list[ToolMemory] = Field(default_factory=list)
    confirmed_facts: list[FactMemory] = Field(default_factory=list)
    open_questions: list[str] = Field(default_factory=list)
    last_knowledge_chunks: list[KnowledgeChunkMemory] = Field(default_factory=list)
    user_corrections: list[UserCorrectionMemory] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)


class ChatSummary(BaseModel):
    session_id: str
    conversation_goal: str = ""
    discussion_summary: str = ""
    confirmed_context: list[str] = Field(default_factory=list)
    hypotheses: list[str] = Field(default_factory=list)
    open_questions: list[str] = Field(default_factory=list)
    user_corrections: list[str] = Field(default_factory=list)

    summarized_until_message_id: int = 0
    summarized_message_count: int = 0
    summary_version: int = 1

    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)


class ChatSession(BaseModel):
    session_id: str
    title: str = "新对话"
    status: str = "active"
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)


class ChatMessage(BaseModel):
    message_id: int | None = None
    session_id: str
    role: str
    content: str
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utc_now)


class ChatMemoryLimits(BaseModel):
    recent_tools: int = 10
    confirmed_facts: int = 20
    open_questions: int = 10
    last_knowledge_chunks: int = 5
    user_corrections: int = 10


class Incident(BaseModel):
    incident_id: str
    fingerprint: str
    occurrence_index: int = Field(ge=1)
    alert_name: str
    severity: str = ""
    status: Literal["firing", "resolved"]
    namespace: str = ""
    target: str = ""
    generator_url: str = ""
    source: str = ""
    receiver: str = ""
    webhook_source: str = ""
    started_at: datetime | None = None
    last_seen_at: datetime | None = None
    last_received_at: datetime | None = None
    resolved_at: datetime | None = None
    resolved_at_source: Literal[
        "",
        "alertmanager",
        "received_at_fallback",
    ] = ""
    notification_count: int = Field(default=0, ge=0)
    unmatched_start: bool = False
    labels: dict[str, str] = Field(default_factory=dict)
    annotations: dict[str, str] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)

    @field_validator(
        "started_at",
        "last_seen_at",
        "last_received_at",
        "resolved_at",
        "created_at",
        "updated_at",
        mode="before",
    )
    @classmethod
    def validate_utc_fields(cls, value: datetime | str | None) -> datetime | None:
        return parse_utc_datetime(value)


class IncidentEvent(BaseModel):
    event_id: str
    incident_id: str
    event_type: Literal[
        "incident_created",
        "firing_notification",
        "resolved_notification",
    ]
    received_at: datetime
    alert_status: Literal["firing", "resolved"]
    starts_at: datetime | None = None
    ends_at: datetime | None = None
    group_key: str = ""
    receiver: str = ""
    generator_url: str = ""
    source: str = ""
    webhook_source: str = ""
    labels: dict[str, str] = Field(default_factory=dict)
    annotations: dict[str, str] = Field(default_factory=dict)

    @field_validator(
        "received_at",
        "starts_at",
        "ends_at",
        mode="before",
    )
    @classmethod
    def validate_utc_fields(cls, value: datetime | str | None) -> datetime | None:
        return parse_utc_datetime(value)


class IncidentRecordResult(BaseModel):
    incident: Incident
    created: bool
    event_type: Literal[
        "firing_notification",
        "resolved_notification",
    ]
