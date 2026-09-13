from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

from alerting.classifier import (
    AlertClassification,
    ClassificationConfidence,
)
from memory.models import parse_utc_datetime, utc_now


AnalysisRunStatus = Literal[
    "pending",
    "running",
    "waiting_approval",
    "waiting_recheck",
    "monitoring",
    "completed",
    "failed",
    "cancelled",
]

AnalysisPhase = Literal[
    "received",
    "collecting_evidence",
    "classified",
    "monitoring",
    "resolved",
    "closed",
]

AnalysisEventType = Literal[
    "analysis_started",
    "classification",
    "skill_selected",
    "assessment",
    "tool_call",
    "tool_result",
    "approval_requested",
    "approval_result",
    "action_result",
    "recovery_check",
    "conclusion",
    "error",
]


class IncidentAnalysisRun(BaseModel):
    analysis_id: str
    incident_id: str
    status: AnalysisRunStatus = "pending"
    phase: AnalysisPhase = "received"
    classification: AlertClassification = "unknown"
    classification_confidence: ClassificationConfidence = "low"
    classification_reason: str = ""
    classified_at: datetime | None = None
    current_round: int = Field(default=1, ge=1)
    started_at: datetime | None = None
    next_recheck_at: datetime | None = None
    completed_at: datetime | None = None
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)

    @field_validator(
        "classified_at",
        "started_at",
        "next_recheck_at",
        "completed_at",
        "created_at",
        "updated_at",
        mode="before",
    )
    @classmethod
    def validate_utc_fields(cls, value: datetime | str | None) -> datetime | None:
        return parse_utc_datetime(value)


class IncidentAnalysisEvent(BaseModel):
    event_id: str
    analysis_id: str
    incident_id: str
    sequence_no: int = Field(ge=1)
    round_index: int = Field(default=1, ge=1)
    event_type: AnalysisEventType
    title: str
    content_md: str = ""
    tool_name: str = ""
    tool_call_id: str = ""
    evidence: dict[str, Any] | list[Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utc_now)

    @field_validator("created_at", mode="before")
    @classmethod
    def validate_utc_fields(cls, value: datetime | str | None) -> datetime | None:
        return parse_utc_datetime(value)
