from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator


EvidenceStatus = Literal[
    "success",
    "no_data",
    "failed",
    "timeout",
    "skipped",
]

ClaimType = Literal[
    "fact",
    "hypothesis",
    "recommendation",
    "unknown",
]


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class EvidenceRecord(BaseModel):
    """一次工具调用产生的证据。"""

    evidence_id: str = Field(min_length=1)
    source: str = "tool"
    tool_name: str = Field(min_length=1)
    tool_call_id: str = ""
    status: EvidenceStatus

    arguments: dict[str, Any] = Field(
        default_factory=dict
    )

    observed_at: datetime = Field(
        default_factory=utc_now
    )
    expires_at: datetime

    summary: str = ""
    query_used: str = ""
    data: Any = None
    error: str = ""

    @model_validator(mode="after")
    def validate_time_range(self) -> "EvidenceRecord":
        if self.expires_at < self.observed_at:
            raise ValueError(
                "expires_at cannot be earlier than observed_at"
            )
        return self

    def is_fresh(
        self,
        now: datetime | None = None,
    ) -> bool:
        current_time = now or utc_now()
        return (
            self.status == "success"
            and current_time <= self.expires_at
        )


class EvidenceRef(BaseModel):
    """Claim 对证据及其字段的引用。"""

    evidence_id: str = Field(min_length=1)
    field_path: str = ""
    expected_value: Any = None
    unit: str = ""


class Claim(BaseModel):
    """模型生成的一条结构化结论。"""

    text: str = Field(min_length=1)
    type: ClaimType
    evidence_refs: list[EvidenceRef] = Field(
        default_factory=list
    )


class ClaimEnvelope(BaseModel):
    """模型最终输出的结构化结论集合。"""

    claims: list[Claim] = Field(
        default_factory=list
    )
