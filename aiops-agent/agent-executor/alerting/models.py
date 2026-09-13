from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, field_validator

from memory.models import parse_utc_datetime


class NormalizedAlert(BaseModel):
    fingerprint: str
    alert_name: str
    status: Literal["firing", "resolved"]
    severity: str = ""
    namespace: str = ""
    target: str = ""
    starts_at: datetime | None = None
    ends_at: datetime | None = None
    group_key: str = ""
    receiver: str = ""
    generator_url: str = ""
    source: str = ""
    webhook_source: str = ""
    labels: dict[str, str] = Field(default_factory=dict)
    annotations: dict[str, str] = Field(default_factory=dict)

    @field_validator("starts_at", "ends_at", mode="before")
    @classmethod
    def validate_utc_fields(cls, value: datetime | str | None) -> datetime | None:
        return parse_utc_datetime(value)


class AlertIngestionItem(BaseModel):
    index: int
    status: Literal["accepted", "rejected"]
    incident_id: str = ""
    fingerprint: str = ""
    alert_name: str = ""
    created: bool = False
    error: str = ""


class AlertIngestionResult(BaseModel):
    received_at: datetime
    total: int = Field(ge=0)
    accepted: int = Field(ge=0)
    rejected: int = Field(ge=0)
    items: list[AlertIngestionItem] = Field(default_factory=list)

    @field_validator("received_at", mode="before")
    @classmethod
    def validate_received_at(cls, value: datetime | str) -> datetime:
        parsed = parse_utc_datetime(value)
        if parsed is None:
            raise ValueError("received_at is required")
        return parsed
