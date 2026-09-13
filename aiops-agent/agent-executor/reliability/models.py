from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


EvaluationStatus = Literal["no_data", "insufficient_traffic", "evaluated"]
ReliabilityStatus = Literal["unknown", "healthy", "watch", "high_risk"]
AssessmentStatus = Literal["no_data", "insufficient_data", "evaluated"]


class SloEvaluation(BaseModel):
    slo_name: str
    window: str
    status: EvaluationStatus
    reliability_status: ReliabilityStatus
    slo_target: float = Field(ge=0.0, le=1.0)
    raw_requests: float = Field(ge=0.0)
    valid_requests: float = Field(ge=0.0)
    excluded_requests: float = Field(ge=0.0)
    technical_failures: float = Field(ge=0.0)
    sli: float | None = Field(default=None, ge=0.0, le=1.0)
    error_rate: float | None = Field(default=None, ge=0.0, le=1.0)
    burn_rate: float | None = Field(default=None, ge=0.0)
    minimum_requests: int = Field(ge=1)
    distribution: dict[str, float] = Field(default_factory=dict)


class ReliabilityAssessment(BaseModel):
    service: str
    slo_name: str
    status: AssessmentStatus
    reliability_status: ReliabilityStatus
    slo_target: float = Field(ge=0.0, le=1.0)
    compliance: SloEvaluation
    short_window: SloEvaluation
    long_window: SloEvaluation
    error_budget_remaining_percent: float | None = Field(
        default=None,
        ge=0.0,
        le=100.0,
    )
    operational_constraints: list[str] = Field(default_factory=list)
    recommended_action: str
    recheck_conditions: list[str] = Field(default_factory=list)
