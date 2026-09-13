from __future__ import annotations

from pydantic import BaseModel, Field, model_validator


class SloPolicy(BaseModel):
    name: str
    target: float = Field(gt=0.0, lt=1.0)
    minimum_requests: int = Field(default=20, ge=1)
    excluded_results: set[str] = Field(default_factory=set)
    technical_failure_results: set[str] = Field(default_factory=set)
    watch_burn_rate: float = Field(default=1.0, gt=0.0)
    high_risk_burn_rate: float = Field(default=6.0, gt=0.0)

    @model_validator(mode="after")
    def validate_policy(self) -> "SloPolicy":
        overlap = self.excluded_results & self.technical_failure_results
        if overlap:
            labels = ", ".join(sorted(overlap))
            raise ValueError(f"results cannot be both excluded and failures: {labels}")
        if self.high_risk_burn_rate <= self.watch_burn_rate:
            raise ValueError("high_risk_burn_rate must exceed watch_burn_rate")
        return self


DEFAULT_SECKILL_SLO_POLICY = SloPolicy(
    name="seckill_order_processing_availability",
    target=0.999,
    minimum_requests=20,
    excluded_results={
        "activity_closed",
        "user_not_found",
        "duplicate_request",
        "sold_out",
        "duplicate_order",
    },
    technical_failure_results={
        "system_error",
        "mysql_sold_out",
        "timeout",
        "dependency_error",
        "queue_error",
    },
    watch_burn_rate=1.0,
    high_risk_burn_rate=6.0,
)
