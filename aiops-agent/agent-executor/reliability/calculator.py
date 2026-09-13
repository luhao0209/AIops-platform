from __future__ import annotations

import math
from collections.abc import Mapping

from .models import SloEvaluation
from .policy import DEFAULT_SECKILL_SLO_POLICY, SloPolicy


def _normalize_distribution(distribution: Mapping[str, float | int]) -> dict[str, float]:
    normalized: dict[str, float] = {}
    for result, value in distribution.items():
        label = str(result).strip()
        number = float(value)
        if not label:
            raise ValueError("result label cannot be empty")
        if not math.isfinite(number) or number < 0:
            raise ValueError(f"invalid count for result {label}: {value}")
        normalized[label] = normalized.get(label, 0.0) + number
    return normalized


def _risk_level(burn_rate: float, policy: SloPolicy) -> str:
    if burn_rate >= policy.high_risk_burn_rate:
        return "high_risk"
    if burn_rate > policy.watch_burn_rate:
        return "watch"
    return "healthy"


def evaluate_slo_window(
    distribution: Mapping[str, float | int],
    window: str,
    policy: SloPolicy = DEFAULT_SECKILL_SLO_POLICY,
) -> SloEvaluation:
    normalized = _normalize_distribution(distribution)
    raw_requests = sum(normalized.values())
    excluded_requests = sum(
        normalized.get(result, 0.0)
        for result in policy.excluded_results
    )
    valid_requests = raw_requests - excluded_requests
    technical_failures = sum(
        normalized.get(result, 0.0)
        for result in policy.technical_failure_results
    )

    common = {
        "slo_name": policy.name,
        "window": window,
        "slo_target": policy.target,
        "raw_requests": raw_requests,
        "valid_requests": valid_requests,
        "excluded_requests": excluded_requests,
        "technical_failures": technical_failures,
        "minimum_requests": policy.minimum_requests,
        "distribution": normalized,
    }

    if valid_requests <= 0:
        return SloEvaluation(
            status="no_data",
            reliability_status="unknown",
            **common,
        )

    if technical_failures > valid_requests:
        raise ValueError("technical failures cannot exceed valid requests")

    error_rate = technical_failures / valid_requests
    sli = 1.0 - error_rate
    allowed_error_rate = 1.0 - policy.target
    burn_rate = error_rate / allowed_error_rate

    if valid_requests < policy.minimum_requests:
        status = "insufficient_traffic"
        reliability_status = "unknown"
    else:
        status = "evaluated"
        reliability_status = _risk_level(burn_rate, policy)

    return SloEvaluation(
        status=status,
        reliability_status=reliability_status,
        sli=round(sli, 8),
        error_rate=round(error_rate, 8),
        burn_rate=round(burn_rate, 4),
        **common,
    )
