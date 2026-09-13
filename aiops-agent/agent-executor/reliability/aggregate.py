from __future__ import annotations

from collections.abc import Mapping

from .calculator import evaluate_slo_window
from .models import ReliabilityAssessment, SloEvaluation
from .policy import DEFAULT_SECKILL_SLO_POLICY, SloPolicy


def _remaining_error_budget(
    compliance: SloEvaluation,
    policy: SloPolicy,
) -> float | None:
    if compliance.status != "evaluated":
        return None

    allowed_failures = compliance.valid_requests * (1.0 - policy.target)
    if allowed_failures <= 0:
        return None

    remaining = (
        (allowed_failures - compliance.technical_failures)
        / allowed_failures
        * 100.0
    )
    return round(max(0.0, min(100.0, remaining)), 2)


def _current_risk(
    short_window: SloEvaluation,
    long_window: SloEvaluation,
    policy: SloPolicy,
) -> str:
    if short_window.status != "evaluated" or long_window.status != "evaluated":
        return "unknown"

    short_burn = short_window.burn_rate or 0.0
    long_burn = long_window.burn_rate or 0.0
    if (
        short_burn >= policy.high_risk_burn_rate
        and long_burn >= policy.high_risk_burn_rate
    ):
        return "high_risk"
    if short_burn > policy.watch_burn_rate or long_burn > policy.watch_burn_rate:
        return "watch"
    return "healthy"


def _decision_fields(reliability_status: str) -> tuple[list[str], str, list[str]]:
    if reliability_status == "high_risk":
        return (
            ["avoid_nonessential_release", "require_small_canary"],
            "Pause nonessential releases and investigate current technical failures.",
            [
                "short_window_burn_rate_below_high_risk_threshold",
                "long_window_burn_rate_below_watch_threshold",
                "no_new_technical_failures",
            ],
        )
    if reliability_status == "watch":
        return (
            ["prefer_small_canary", "increase_observation"],
            "Use a small canary for necessary changes and continue observation.",
            [
                "long_window_burn_rate_at_or_below_one",
                "no_new_technical_failures",
            ],
        )
    if reliability_status == "healthy":
        return (
            ["normal_change_policy"],
            "Follow the normal change policy.",
            ["burn_rate_remains_at_or_below_one"],
        )
    return (
        ["require_more_data"],
        "Collect enough recent traffic before making a release-risk decision.",
        ["short_and_long_windows_have_sufficient_traffic"],
    )


def evaluate_reliability(
    *,
    service: str,
    compliance_distribution: Mapping[str, float | int],
    short_distribution: Mapping[str, float | int],
    long_distribution: Mapping[str, float | int],
    compliance_window: str = "30d",
    short_window: str = "5m",
    long_window: str = "1h",
    policy: SloPolicy = DEFAULT_SECKILL_SLO_POLICY,
) -> ReliabilityAssessment:
    compliance = evaluate_slo_window(
        compliance_distribution,
        compliance_window,
        policy,
    )
    short_result = evaluate_slo_window(short_distribution, short_window, policy)
    long_result = evaluate_slo_window(long_distribution, long_window, policy)

    evaluations = (compliance, short_result, long_result)
    if all(item.status == "no_data" for item in evaluations):
        status = "no_data"
    elif all(item.status == "evaluated" for item in evaluations):
        status = "evaluated"
    else:
        status = "insufficient_data"

    reliability_status = _current_risk(short_result, long_result, policy)
    constraints, action, recheck = _decision_fields(reliability_status)

    return ReliabilityAssessment(
        service=service,
        slo_name=policy.name,
        status=status,
        reliability_status=reliability_status,
        slo_target=policy.target,
        compliance=compliance,
        short_window=short_result,
        long_window=long_result,
        error_budget_remaining_percent=_remaining_error_budget(compliance, policy),
        operational_constraints=constraints,
        recommended_action=action,
        recheck_conditions=recheck,
    )
