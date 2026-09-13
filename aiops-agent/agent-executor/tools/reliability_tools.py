from __future__ import annotations

from typing import Any

from reliability import DEFAULT_SECKILL_SLO_POLICY, evaluate_reliability

from .metrics_tools import (
    DEFAULT_BUSINESS_METRIC,
    DEFAULT_NAMESPACE,
    _build_distribution,
    _now_text,
    _promql_quote,
)


COMPLIANCE_WINDOW = "30d"
SHORT_WINDOW = "5m"
LONG_WINDOW = "1h"
SERVICE_NAME = "biz-gateway"


def _query_text(metric_name: str, namespace: str, window: str) -> str:
    selector = f'{{namespace="{_promql_quote(namespace)}"}}' if namespace else ""
    return f"sum by (result) (increase({metric_name}{selector}[{window}]))"


def get_seckill_reliability() -> dict[str, Any]:
    windows = (COMPLIANCE_WINDOW, SHORT_WINDOW, LONG_WINDOW)
    distributions: dict[str, dict[str, float]] = {}
    queries = {
        window: _query_text(DEFAULT_BUSINESS_METRIC, DEFAULT_NAMESPACE, window)
        for window in windows
    }

    try:
        for window in windows:
            distributions[window] = _build_distribution(
                DEFAULT_BUSINESS_METRIC,
                DEFAULT_NAMESPACE,
                window,
            )
    except RuntimeError as exc:
        return {
            "generated_at": _now_text(),
            "error": str(exc),
            "summary": "Unable to evaluate reliability because Prometheus data retrieval failed.",
            "queries": queries,
        }

    assessment = evaluate_reliability(
        service=SERVICE_NAME,
        compliance_distribution=distributions[COMPLIANCE_WINDOW],
        short_distribution=distributions[SHORT_WINDOW],
        long_distribution=distributions[LONG_WINDOW],
        compliance_window=COMPLIANCE_WINDOW,
        short_window=SHORT_WINDOW,
        long_window=LONG_WINDOW,
        policy=DEFAULT_SECKILL_SLO_POLICY,
    )
    result = assessment.model_dump(mode="json")
    result.update(
        {
            "generated_at": _now_text(),
            "queries": queries,
            "summary": (
                f"{SERVICE_NAME} reliability status is "
                f"{assessment.reliability_status}; assessment data status is "
                f"{assessment.status}."
            ),
        }
    )
    return result


RELIABILITY_TOOLS: list[dict[str, Any]] = [
    {
        "name": "get_seckill_reliability",
        "label": "SLO 可靠性",
        "spec": {
            "type": "function",
            "function": {
                "name": "get_seckill_reliability",
                "description": (
                    "Evaluate the seckill order-processing SLO using fixed project policy. "
                    "Use this for reliability status, error budget, burn rate, or release-risk "
                    "questions about biz-gateway. It queries 30d, 5m, and 1h Prometheus windows "
                    "and returns deterministic results. Do not use it for business conversion "
                    "rate or inventory questions. SLO targets and thresholds cannot be changed "
                    "by the model."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {},
                },
            },
        },
        "handler": get_seckill_reliability,
    }
]
