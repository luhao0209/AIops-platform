from __future__ import annotations

import json
import math
import os
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen


PROMETHEUS_BASE_URL = os.getenv(
    "PROMETHEUS_BASE_URL",
    "http://prometheus.monitoring.svc.cluster.local:9090",
).rstrip("/")

PROMETHEUS_TIMEOUT = int(os.getenv("PROMETHEUS_TIMEOUT", "15"))
DEFAULT_NAMESPACE = os.getenv("AIOPS_BUSINESS_NAMESPACE", "data-services")
DEFAULT_BUSINESS_METRIC = os.getenv("AIOPS_BUSINESS_METRIC", "seckill_order_total")
DEFAULT_SUCCESS_LABEL = os.getenv("AIOPS_SUCCESS_LABEL", "success")
DEFAULT_BUSINESS_WINDOW = os.getenv("AIOPS_BUSINESS_WINDOW", "15m")
BUSINESS_SLI_WINDOW = "30d"
BUSINESS_SLI_SHORT_WINDOW = "5m"
TECHNICAL_SLO_TARGET_PERCENT = 99.9
DEFAULT_BUSINESS_EXCLUDED_RESULTS = {
    item.strip()
    for item in os.getenv(
        "AIOPS_BUSINESS_EXCLUDED_RESULTS",
        "duplicate_order,duplicate_request",
    ).split(",")
    if item.strip()
}
TECHNICAL_SLI_EXCLUDED_RESULTS = {
    "activity_closed",
    "user_not_found",
    "duplicate_request",
    "sold_out",
    "duplicate_order",
}
TECHNICAL_FAILURE_RESULTS = {
    "system_error",
    "mysql_sold_out",
    "timeout",
    "dependency_error",
    "queue_error",
}
DEFAULT_SERVICE_REQUEST_METRIC = os.getenv("AIOPS_SERVICE_REQUEST_METRIC", DEFAULT_BUSINESS_METRIC)
DEFAULT_SERVICE_LATENCY_BUCKET_METRIC = os.getenv("AIOPS_SERVICE_LATENCY_BUCKET_METRIC", "")
DEFAULT_NODE_FILESYSTEM_METRIC = os.getenv("AIOPS_NODE_FILESYSTEM_METRIC", "node_filesystem_avail_bytes")
DEFAULT_NODE_FILESYSTEM_SIZE_METRIC = os.getenv("AIOPS_NODE_FILESYSTEM_SIZE_METRIC", "node_filesystem_size_bytes")
DEFAULT_NODE_MEMORY_AVAILABLE_METRIC = os.getenv("AIOPS_NODE_MEMORY_AVAILABLE_METRIC", "node_memory_MemAvailable_bytes")
DEFAULT_NODE_MEMORY_TOTAL_METRIC = os.getenv("AIOPS_NODE_MEMORY_TOTAL_METRIC", "node_memory_MemTotal_bytes")
VALID_NAMESPACES = ["aiops", "data-services", "monitoring"]

METRIC_DICTIONARY: dict[str, str] = {
    "请求量": "http_requests_total",
    "秒杀订单结果": "seckill_order_total",
    "节点 CPU": "node_cpu_seconds_total",
    "节点内存": "node_memory_MemAvailable_bytes",
    "容器 CPU": "container_cpu_usage_seconds_total",
    "容器内存": "container_memory_working_set_bytes",
    "Pod 重启次数": "kube_pod_container_status_restarts_total",
}

METRIC_DICTIONARY_TEXT = "\n".join(
    [f"- {label}: {metric}" for label, metric in METRIC_DICTIONARY.items()]
)


def _now_text() -> str:
    return datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S")


def _error_payload(message: str, **extra: Any) -> dict[str, Any]:
    payload = {"generated_at": _now_text(), "error": message}
    payload.update(extra)
    return payload


def _validate_namespace(namespace: str | None) -> tuple[str, dict[str, Any] | None]:
    normalized = (namespace or DEFAULT_NAMESPACE).strip()
    if normalized not in VALID_NAMESPACES:
        return normalized, _error_payload(
            "namespace not found",
            requested_namespace=normalized,
            valid_namespaces=VALID_NAMESPACES,
        )
    return normalized, None


def _prometheus_get(path: str) -> dict[str, Any]:
    url = f"{PROMETHEUS_BASE_URL}{path}"
    request = Request(url, method="GET")

    try:
        with urlopen(request, timeout=PROMETHEUS_TIMEOUT) as response:
            body = json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="ignore")
        raise RuntimeError(f"prometheus http error {exc.code}: {detail}") from exc
    except URLError as exc:
        raise RuntimeError(f"prometheus connection error: {exc}") from exc

    if body.get("status") != "success":
        raise RuntimeError(f"prometheus returned non-success response: {body}")

    return body


def _format_prometheus_time(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_explicit_query_time(value: str, field_name: str) -> datetime:
    text = (value or "").strip()
    if not text:
        raise ValueError(f"{field_name} must not be empty")
    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"

    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ValueError(
            f"{field_name} must be a valid ISO 8601 datetime"
        ) from exc

    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{field_name} must include an explicit timezone")
    return parsed.astimezone(timezone.utc)


def _window_to_timedelta(window: str) -> timedelta:
    normalized = (window or "30m").strip().lower()
    if normalized.endswith("m"):
        return timedelta(minutes=int(normalized[:-1]))
    if normalized.endswith("h"):
        return timedelta(hours=int(normalized[:-1]))
    if normalized.endswith("d"):
        return timedelta(days=int(normalized[:-1]))
    raise ValueError(f"unsupported window: {window}")


def _to_float(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _promql_quote(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _vector_to_number_map(result: list[dict[str, Any]]) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    for item in result:
        metric = item.get("metric", {})
        value = item.get("value", [])
        normalized.append(
            {
                "metric": metric,
                "timestamp": str(value[0]) if isinstance(value, list) and len(value) >= 2 else "",
                "value": _to_float(value[1] if isinstance(value, list) and len(value) >= 2 else 0),
            }
        )
    return normalized


def _matrix_to_series(result: list[dict[str, Any]]) -> list[dict[str, Any]]:
    series_list: list[dict[str, Any]] = []
    for item in result:
        metric = item.get("metric", {})
        values = item.get("values", [])
        points: list[dict[str, Any]] = []
        for sample in values:
            if not isinstance(sample, list) or len(sample) < 2:
                continue
            points.append({"timestamp": str(sample[0]), "value": _to_float(sample[1])})
        series_list.append({"metric": metric, "points": points})
    return series_list


def _downsample_points(points: list[dict[str, Any]], max_points: int = 20) -> list[dict[str, Any]]:
    if len(points) <= max_points:
        return points
    step = max(1, math.ceil(len(points) / max_points))
    sampled = points[::step]
    if sampled[-1] != points[-1]:
        sampled.append(points[-1])
    return sampled


def _query_instant(
    promql: str,
    *,
    at_time: datetime | None = None,
) -> dict[str, Any]:
    encoded = quote(promql, safe="")
    path = f"/api/v1/query?query={encoded}"
    if at_time is not None:
        encoded_time = quote(_format_prometheus_time(at_time), safe="")
        path += f"&time={encoded_time}"
    body = _prometheus_get(path)
    return body.get("data", {})


def _query_range(promql: str, start: datetime, end: datetime, step: str) -> dict[str, Any]:
    encoded = quote(promql, safe="")
    encoded_start = quote(_format_prometheus_time(start), safe="")
    encoded_end = quote(_format_prometheus_time(end), safe="")
    encoded_step = quote(step, safe="")
    body = _prometheus_get(
        f"/api/v1/query_range?query={encoded}&start={encoded_start}&end={encoded_end}&step={encoded_step}"
    )
    return body.get("data", {})


def _build_distribution(
    metric_name: str,
    namespace: str,
    window: str = DEFAULT_BUSINESS_WINDOW,
) -> dict[str, float]:


    selector = f'{{namespace="{namespace}"}}' if namespace else ""
    promql = f'sum by (result) (increase({metric_name}{selector}[{window}]))'
    raw = _query_instant(promql)
    result = raw.get("result", [])
    normalized = _vector_to_number_map(result)
    distribution: dict[str, float] = {}
    for item in normalized:
        metric = item.get("metric", {})
        result_label = metric.get("result", "unknown")
        distribution[result_label] = distribution.get(result_label, 0.0) + item.get("value", 0.0)
    return distribution


def _build_lifetime_distribution(
    metric_name: str,
    namespace: str,
) -> dict[str, float]:
    """读取当前存活时序的 Counter 累计值，与页面“实例业务成功率”一致。"""
    selector = f'{{namespace="{_promql_quote(namespace)}"}}' if namespace else ""
    promql = f"sum by (result) ({metric_name}{selector})"
    raw = _query_instant(promql)
    normalized = _vector_to_number_map(raw.get("result", []))
    distribution: dict[str, float] = {}
    for item in normalized:
        result_label = item.get("metric", {}).get("result", "unknown")
        distribution[result_label] = (
            distribution.get(result_label, 0.0) + item.get("value", 0.0)
        )
    return distribution


def _business_rate_snapshot(
    *,
    label: str,
    scope: str,
    window: str,
    query: str,
    distribution: dict[str, float],
    success_label: str,
    excluded_results: set[str],
) -> dict[str, Any]:
    raw_total = sum(distribution.values())
    excluded_count = sum(
        value
        for result, value in distribution.items()
        if result in excluded_results
    )
    effective_total = raw_total - excluded_count
    success_count = distribution.get(success_label, 0.0)
    failure_count = max(0.0, effective_total - success_count)
    success_rate = (
        round(success_count / effective_total * 100, 4)
        if effective_total > 0
        else None
    )

    return {
        "label": label,
        "scope": scope,
        "window": window,
        "query": query,
        "status": "evaluated" if effective_total > 0 else "no_data",
        "success_rate": success_rate,
        "success_rate_text": (
            f"{success_rate:.2f}%" if success_rate is not None else "NoData"
        ),
        "success_count": round(success_count, 4),
        "failure_count": round(failure_count, 4),
        "effective_count": round(effective_total, 4),
        "raw_total_count": round(raw_total, 4),
        "excluded_count": round(excluded_count, 4),
        "distribution": {
            key: round(value, 4)
            for key, value in sorted(distribution.items())
        },
    }


def _technical_sli_snapshot(
    *,
    label: str,
    scope: str,
    window: str,
    query: str,
    distribution: dict[str, float],
) -> dict[str, Any]:
    raw_total = sum(distribution.values())
    excluded_count = sum(
        value
        for result, value in distribution.items()
        if result in TECHNICAL_SLI_EXCLUDED_RESULTS
    )
    effective_total = max(0.0, raw_total - excluded_count)
    technical_failure_count = sum(
        value
        for result, value in distribution.items()
        if result in TECHNICAL_FAILURE_RESULTS
    )
    good_count = max(0.0, effective_total - technical_failure_count)
    sli_percent = (
        round(good_count / effective_total * 100, 4)
        if effective_total > 0
        else None
    )

    return {
        "label": label,
        "scope": scope,
        "window": window,
        "query": query,
        "sli_type": "technical_availability",
        "status": "evaluated" if effective_total > 0 else "no_data",
        "sli_percent": sli_percent,
        "sli_text": (
            f"{sli_percent:.2f}%" if sli_percent is not None else "NoData"
        ),
        "good_count": round(good_count, 4),
        "technical_failure_count": round(technical_failure_count, 4),
        "effective_count": round(effective_total, 4),
        "raw_total_count": round(raw_total, 4),
        "excluded_count": round(excluded_count, 4),
        "excluded_results": sorted(TECHNICAL_SLI_EXCLUDED_RESULTS),
        "technical_failure_results": sorted(TECHNICAL_FAILURE_RESULTS),
        "distribution": {
            key: round(value, 4)
            for key, value in sorted(distribution.items())
        },
    }


def get_business_success_rate_context(
    namespace: str | None = None,
) -> dict[str, Any]:
    """返回购买成功率 KPI 与订单处理技术可用性 SLI 的固定口径。"""
    namespace_value, namespace_error = _validate_namespace(namespace)
    if namespace_error:
        return namespace_error

    metric_name = DEFAULT_BUSINESS_METRIC
    success_label = DEFAULT_SUCCESS_LABEL
    excluded_results = set(DEFAULT_BUSINESS_EXCLUDED_RESULTS)
    selector = (
        f'{{namespace="{_promql_quote(namespace_value)}"}}'
        if namespace_value
        else ""
    )
    queries = {
        "instance_lifetime": f"sum by (result) ({metric_name}{selector})",
        "recent_15m": (
            f"sum by (result) (increase({metric_name}{selector}[15m]))"
        ),
        "sli_5m": (
            f"sum by (result) (increase({metric_name}{selector}[{BUSINESS_SLI_SHORT_WINDOW}]))"
        ),
        "sli_30d": (
            f"sum by (result) (increase({metric_name}{selector}[{BUSINESS_SLI_WINDOW}]))"
        ),
    }

    try:
        lifetime_distribution = _build_lifetime_distribution(
            metric_name,
            namespace_value,
        )
        recent_distribution = _build_distribution(
            metric_name,
            namespace_value,
            "15m",
        )
        short_sli_distribution = _build_distribution(
            metric_name,
            namespace_value,
            BUSINESS_SLI_SHORT_WINDOW,
        )
        sli_distribution = _build_distribution(
            metric_name,
            namespace_value,
            BUSINESS_SLI_WINDOW,
        )
    except RuntimeError as exc:
        return _error_payload(
            str(exc),
            metric_name=metric_name,
            namespace=namespace_value,
            queries=queries,
        )

    scopes = {
        "instance_lifetime": _business_rate_snapshot(
            label="实例业务成功率",
            scope="instance_lifetime",
            window="current_series_lifetime",
            query=queries["instance_lifetime"],
            distribution=lifetime_distribution,
            success_label=success_label,
            excluded_results=excluded_results,
        ),
        "recent_15m": _business_rate_snapshot(
            label="15分钟业务成功率",
            scope="recent_15m",
            window="15m",
            query=queries["recent_15m"],
            distribution=recent_distribution,
            success_label=success_label,
            excluded_results=excluded_results,
        ),
        "sli_5m": _technical_sli_snapshot(
            label="5分钟技术可用性SLI",
            scope="sli_5m",
            window=BUSINESS_SLI_SHORT_WINDOW,
            query=queries["sli_5m"],
            distribution=short_sli_distribution,
        ),
        "sli_30d": _technical_sli_snapshot(
            label="30天技术可用性SLI",
            scope="sli_30d",
            window=BUSINESS_SLI_WINDOW,
            query=queries["sli_30d"],
            distribution=sli_distribution,
        ),
    }

    sli_snapshot = scopes["sli_30d"]
    sli_value = sli_snapshot.get("sli_percent")
    if sli_value is None:
        remaining_budget = None
    else:
        allowed_error_rate = 100.0 - TECHNICAL_SLO_TARGET_PERCENT
        actual_error_rate = max(0.0, 100.0 - float(sli_value))
        remaining_budget = max(
            0.0,
            min(
                100.0,
                (allowed_error_rate - actual_error_rate)
                / allowed_error_rate
                * 100.0,
            ),
        )

    lifetime_text = scopes["instance_lifetime"]["success_rate_text"]
    recent_text = scopes["recent_15m"]["success_rate_text"]
    sli_text = scopes["sli_30d"]["sli_text"]
    budget_text = (
        f"{remaining_budget:.2f}%" if remaining_budget is not None else "NoData"
    )

    return {
        "generated_at": _now_text(),
        "metric_name": metric_name,
        "namespace": namespace_value,
        "source_of_truth": "get_business_success_rate_context",
        "purchase_rate_policy": {
            "success_result": success_label,
            "excluded_results": sorted(excluded_results),
            "failure_definition": (
                "除排除项外，所有非 success 结果均计为失败"
            ),
            "formula": "success / (raw_total - excluded) * 100%",
        },
        "technical_sli_policy": {
            "slo_target_percent": TECHNICAL_SLO_TARGET_PERCENT,
            "sli_window": BUSINESS_SLI_WINDOW,
            "short_sli_window": BUSINESS_SLI_SHORT_WINDOW,
            "excluded_business_results": sorted(
                TECHNICAL_SLI_EXCLUDED_RESULTS
            ),
            "technical_failure_results": sorted(
                TECHNICAL_FAILURE_RESULTS
            ),
            "formula": (
                "(effective_requests - technical_failures) "
                "/ effective_requests * 100%"
            ),
        },
        "scopes": scopes,
        "error_budget": {
            "window": BUSINESS_SLI_WINDOW,
            "slo_target_percent": TECHNICAL_SLO_TARGET_PERCENT,
            "remaining_percent": (
                round(remaining_budget, 4)
                if remaining_budget is not None
                else None
            ),
            "remaining_text": budget_text,
            "formula": (
                "(允许错误率 - 30天实际错误率) / 允许错误率 * 100%"
            ),
        },
        "queries": queries,
        "query_used": " | ".join(queries.values()),
        "summary": (
            f"购买成功率 KPI：实例累计 {lifetime_text}，"
            f"最近15分钟 {recent_text}；5分钟技术可用性SLI "
            f"{scopes['sli_5m']['sli_text']}，30天技术可用性SLI {sli_text}，"
            f"技术SLO目标 {TECHNICAL_SLO_TARGET_PERCENT:.2f}%，"
            f"剩余错误预算 {budget_text}。"
        ),
    }


def _single_value_from_vector(result: list[dict[str, Any]]) -> float:
    normalized = _vector_to_number_map(result)
    return round(sum(item.get("value", 0.0) for item in normalized), 6)


def _summarize_scalar_vector(
    promql: str,
    metric_label: str | None = None,
    namespace: str | None = None,
) -> dict[str, Any]:
    try:
        data = _query_instant(promql)
    except RuntimeError as exc:
        return _error_payload(str(exc), query=promql)

    result = data.get("result", [])
    normalized = _vector_to_number_map(result)
    if namespace:
        normalized = [
            item for item in normalized if item.get("metric", {}).get("namespace") == namespace
        ]

    total_value = round(sum(item.get("value", 0.0) for item in normalized), 4)
    label = metric_label or promql

    return {
        "generated_at": _now_text(),
        "prometheus_base_url": PROMETHEUS_BASE_URL,
        "metric_label": label,
        "query": promql,
        "result_type": data.get("resultType", ""),
        "result_count": len(normalized),
        "value": total_value,
        "summary": f"{label} 当前值为 {total_value}，共匹配到 {len(normalized)} 条时序。",
        "result": normalized,
    }


def _detect_pattern(values: list[float]) -> str:
    if len(values) < 4:
        return "insufficient_data"

    latest = values[-1]
    baseline_values = values[:-1]
    mean = sum(baseline_values) / len(baseline_values)
    variance = sum((value - mean) ** 2 for value in baseline_values) / max(1, len(baseline_values))
    std = math.sqrt(variance)

    if std > 0 and latest > mean + 3 * std:
        return "spike"

    recent = values[-4:]
    if all(recent[i] >= recent[i - 1] for i in range(1, len(recent))) and recent[-1] > recent[0] * 1.2:
        return "continuous_degradation"

    if mean > 0 and all(value >= mean * 0.9 for value in recent):
        return "stable_high"

    return "stable"


def query_prometheus(promql: str) -> dict[str, Any]:
    return _summarize_scalar_vector(promql=promql)


def query_prometheus_range(promql: str, window: str = "30m", step: str = "1m") -> dict[str, Any]:
    try:
        delta = _window_to_timedelta(window)
    except ValueError as exc:
        return _error_payload(str(exc), query=promql, window=window, step=step)

    end_time = datetime.now(timezone.utc)
    start_time = end_time - delta

    try:
        data = _query_range(promql, start=start_time, end=end_time, step=step)
    except RuntimeError as exc:
        return _error_payload(str(exc), query=promql, window=window, step=step)

    return {
        "generated_at": _now_text(),
        "prometheus_base_url": PROMETHEUS_BASE_URL,
        "query": promql,
        "window": window,
        "step": step,
        "result_type": data.get("resultType", ""),
        "series": _matrix_to_series(data.get("result", [])),
    }


def get_business_overview(
    metric_name: str | None = None,
    namespace: str | None = None,
    success_label: str | None = None,
    window: str | None = None,
    excluded_results: list[str] | None = None,
) -> dict[str, Any]:
    namespace_value, namespace_error = _validate_namespace(namespace)
    if namespace_error:
        return namespace_error

    metric_name = (metric_name or DEFAULT_BUSINESS_METRIC).strip()
    success_label = (success_label or DEFAULT_SUCCESS_LABEL).strip()
    window_value = (window or DEFAULT_BUSINESS_WINDOW).strip() or DEFAULT_BUSINESS_WINDOW
    if excluded_results is None:
        excluded_result_set = set(DEFAULT_BUSINESS_EXCLUDED_RESULTS)
    elif not isinstance(excluded_results, list) or any(
        not isinstance(item, str) for item in excluded_results
    ):
        return _error_payload(
            "excluded_results must be an array of strings",
            metric_name=metric_name,
            namespace=namespace_value,
            success_label=success_label,
            window=window_value,
        )
    else:
        excluded_result_set = {
            item.strip() for item in excluded_results if item.strip()
        }

    try:
        _window_to_timedelta(window_value)
    except ValueError as exc:
        return _error_payload(
            str(exc),
            metric_name=metric_name,
            namespace=namespace_value,
            success_label=success_label,
            window=window_value,
        )

    try:
        distribution = _build_distribution(metric_name, namespace_value, window_value)
    except RuntimeError as exc:
        return _error_payload(
            str(exc),
            metric_name=metric_name,
            namespace=namespace_value,
            success_label=success_label,
            window=window_value,
        )

    raw_total = sum(distribution.values())
    excluded_distribution = {
        result: value
        for result, value in distribution.items()
        if result in excluded_result_set
    }
    effective_distribution = {
        result: value
        for result, value in distribution.items()
        if result not in excluded_result_set
    }
    excluded_count = sum(excluded_distribution.values())
    total = sum(effective_distribution.values())
    success_count = effective_distribution.get(success_label, 0.0)
    success_rate = round((success_count / total) * 100, 2) if total > 0 else 0.0

    dominant_result = ""
    dominant_value = 0.0
    if effective_distribution:
        dominant_result, dominant_value = max(
            effective_distribution.items(), key=lambda item: item[1]
        )

    sorted_distribution = [
        {"result": key, "value": int(value)}
        for key, value in sorted(distribution.items(), key=lambda item: item[1], reverse=True)
    ]
    sorted_effective_distribution = [
        {"result": key, "value": int(value)}
        for key, value in sorted(
            effective_distribution.items(), key=lambda item: item[1], reverse=True
        )
    ]

    if total <= 0:
        summary = f"近 {window_value} 窗口内未查询到指标 {metric_name} 的下单样本（可能无流量）。"
        level = "warn"
    elif success_rate >= 95:
        summary = f"近 {window_value} 有效业务量 {int(total)}，成功 {int(success_count)}，成功率 {success_rate}%，整体稳定。"
        level = "good"
    elif success_rate >= 80:
        summary = f"近 {window_value} 有效业务量 {int(total)}，成功 {int(success_count)}，成功率 {success_rate}%，需要关注失败结果分布。"
        level = "warn"
    else:
        summary = f"近 {window_value} 有效业务量 {int(total)}，成功 {int(success_count)}，成功率 {success_rate}%，明显偏低。"
        level = "bad"

    if excluded_count > 0:
        summary += (
            f" 原始请求量 {int(raw_total)}，按告警口径排除重复类结果"
            f" {int(excluded_count)} 条。"
        )

    if dominant_result and dominant_result != success_label:
        summary += f" 近窗占比最高的结果是 {dominant_result}（{int(dominant_value)}）。"

    return {
        "generated_at": _now_text(),
        "prometheus_base_url": PROMETHEUS_BASE_URL,
        "metric_name": metric_name,
        "namespace": namespace_value,
        "success_label": success_label,
        "window": window_value,
        "summary": summary,
        "level": level,
        "success_rate": success_rate,
        "success_count": int(success_count),
        "total_count": int(total),
        "raw_total_count": int(raw_total),
        "excluded_count": int(excluded_count),
        "excluded_results": sorted(excluded_result_set),
        "excluded_distribution": [
            {"result": key, "value": int(value)}
            for key, value in sorted(
                excluded_distribution.items(), key=lambda item: item[1], reverse=True
            )
        ],
        "dominant_result": dominant_result,
        "distribution": sorted_distribution,
        "effective_distribution": sorted_effective_distribution,
        "metric_dictionary": METRIC_DICTIONARY,
    }


def get_metric_value(
    promql: str,
    metric_label: str | None = None,
    namespace: str | None = None,
) -> dict[str, Any]:
    namespace_value = None
    if namespace is not None:
        namespace_value, namespace_error = _validate_namespace(namespace)
        if namespace_error:
            return namespace_error

    return _summarize_scalar_vector(
        promql=promql,
        metric_label=metric_label,
        namespace=namespace_value,
    )


def get_metric_trend(
    promql: str,
    window: str = "30m",
    step: str = "1m",
    metric_label: str | None = None,
    start_at: str | None = None,
    end_at: str | None = None,
    threshold: float | None = None,
    threshold_direction: str = "above",
    series_match: dict[str, str] | None = None,
    condition_promql: str | None = None,
) -> dict[str, Any]:
    normalized_threshold_direction = (threshold_direction or "above").strip().lower()
    if normalized_threshold_direction not in {"above", "below"}:
        return _error_payload(
            "threshold_direction must be above or below",
            query=promql,
            threshold=threshold,
            threshold_direction=threshold_direction,
        )

    explicit_start = (start_at or "").strip()
    explicit_end = (end_at or "").strip()
    has_explicit_range = bool(explicit_start or explicit_end)

    if bool(explicit_start) != bool(explicit_end):
        return _error_payload(
            "start_at and end_at must be provided together",
            query=promql,
            window=window,
            step=step,
            start_at=explicit_start or None,
            end_at=explicit_end or None,
        )

    if has_explicit_range:
        try:
            start_time = _parse_explicit_query_time(
                explicit_start,
                "start_at",
            )
            end_time = _parse_explicit_query_time(
                explicit_end,
                "end_at",
            )
        except ValueError as exc:
            return _error_payload(
                str(exc),
                query=promql,
                window=window,
                step=step,
                start_at=explicit_start,
                end_at=explicit_end,
            )

        if start_time >= end_time:
            return _error_payload(
                "start_at must be earlier than end_at",
                query=promql,
                window=window,
                step=step,
                start_at=_format_prometheus_time(start_time),
                end_at=_format_prometheus_time(end_time),
            )
        query_mode = "explicit_range"
        range_label = (
            f"{_format_prometheus_time(start_time)} 至 "
            f"{_format_prometheus_time(end_time)}"
        )
    else:
        try:
            delta = _window_to_timedelta(window)
        except ValueError as exc:
            return _error_payload(
                str(exc),
                query=promql,
                window=window,
                step=step,
            )
        end_time = datetime.now(timezone.utc)
        start_time = end_time - delta
        query_mode = "relative_window"
        range_label = f"最近 {window}"

    try:
        data = _query_range(promql, start=start_time, end=end_time, step=step)
    except RuntimeError as exc:
        return _error_payload(
            str(exc),
            query=promql,
            window=window,
            step=step,
            query_mode=query_mode,
            start_at=_format_prometheus_time(start_time),
            end_at=_format_prometheus_time(end_time),
        )

    raw_series = _matrix_to_series(data.get("result", []))
    if series_match is not None and not isinstance(series_match, dict):
        return _error_payload(
            "series_match must be an object",
            query=promql,
            series_match=series_match,
        )
    normalized_series_match = {
        str(key).strip(): str(value).strip()
        for key, value in (series_match or {}).items()
        if str(key).strip() and str(value).strip()
    }
    available_series = [
        item.get("metric", {})
        for item in raw_series
    ]
    if normalized_series_match:
        raw_series = [
            item
            for item in raw_series
            if all(
                str(item.get("metric", {}).get(key, "")) == value
                for key, value in normalized_series_match.items()
            )
        ]

    if len(raw_series) > 1:
        return _error_payload(
            "multiple time series found; refine promql or provide series_match",
            query=promql,
            query_mode=query_mode,
            start_at=_format_prometheus_time(start_time),
            end_at=_format_prometheus_time(end_time),
            series_match=normalized_series_match,
            available_series=available_series[:20],
        )

    if normalized_series_match and not raw_series:
        return _error_payload(
            "no time series matched series_match",
            query=promql,
            query_mode=query_mode,
            start_at=_format_prometheus_time(start_time),
            end_at=_format_prometheus_time(end_time),
            series_match=normalized_series_match,
            available_series=available_series[:20],
        )
    flattened_samples: list[tuple[float, float]] = []
    compact_series: list[dict[str, Any]] = []

    for item in raw_series:
        points = item.get("points", [])
        for point in points:
            try:
                timestamp = float(point.get("timestamp", 0.0))
                value = float(point.get("value", 0.0))
            except (TypeError, ValueError):
                continue
            flattened_samples.append((timestamp, value))
        compact_series.append({"metric": item.get("metric", {}), "points": _downsample_points(points)})

    if not flattened_samples:
        return _error_payload(
            "no time series data found",
            query=promql,
            window=window,
            step=step,
            query_mode=query_mode,
            start_at=_format_prometheus_time(start_time),
            end_at=_format_prometheus_time(end_time),
        )

    flattened_samples.sort(key=lambda item: item[0])
    flattened_values = [item[1] for item in flattened_samples]
    latest = round(flattened_values[-1], 4)
    minimum = round(min(flattened_values), 4)
    peak = round(max(flattened_values), 4)
    baseline = round(sum(flattened_values) / len(flattened_values), 4)
    sample_count = len(flattened_values)
    pattern = _detect_pattern(flattened_values)
    label = metric_label or promql

    normalized_condition_promql = (condition_promql or "").strip()
    condition_active_timestamps: set[float] | None = None
    condition_active_latest: bool | None = None
    condition_series_metric: dict[str, Any] | None = None
    if normalized_condition_promql:
        try:
            condition_data = _query_range(
                normalized_condition_promql,
                start=start_time,
                end=end_time,
                step=step,
            )
        except RuntimeError as exc:
            return _error_payload(
                f"failed to query complete alert condition: {exc}",
                query=promql,
                condition_promql=normalized_condition_promql,
                start_at=_format_prometheus_time(start_time),
                end_at=_format_prometheus_time(end_time),
            )

        condition_series = _matrix_to_series(
            condition_data.get("result", [])
        )
        if normalized_series_match:
            condition_series = [
                item
                for item in condition_series
                if all(
                    str(item.get("metric", {}).get(key, "")) == value
                    for key, value in normalized_series_match.items()
                )
            ]
        if len(condition_series) > 1:
            return _error_payload(
                "multiple alert-condition series found; refine promql or provide series_match",
                query=promql,
                condition_promql=normalized_condition_promql,
                series_match=normalized_series_match,
                available_condition_series=[
                    item.get("metric", {}) for item in condition_series[:20]
                ],
            )

        condition_active_timestamps = set()
        if condition_series:
            condition_series_metric = condition_series[0].get("metric", {})
            for point in condition_series[0].get("points", []):
                try:
                    condition_active_timestamps.add(
                        float(point.get("timestamp", 0.0))
                    )
                except (TypeError, ValueError):
                    continue
        condition_active_latest = (
            flattened_samples[-1][0] in condition_active_timestamps
        )

    threshold_summary: dict[str, Any] = {}
    if threshold is not None:
        if normalized_threshold_direction == "below":
            metric_breached_samples = [
                item for item in flattened_samples if item[1] < threshold
            ]
        else:
            metric_breached_samples = [
                item for item in flattened_samples if item[1] > threshold
            ]
        breached_samples = metric_breached_samples
        if condition_active_timestamps is not None:
            breached_samples = [
                item
                for item in metric_breached_samples
                if item[0] in condition_active_timestamps
            ]
        breached_timestamps = {item[0] for item in breached_samples}
        approx_breached_seconds = sum(
            later[0] - earlier[0]
            for earlier, later in zip(
                flattened_samples,
                flattened_samples[1:],
            )
            if (
                later[0] > earlier[0]
                and earlier[0] in breached_timestamps
                and later[0] in breached_timestamps
            )
        )
        first_breached_at = (
            datetime.fromtimestamp(
                breached_samples[0][0],
                tz=timezone.utc,
            ).isoformat().replace("+00:00", "Z")
            if breached_samples
            else None
        )
        threshold_summary = {
            "threshold": threshold,
            "threshold_direction": normalized_threshold_direction,
            "metric_breached_sample_count": len(metric_breached_samples),
            "breached_sample_count": len(breached_samples),
            "approx_breached_seconds": round(approx_breached_seconds, 1),
            "first_breached_at": first_breached_at,

            "above_threshold_sample_count": (
                len(breached_samples)
                if normalized_threshold_direction == "above"
                else 0
            ),
            "approx_above_threshold_seconds": (
                round(approx_breached_seconds, 1)
                if normalized_threshold_direction == "above"
                else 0.0
            ),
            "first_crossed_at": (
                first_breached_at
                if normalized_threshold_direction == "above"
                else None
            ),
        }

    if pattern == "spike":
        trend_summary = f"{label} 在 {range_label} 内出现明显尖峰，更像毛刺而不是持续恶化。"
    elif pattern == "continuous_degradation":
        trend_summary = f"{label} 在 {range_label} 内持续抬升或恶化，需要关注是否为连续性问题。"
    elif pattern == "stable_high":
        trend_summary = f"{label} 在 {range_label} 内持续处于高位，更像持续性高负载。"
    elif pattern == "stable":
        trend_summary = f"{label} 在 {range_label} 内整体平稳，没有明显毛刺。"
    else:
        trend_summary = f"{label} 数据点不足，暂时无法判断趋势模式。"

    return {
        "generated_at": _now_text(),
        "prometheus_base_url": PROMETHEUS_BASE_URL,
        "metric_label": label,
        "query": promql,
        "window": window,
        "step": step,
        "query_mode": query_mode,
        "start_at": _format_prometheus_time(start_time),
        "end_at": _format_prometheus_time(end_time),
        "pattern": pattern,
        "sample_count": sample_count,
        "min": minimum,
        "latest": latest,
        "peak": peak,
        "baseline": baseline,
        "condition_promql": normalized_condition_promql or None,
        "condition_active_sample_count": (
            len(condition_active_timestamps)
            if condition_active_timestamps is not None
            else None
        ),
        "condition_active_latest": condition_active_latest,
        "condition_series_metric": condition_series_metric,
        **threshold_summary,
        "trend_summary": trend_summary,
        "series": compact_series,
        "series_match": normalized_series_match,
        "series_metric": raw_series[0].get("metric", {}),
    }


def compare_metric_time_shift(
    promql: str,
    offset: str = "1d",
    metric_label: str | None = None,
) -> dict[str, Any]:
    normalized_offset = (offset or "1d").strip().lower()
    supported_offsets = {"1h", "6h", "12h", "1d", "7d"}
    if normalized_offset not in supported_offsets:
        return _error_payload(
            "unsupported offset",
            requested_offset=offset,
            valid_offsets=sorted(supported_offsets),
            query=promql,
        )

    current_query = promql
    shifted_query = f"{promql} offset {normalized_offset}"
    label = metric_label or promql

    try:
        current_data = _query_instant(current_query)
        shifted_data = _query_instant(shifted_query)
    except RuntimeError as exc:
        return _error_payload(
            str(exc),
            query=promql,
            offset=normalized_offset,
            metric_label=label,
        )

    current_value = _single_value_from_vector(current_data.get("result", []))
    shifted_value = _single_value_from_vector(shifted_data.get("result", []))

    absolute_change = round(current_value - shifted_value, 6)
    if shifted_value == 0:
        percent_change = None
    else:
        percent_change = round((absolute_change / shifted_value) * 100, 2)

    if shifted_value == 0 and current_value == 0:
        comparison = "flat"
        summary = f"{label} 当前值和 {normalized_offset} 前的同类值都为 0，暂无可比波动。"
    elif shifted_value == 0:
        comparison = "up"
        summary = f"{label} 当前值为 {current_value}，而 {normalized_offset} 前几乎为 0，当前明显更高。"
    elif absolute_change > 0:
        comparison = "up"
        summary = (
            f"{label} 当前值 {current_value}，相比 {normalized_offset} 前的 {shifted_value} 上升了 "
            f"{absolute_change}（{percent_change}%）。"
        )
    elif absolute_change < 0:
        comparison = "down"
        summary = (
            f"{label} 当前值 {current_value}，相比 {normalized_offset} 前的 {shifted_value} 下降了 "
            f"{abs(absolute_change)}（{abs(percent_change) if percent_change is not None else 'N/A'}%）。"
        )
    else:
        comparison = "flat"
        summary = f"{label} 当前值 {current_value}，与 {normalized_offset} 前基本持平。"

    return {
        "generated_at": _now_text(),
        "prometheus_base_url": PROMETHEUS_BASE_URL,
        "metric_label": label,
        "query": promql,
        "offset": normalized_offset,
        "current_query": current_query,
        "shifted_query": shifted_query,
        "current_value": current_value,
        "shifted_value": shifted_value,
        "absolute_change": absolute_change,
        "percent_change": percent_change,
        "comparison": comparison,
        "summary": summary,
    }


def get_topk_resource_consumers(
    resource_type: str,
    namespace: str | None = None,
    top_n: int = 5,
    window: str = "5m",
) -> dict[str, Any]:
    normalized_resource = (resource_type or "").strip().lower()
    if normalized_resource not in {"cpu", "memory"}:
        return _error_payload(
            "unsupported resource_type",
            requested_resource_type=resource_type,
            valid_resource_types=["cpu", "memory"],
        )

    namespace_filter = ""
    namespace_value = ""
    if namespace is not None:
        namespace_value, namespace_error = _validate_namespace(namespace)
        if namespace_error:
            return namespace_error
        namespace_filter = f',namespace="{namespace_value}"'

    normalized_top_n = max(1, min(int(top_n or 5), 20))

    if normalized_resource == "cpu":
        promql = (
            f'topk({normalized_top_n}, '
            f'sum by (namespace, pod) (rate(container_cpu_usage_seconds_total'
            f'{{container!="", pod!="", image!=""{namespace_filter}}}[{window}])))'
        )
        unit = "cores"
    else:
        promql = (
            f'topk({normalized_top_n}, '
            f'sum by (namespace, pod) (container_memory_working_set_bytes'
            f'{{container!="", pod!="", image!=""{namespace_filter}}}))'
        )
        unit = "MiB"

    try:
        data = _query_instant(promql)
    except RuntimeError as exc:
        return _error_payload(
            str(exc),
            resource_type=normalized_resource,
            namespace=namespace_value,
            top_n=normalized_top_n,
            window=window,
            query=promql,
        )

    normalized = _vector_to_number_map(data.get("result", []))
    items: list[dict[str, Any]] = []
    for item in normalized:
        metric = item.get("metric", {})
        raw_value = item.get("value", 0.0)
        if normalized_resource == "memory":
            display_value = round(raw_value / 1024 / 1024, 2)
        else:
            display_value = round(raw_value, 4)

        items.append(
            {
                "namespace": metric.get("namespace", ""),
                "pod": metric.get("pod", ""),
                "value": display_value,
                "unit": unit,
            }
        )

    scope = namespace_value or "all namespaces"
    if items:
        top_item = items[0]
        summary = (
            f"最近最占 {normalized_resource} 资源的是 "
            f"{top_item['namespace']}/{top_item['pod']}，"
            f"数值 {top_item['value']} {unit}。"
        )
    else:
        summary = f"当前未查询到 {scope} 下的 {normalized_resource} Top{normalized_top_n} 数据。"

    return {
        "generated_at": _now_text(),
        "prometheus_base_url": PROMETHEUS_BASE_URL,
        "resource_type": normalized_resource,
        "namespace": namespace_value,
        "top_n": normalized_top_n,
        "window": window,
        "query": promql,
        "summary": summary,
        "items": items,
    }


def get_node_top_pods(
    node_name: str,
    resource_type: str,
    top_n: int = 5,
    window: str = "1m",
    at_time: str | None = None,
) -> dict[str, Any]:
    normalized_node = (node_name or "").strip()
    if not normalized_node:
        return _error_payload("node_name is required")

    normalized_resource = (resource_type or "").strip().lower()
    if normalized_resource not in {"cpu", "memory"}:
        return _error_payload(
            "unsupported resource_type",
            requested_resource_type=resource_type,
            valid_resource_types=["cpu", "memory"],
        )

    try:
        _window_to_timedelta(window)
    except ValueError as exc:
        return _error_payload(str(exc), node_name=normalized_node, window=window)

    normalized_top_n = max(1, min(int(top_n or 5), 20))
    node_value = _promql_quote(normalized_node)
    evaluation_time: datetime | None = None
    if (at_time or "").strip():
        try:
            evaluation_time = _parse_explicit_query_time(
                str(at_time),
                "at_time",
            )
        except ValueError as exc:
            return _error_payload(
                str(exc),
                node_name=normalized_node,
                resource_type=normalized_resource,
                at_time=at_time,
            )

    if normalized_resource == "cpu":
        usage = (
            "sum by (namespace, pod) ("
            f"rate(container_cpu_usage_seconds_total{{instance=\"{node_value}\",container!=\"\","
            f"container!=\"POD\",pod!=\"\",image!=\"\"}}[{window}])"
            ")"
        )
        unit = "cores"
    else:
        usage = (
            "sum by (namespace, pod) ("
            f"container_memory_working_set_bytes{{instance=\"{node_value}\",container!=\"\","
            "container!=\"POD\",pod!=\"\",image!=\"\"}"
            ")"
        )
        unit = "MiB"

    promql = f"topk({normalized_top_n}, {usage})"

    try:
        data = _query_instant(promql, at_time=evaluation_time)
    except RuntimeError as exc:
        return _error_payload(
            str(exc),
            node_name=normalized_node,
            resource_type=normalized_resource,
            query=promql,
            at_time=(
                _format_prometheus_time(evaluation_time)
                if evaluation_time
                else None
            ),
        )

    items: list[dict[str, Any]] = []
    for item in _vector_to_number_map(data.get("result", [])):
        metric = item.get("metric", {})
        raw_value = item.get("value", 0.0)
        value = raw_value if normalized_resource == "cpu" else raw_value / 1024 / 1024
        items.append(
            {
                "node": normalized_node,
                "namespace": metric.get("namespace", ""),
                "pod": metric.get("pod", ""),
                "value": round(value, 4 if normalized_resource == "cpu" else 2),
                "unit": unit,
            }
        )

    items.sort(key=lambda item: item["value"], reverse=True)
    node_capacity_cores: float | None = None
    capacity_query = ""
    if normalized_resource == "cpu":
        capacity_query = (
            "count(count by (cpu) ("
            f'node_cpu_seconds_total{{instance="{node_value}",mode="idle"}}'
            "))"
        )
        try:
            capacity_data = _query_instant(
                capacity_query,
                at_time=evaluation_time,
            )
            capacity_value = _single_value_from_vector(
                capacity_data.get("result", [])
            )
            if capacity_value > 0:
                node_capacity_cores = capacity_value
        except RuntimeError:
            node_capacity_cores = None

        if node_capacity_cores:
            for item in items:
                item["node_capacity_percent"] = round(
                    item["value"] / node_capacity_cores * 100,
                    2,
                )

    if items:
        top_item = items[0]
        time_text = (
            f"在 {_format_prometheus_time(evaluation_time)} 时"
            if evaluation_time
            else "在当前查询窗口内"
        )
        summary = (
            f"节点 {normalized_node} {time_text}，{normalized_resource} 占用最高的 Pod 是 "
            f"{top_item['namespace']}/{top_item['pod']}，"
            f"数值 {top_item['value']} {unit}。"
        )
        if normalized_resource == "cpu" and node_capacity_cores:
            summary += (
                f" 节点容量为 {node_capacity_cores:g} cores，"
                f"该 Pod 约占节点容量的 "
                f"{top_item.get('node_capacity_percent', '--')}%。"
            )
    else:
        summary = (
            f"节点 {normalized_node} 当前没有查询到可用的 Pod "
            f"{normalized_resource} 数据。"
        )

    return {
        "generated_at": _now_text(),
        "prometheus_base_url": PROMETHEUS_BASE_URL,
        "node_name": normalized_node,
        "resource_type": normalized_resource,
        "top_n": normalized_top_n,
        "window": window,
        "at_time": (
            _format_prometheus_time(evaluation_time)
            if evaluation_time
            else None
        ),
        "query": promql,
        "capacity_query": capacity_query,
        "node_capacity_cores": node_capacity_cores,
        "summary": summary,
        "items": items,
    }


def get_pod_resource_trend(
    namespace: str,
    pod_name: str,
    resource_type: str,
    start_at: str,
    end_at: str,
    step: str = "1m",
    node_name: str | None = None,
) -> dict[str, Any]:
    """Query one Pod over the exact incident window, not at the current instant."""
    namespace_value, namespace_error = _validate_namespace(namespace)
    if namespace_error:
        return namespace_error

    normalized_pod = (pod_name or "").strip()
    if not normalized_pod:
        return _error_payload("pod_name is required")

    normalized_resource = (resource_type or "").strip().lower()
    if normalized_resource not in {"cpu", "memory"}:
        return _error_payload(
            "unsupported resource_type",
            requested_resource_type=resource_type,
            valid_resource_types=["cpu", "memory"],
        )

    namespace_label = _promql_quote(namespace_value)
    pod_label = _promql_quote(normalized_pod)
    if normalized_resource == "cpu":
        promql = (
            "sum(rate(container_cpu_usage_seconds_total{"
            f'namespace="{namespace_label}",pod="{pod_label}",'
            'container!="",container!="POD",image!=""}[1m]))'
        )
        metric_label = f"Pod {namespace_value}/{normalized_pod} CPU"
        unit = "cores"
    else:
        promql = (
            "sum(container_memory_working_set_bytes{"
            f'namespace="{namespace_label}",pod="{pod_label}",'
            'container!="",container!="POD",image!=""}) / 1024 / 1024'
        )
        metric_label = f"Pod {namespace_value}/{normalized_pod} 内存"
        unit = "MiB"

    trend = get_metric_trend(
        promql=promql,
        step=step,
        metric_label=metric_label,
        start_at=start_at,
        end_at=end_at,
    )
    if trend.get("error"):
        return {
            **trend,
            "namespace": namespace_value,
            "pod_name": normalized_pod,
            "resource_type": normalized_resource,
            "unit": unit,
        }

    result = {
        **trend,
        "namespace": namespace_value,
        "pod_name": normalized_pod,
        "resource_type": normalized_resource,
        "unit": unit,
    }
    normalized_node = (node_name or "").strip()
    if normalized_resource == "cpu" and normalized_node:
        try:
            evaluation_time = _parse_explicit_query_time(end_at, "end_at")
            node_value = _promql_quote(normalized_node)
            capacity_query = (
                "count(count by (cpu) ("
                f'node_cpu_seconds_total{{instance="{node_value}",mode="idle"}}'
                "))"
            )
            capacity_data = _query_instant(
                capacity_query,
                at_time=evaluation_time,
            )
            node_capacity_cores = _single_value_from_vector(
                capacity_data.get("result", [])
            )
            if node_capacity_cores > 0:
                result.update(
                    {
                        "node_name": normalized_node,
                        "node_capacity_cores": node_capacity_cores,
                        "peak_node_capacity_percent": round(
                            float(result.get("peak", 0.0))
                            / node_capacity_cores
                            * 100,
                            2,
                        ),
                        "latest_node_capacity_percent": round(
                            float(result.get("latest", 0.0))
                            / node_capacity_cores
                            * 100,
                            2,
                        ),
                        "capacity_query": capacity_query,
                    }
                )
        except (RuntimeError, ValueError, TypeError):
            pass
    capacity_text = ""
    if result.get("node_capacity_cores"):
        capacity_text = (
            f"；节点容量 {result['node_capacity_cores']:g} cores，"
            f"Pod 峰值约占节点容量的 "
            f"{result.get('peak_node_capacity_percent', '--')}%"
        )
    result["summary"] = (
        f"{metric_label} 在 {trend.get('start_at')} 至 {trend.get('end_at')} "
        f"取得 {trend.get('sample_count', 0)} 个样本，峰值 "
        f"{trend.get('peak', '--')} {unit}，最新值 "
        f"{trend.get('latest', '--')} {unit}{capacity_text}，趋势为 "
        f"{trend.get('pattern', 'unknown')}。"
    )
    return result


def get_service_golden_signals(
    service_name: str,
    namespace: str,
    window: str = "5m",
    path: str | None = None,
) -> dict[str, Any]:
    normalized_service = (service_name or "").strip()
    if not normalized_service:
        return _error_payload("service_name is required")

    namespace_value, namespace_error = _validate_namespace(namespace)
    if namespace_error:
        return namespace_error

    service_value = _promql_quote(normalized_service)
    namespace_label = _promql_quote(namespace_value)
    normalized_path = (path or "").strip()
    path_selector = (
        f',path="{_promql_quote(normalized_path)}"'
        if normalized_path
        else ""
    )
    base_metric = DEFAULT_SERVICE_REQUEST_METRIC

    rate_query = (
        f'sum(rate({base_metric}{{namespace="{namespace_label}",service="{service_value}"'
        f'{path_selector}}}[{window}]))'
    )
    total_query = (
        f'sum(increase({base_metric}{{namespace="{namespace_label}",service="{service_value}"'
        f'{path_selector}}}[{window}]))'
    )
    if "http_request" in base_metric:
        error_query = (
            f'sum(increase({base_metric}{{namespace="{namespace_label}",service="{service_value}",'
            f'status_code=~"5.."{path_selector}}}[{window}]))'
        )
    else:
        error_query = (
            f'sum(increase({base_metric}{{namespace="{namespace_label}",service="{service_value}",'
            f'result!="{DEFAULT_SUCCESS_LABEL}"{path_selector}}}[{window}]))'
        )

    try:
        rate_data = _query_instant(rate_query)
        total_data = _query_instant(total_query)
        error_data = _query_instant(error_query)
    except RuntimeError as exc:
        return _error_payload(
            str(exc),
            service_name=normalized_service,
            namespace=namespace_value,
            window=window,
        )

    request_rate = _single_value_from_vector(rate_data.get("result", []))
    total_requests = _single_value_from_vector(total_data.get("result", []))
    error_requests = _single_value_from_vector(error_data.get("result", []))
    error_rate = round((error_requests / total_requests) * 100, 4) if total_requests > 0 else 0.0

    latency_available = False
    latency_p95_ms = None
    latency_query = ""
    latency_summary = "当前未配置可用的延迟直方图指标。"

    if DEFAULT_SERVICE_LATENCY_BUCKET_METRIC:
        latency_query = (
            "histogram_quantile(0.95, "
            f"sum by (le) (rate({DEFAULT_SERVICE_LATENCY_BUCKET_METRIC}"
            f'{{namespace="{namespace_label}",service="{service_value}"'
            f'{path_selector}}}[{window}])))'
        )
        try:
            latency_data = _query_instant(latency_query)
            latency_value = _single_value_from_vector(latency_data.get("result", []))
            if latency_value > 0:
                latency_available = True
                latency_p95_ms = round(latency_value * 1000, 2)
                latency_summary = f"P95 延迟约 {latency_p95_ms} ms。"
            else:
                latency_summary = "延迟指标查询成功，但当前没有有效样本。"
        except RuntimeError as exc:
            latency_summary = f"延迟指标查询失败：{exc}"

    if total_requests <= 0:
        summary = (
            f"服务 {namespace_value}/{normalized_service} 在最近 {window} 内未查询到有效请求样本，"
            "暂时无法完整判断黄金指标。"
        )
        level = "warn"
    elif error_rate >= 20:
        summary = (
            f"服务 {namespace_value}/{normalized_service} 最近 {window} 请求量约 {request_rate}/s，"
            f"错误率 {error_rate}% ，明显偏高。{latency_summary}"
        )
        level = "bad"
    elif error_rate > 5:
        summary = (
            f"服务 {namespace_value}/{normalized_service} 最近 {window} 请求量约 {request_rate}/s，"
            f"错误率 {error_rate}% ，需要关注。{latency_summary}"
        )
        level = "warn"
    else:
        summary = (
            f"服务 {namespace_value}/{normalized_service} 最近 {window} 请求量约 {request_rate}/s，"
            f"错误率 {error_rate}% ，整体稳定。{latency_summary}"
        )
        level = "good"

    return {
        "generated_at": _now_text(),
        "prometheus_base_url": PROMETHEUS_BASE_URL,
        "service_name": normalized_service,
        "namespace": namespace_value,
        "path": normalized_path or None,
        "window": window,
        "request_metric": base_metric,
        "request_rate_per_second": request_rate,
        "total_requests": round(total_requests, 2),
        "error_requests": round(error_requests, 2),
        "error_rate_percent": error_rate,
        "latency_available": latency_available,
        "latency_p95_ms": latency_p95_ms,
        "queries": {
            "rate": rate_query,
            "errors": error_query,
            "total": total_query,
            "latency_p95": latency_query,
        },
        "summary": summary,
        "level": level,
    }


def get_infrastructure_saturation(
    component_type: str,
    target_name: str | None = None,
    namespace: str | None = None,
    window: str = "5m",
) -> dict[str, Any]:
    normalized_component = (component_type or "").strip().lower()
    if normalized_component not in {"node", "mysql", "redis"}:
        return _error_payload(
            "unsupported component_type",
            requested_component_type=component_type,
            valid_component_types=["node", "mysql", "redis"],
        )

    namespace_value = ""
    if namespace is not None:
        namespace_value, namespace_error = _validate_namespace(namespace)
        if namespace_error:
            return namespace_error

    if normalized_component == "node":
        queries = {
            "cpu_idle": f'avg by (instance) (rate(node_cpu_seconds_total{{mode="idle"}}[{window}]))',
            "memory_available": f"{DEFAULT_NODE_MEMORY_AVAILABLE_METRIC}",
            "memory_total": f"{DEFAULT_NODE_MEMORY_TOTAL_METRIC}",
            "disk_available": (
                f'{DEFAULT_NODE_FILESYSTEM_METRIC}{{fstype!~"tmpfs|overlay",mountpoint="/"}}'
            ),
            "disk_total": (
                f'{DEFAULT_NODE_FILESYSTEM_SIZE_METRIC}{{fstype!~"tmpfs|overlay",mountpoint="/"}}'
            ),
        }

        try:
            cpu_data = _query_instant(queries["cpu_idle"])
            mem_avail_data = _query_instant(queries["memory_available"])
            mem_total_data = _query_instant(queries["memory_total"])
            disk_avail_data = _query_instant(queries["disk_available"])
            disk_total_data = _query_instant(queries["disk_total"])
        except RuntimeError as exc:
            return _error_payload(str(exc), component_type=normalized_component, target_name=target_name)

        cpu_map: dict[str, float] = {}
        for item in _vector_to_number_map(cpu_data.get("result", [])):
            instance = item.get("metric", {}).get("instance", "")
            if target_name and target_name not in instance:
                continue
            cpu_map[instance] = round((1 - item.get("value", 0.0)) * 100, 2)

        mem_avail_map: dict[str, float] = {}
        mem_total_map: dict[str, float] = {}
        disk_avail_map: dict[str, float] = {}
        disk_total_map: dict[str, float] = {}

        for item in _vector_to_number_map(mem_avail_data.get("result", [])):
            instance = item.get("metric", {}).get("instance", "")
            if target_name and target_name not in instance:
                continue
            mem_avail_map[instance] = item.get("value", 0.0)
        for item in _vector_to_number_map(mem_total_data.get("result", [])):
            instance = item.get("metric", {}).get("instance", "")
            if target_name and target_name not in instance:
                continue
            mem_total_map[instance] = item.get("value", 0.0)
        for item in _vector_to_number_map(disk_avail_data.get("result", [])):
            instance = item.get("metric", {}).get("instance", "")
            if target_name and target_name not in instance:
                continue
            disk_avail_map[instance] = item.get("value", 0.0)
        for item in _vector_to_number_map(disk_total_data.get("result", [])):
            instance = item.get("metric", {}).get("instance", "")
            if target_name and target_name not in instance:
                continue
            disk_total_map[instance] = item.get("value", 0.0)

        instances = sorted(
            set(cpu_map.keys()) | set(mem_avail_map.keys()) | set(mem_total_map.keys()) | set(disk_avail_map.keys()) | set(disk_total_map.keys())
        )

        items: list[dict[str, Any]] = []
        for instance in instances:
            mem_total = mem_total_map.get(instance, 0.0)
            mem_avail = mem_avail_map.get(instance, 0.0)
            disk_total = disk_total_map.get(instance, 0.0)
            disk_avail = disk_avail_map.get(instance, 0.0)
            mem_used_pct = round(((mem_total - mem_avail) / mem_total) * 100, 2) if mem_total > 0 else None
            disk_used_pct = round(((disk_total - disk_avail) / disk_total) * 100, 2) if disk_total > 0 else None
            items.append(
                {
                    "instance": instance,
                    "cpu_usage_percent": cpu_map.get(instance),
                    "memory_used_percent": mem_used_pct,
                    "disk_used_percent": disk_used_pct,
                    "memory_available_gib": round(mem_avail / 1024 / 1024 / 1024, 2) if mem_avail > 0 else 0.0,
                    "disk_available_gib": round(disk_avail / 1024 / 1024 / 1024, 2) if disk_avail > 0 else 0.0,
                }
            )

        if not items:
            return _error_payload(
                "no node saturation data found",
                component_type=normalized_component,
                target_name=target_name,
                queries=queries,
            )

        hottest = max(
            items,
            key=lambda item: max(
                item.get("cpu_usage_percent") or 0,
                item.get("memory_used_percent") or 0,
                item.get("disk_used_percent") or 0,
            ),
        )
        summary = (
            f"当前最需要关注的节点是 {hottest['instance']}，"
            f"CPU {hottest.get('cpu_usage_percent')}%，"
            f"内存使用 {hottest.get('memory_used_percent')}%，"
            f"磁盘使用 {hottest.get('disk_used_percent')}%。"
        )

        return {
            "generated_at": _now_text(),
            "prometheus_base_url": PROMETHEUS_BASE_URL,
            "component_type": normalized_component,
            "target_name": target_name or "",
            "window": window,
            "summary": summary,
            "items": items,
            "queries": queries,
        }

    namespace_for_workload = namespace_value or "data-services"
    target_filter = ""
    if target_name:
        target_filter = f',pod=~".*{_promql_quote(target_name)}.*"'

    if normalized_component == "mysql":
        queries = {
            "cpu": (
                f'sum(rate(container_cpu_usage_seconds_total{{namespace="{_promql_quote(namespace_for_workload)}",'
                f'container!="",pod!="",image!=""{target_filter}}}[{window}])) by (pod)'
            ),
            "memory": (
                f'sum(container_memory_working_set_bytes{{namespace="{_promql_quote(namespace_for_workload)}",'
                f'container!="",pod!="",image!=""{target_filter}}}) by (pod)'
            ),
        }
    else:
        queries = {
            "cpu": (
                f'sum(rate(container_cpu_usage_seconds_total{{namespace="{_promql_quote(namespace_for_workload)}",'
                f'container!="",pod!="",image!=""{target_filter}}}[{window}])) by (pod)'
            ),
            "memory": (
                f'sum(container_memory_working_set_bytes{{namespace="{_promql_quote(namespace_for_workload)}",'
                f'container!="",pod!="",image!=""{target_filter}}}) by (pod)'
            ),
        }

    try:
        cpu_data = _query_instant(queries["cpu"])
        mem_data = _query_instant(queries["memory"])
    except RuntimeError as exc:
        return _error_payload(
            str(exc),
            component_type=normalized_component,
            target_name=target_name,
            namespace=namespace_for_workload,
        )

    cpu_map: dict[str, float] = {}
    mem_map: dict[str, float] = {}
    for item in _vector_to_number_map(cpu_data.get("result", [])):
        pod = item.get("metric", {}).get("pod", "")
        cpu_map[pod] = round(item.get("value", 0.0), 4)
    for item in _vector_to_number_map(mem_data.get("result", [])):
        pod = item.get("metric", {}).get("pod", "")
        mem_map[pod] = round(item.get("value", 0.0) / 1024 / 1024, 2)

    items = [
        {"pod": pod, "cpu_cores": cpu_map.get(pod, 0.0), "memory_mib": mem_map.get(pod, 0.0)}
        for pod in sorted(set(cpu_map.keys()) | set(mem_map.keys()))
    ]

    if not items:
        return _error_payload(
            "no workload saturation data found",
            component_type=normalized_component,
            target_name=target_name,
            namespace=namespace_for_workload,
            queries=queries,
        )

    hottest = max(items, key=lambda item: max(item.get("cpu_cores", 0.0), item.get("memory_mib", 0.0)))
    summary = (
        f"{normalized_component} 相关工作负载中最需要关注的是 {hottest['pod']}，"
        f"CPU {hottest.get('cpu_cores')} cores，"
        f"内存 {hottest.get('memory_mib')} MiB。"
    )

    return {
        "generated_at": _now_text(),
        "prometheus_base_url": PROMETHEUS_BASE_URL,
        "component_type": normalized_component,
        "namespace": namespace_for_workload,
        "target_name": target_name or "",
        "window": window,
        "summary": summary,
        "items": items,
        "queries": queries,
    }

METRICS_TOOLS: list[dict[str, Any]] = [
    {
        "name": "get_business_success_rate_context",
        "label": "购买成功率与技术SLI口径",
        "spec": {
            "type": "function",
            "function": {
                "name": "get_business_success_rate_context",
                "description": (
                    "购买成功率KPI与技术可用性SLI的唯一口径工具。一次返回页面展示的"
                    "实例累计购买成功率、最近15分钟购买成功率、最近30天技术可用性SLI、"
                    "99.9%技术SLO目标及剩余错误预算，并返回各自的PromQL、分子分母、"
                    "业务排除项、技术失败项和结果分布。"
                    "当用户提到购买成功率、页面SLI、SLO目标、错误预算、"
                    "成功率计算方法，或质疑不同成功率数值不一致时，必须优先使用本工具。"
                    "禁止自行选择24小时等其他窗口来解释实例累计值。"
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "namespace": {
                            "type": "string",
                            "description": (
                                "可选。业务命名空间，默认 data-services。"
                            ),
                        },
                    },
                },
            },
        },
        "handler": get_business_success_rate_context,
    },
    {
        "name": "get_business_overview",
        "label": "业务总览",
        "spec": {
            "type": "function",
            "function": {
                "name": "get_business_overview",
                "description": (
                    "获取指定窗口的订单结果总览，返回原始请求数、按参数排除后的有效请求数、"
                    "购买成功数、购买成功率和完整结果分布。"
                    "默认统计最近 15 分钟 increase，不是 Counter 终身累计。"
                    "默认购买成功率仅从分母排除 duplicate_order 和 duplicate_request。"
                    "适合分析业务转化和指定告警窗口的订单结果分布，但它不是技术SLI工具。"
                    "不得用本工具的临时窗口解释页面实例累计值或30天SLI；"
                    "这些问题必须使用 get_business_success_rate_context。"
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "metric_name": {
                            "type": "string",
                            "description": "可选。业务指标名，默认使用 seckill_order_total。",
                        },
                        "namespace": {
                            "type": "string",
                            "description": "可选。命名空间，通常为 data-services。",
                        },
                        "success_label": {
                            "type": "string",
                            "description": "可选。成功结果标签，默认 success。",
                        },
                        "window": {
                            "type": "string",
                            "description": "可选。统计窗口，如 5m / 15m / 1h，默认 15m。",
                        },
                        "excluded_results": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": (
                                "可选。从成功率分母排除的 result 标签。默认排除 "
                                "duplicate_order 和 duplicate_request。"
                            ),
                        },
                    },
                },
            },
        },
        "handler": get_business_overview,
    },
    {
        "name": "get_metric_value",
        "label": "指标查询",
        "spec": {
            "type": "function",
            "function": {
                "name": "get_metric_value",
                "description": (
                    "执行 Prometheus 即时查询，获取某个指标当前值。"
                    "必须区分 result_count=0 与真实值 value=0："
                    "result_count=0 或工具返回 error 时，若怀疑指标名或标签不匹配，"
                    "可调用 search_knowledge_base 检索“组件 + 指标目的 + PromQL 标签映射”，"
                    "按本环境映射修改参数后最多重试一次；"
                    "result_count>0 时即使 value=0 也表示已取得真实序列，不要触发该回退。"
                    "请优先使用以下指标字典，不要编造指标名：\n"
                    f"{METRIC_DICTIONARY_TEXT}"
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "promql": {
                            "type": "string",
                            "description": "必填。PromQL 查询语句。",
                        },
                        "metric_label": {
                            "type": "string",
                            "description": "可选。返回结果中的中文指标名，例如 成功率、节点 CPU。",
                        },
                        "namespace": {
                            "type": "string",
                            "description": "可选。若需要按命名空间过滤，可传 aiops、data-services、monitoring。",
                        },
                    },
                    "required": ["promql"],
                },
            },
        },
        "handler": get_metric_value,
    },
    {
        "name": "get_metric_trend",
        "label": "指标趋势",
        "spec": {
            "type": "function",
            "function": {
                "name": "get_metric_trend",
                "description": (
                    "执行 Prometheus 区间查询，获取指标趋势，并返回 pattern 与 trend_summary，"
                    "用于区分毛刺、持续恶化、稳定高位等情况。"
                    "首次查询没有时间序列或返回 error 时，可调用 search_knowledge_base "
                    "检索本环境 PromQL 标签映射，修正参数后最多重试一次；"
                    "重试仍无数据则按证据不足处理，禁止继续循环查询。"
                    "请优先使用以下指标字典，不要编造指标名：\n"
                    f"{METRIC_DICTIONARY_TEXT}"
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "promql": {
                            "type": "string",
                            "description": "必填。PromQL 查询语句。",
                        },
                        "window": {
                            "type": "string",
                            "description": "可选。时间窗口，例如 30m、1h、6h。默认 30m。",
                        },
                        "step": {
                            "type": "string",
                            "description": "可选。采样步长，例如 1m、5m。默认 1m。",
                        },
                        "metric_label": {
                            "type": "string",
                            "description": "可选。返回结果中的中文指标名。",
                        },
                        "start_at": {
                            "type": "string",
                            "description": (
                                "可选。明确查询起点，必须使用带时区的 ISO 8601 时间。"
                                "必须与 end_at 同时提供。告警分析应优先查询告警发生前后的历史区间。"
                            ),
                        },
                        "end_at": {
                            "type": "string",
                            "description": (
                                "可选。明确查询终点，必须使用带时区的 ISO 8601 时间。"
                                "必须与 start_at 同时提供。"
                            ),
                        },
                        "threshold": {
                            "type": "number",
                            "description": (
                                "可选。告警规则阈值。提供后结合 threshold_direction "
                                "返回违反阈值的样本数、近似持续时间和首次违反时间。"
                            ),
                        },
                        "threshold_direction": {
                            "type": "string",
                            "enum": ["above", "below"],
                            "description": (
                                "可选。above 表示高于阈值异常，below 表示低于阈值异常；"
                                "默认 above。告警分析必须与规则比较符方向一致。"
                            ),
                        },
                        "series_match": {
                            "type": "object",
                            "description": (
                                "可选。限定唯一时间序列的标签，例如 "
                                '{"instance":"worker-biz"}。若查询返回多条序列，'
                                "必须传入该参数或修改 PromQL 聚合到单条序列。"
                            ),
                            "additionalProperties": {"type": "string"},
                        },
                        "condition_promql": {
                            "type": "string",
                            "description": (
                                "可选。完整告警条件 PromQL。提供后，违反阈值样本只统计"
                                "完整条件同时成立的采样点，适用于带附加门槛的复合告警。"
                            ),
                        },
                    },
                    "required": ["promql"],
                },
            },
        },
        "handler": get_metric_trend,
    },
    {
        "name": "compare_metric_time_shift",
        "label": "时序对比",
        "spec": {
            "type": "function",
            "function": {
                "name": "compare_metric_time_shift",
                "description": (
                    "对比当前指标值与过去某个偏移时间点的值，"
                    "适合回答今天和昨天同一时段相比如何、是否属于周期性高峰这类问题。"
                    "请优先使用以下指标字典，不要编造指标名：\n"
                    f"{METRIC_DICTIONARY_TEXT}"
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "promql": {
                            "type": "string",
                            "description": "必填。PromQL 查询语句。",
                        },
                        "offset": {
                            "type": "string",
                            "description": "可选。偏移量，可传 1h、6h、12h、1d、7d。默认 1d。",
                        },
                        "metric_label": {
                            "type": "string",
                            "description": "可选。返回结果中的中文指标名。",
                        },
                    },
                    "required": ["promql"],
                },
            },
        },
        "handler": compare_metric_time_shift,
    },
    {
        "name": "get_topk_resource_consumers",
        "label": "资源 TopK",
        "spec": {
            "type": "function",
            "function": {
                "name": "get_topk_resource_consumers",
                "description": (
                    "查询当前最占 CPU 或内存的 Pod TopK。"
                    "适合回答谁最占资源、哪个 Pod 导致节点负载升高这类问题。"
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "resource_type": {
                            "type": "string",
                            "description": "必填。资源类型，可传 cpu 或 memory。",
                        },
                        "namespace": {
                            "type": "string",
                            "description": "可选。命名空间过滤，可传 aiops、data-services、monitoring。",
                        },
                        "top_n": {
                            "type": "integer",
                            "description": "可选。返回前多少个资源使用者，默认 5。",
                        },
                        "window": {
                            "type": "string",
                            "description": "可选。CPU 查询窗口，例如 5m、15m。默认 5m。",
                        },
                    },
                    "required": ["resource_type"],
                },
            },
        },
        "handler": get_topk_resource_consumers,
    },
    {
        "name": "get_node_top_pods",
        "label": "节点 Pod TopK",
        "spec": {
            "type": "function",
            "function": {
                "name": "get_node_top_pods",
                "description": (
                    "查询指定 Kubernetes 节点上 CPU 或内存占用最高的 Pod。"
                    "当节点资源告警需要定位具体资源消费者时调用；"
                    "node_name 必须是节点名，不能把节点名作为 namespace 传入。"
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "node_name": {
                            "type": "string",
                            "description": "必填。Kubernetes 节点名，例如 worker-biz。",
                        },
                        "resource_type": {
                            "type": "string",
                            "enum": ["cpu", "memory"],
                            "description": "必填。需要排序的资源类型。",
                        },
                        "top_n": {
                            "type": "integer",
                            "description": "可选。返回前多少个 Pod，默认 5，最大 20。",
                        },
                        "window": {
                            "type": "string",
                            "description": (
                                "可选。CPU 速率窗口，应与告警规则中的 rate 窗口一致；"
                                "例如规则使用 [1m] 时这里传 1m。"
                            ),
                        },
                        "at_time": {
                            "type": "string",
                            "description": (
                                "可选。按 ISO 8601 时间查询历史时点 TopK。"
                                "告警分析应传入告警窗口结束时间，避免把恢复后的当前值当作告警期证据。"
                            ),
                        },
                    },
                    "required": ["node_name", "resource_type"],
                },
            },
        },
        "handler": get_node_top_pods,
    },
    {
        "name": "get_pod_resource_trend",
        "label": "Pod 资源趋势",
        "spec": {
            "type": "function",
            "function": {
                "name": "get_pod_resource_trend",
                "description": (
                    "查询指定 Pod 在明确告警时间窗内的 CPU 或内存历史趋势。"
                    "当 TopK 找到可疑 Pod 后，必须使用本工具验证它是否与节点异常同步上升或回落；"
                    "不能用恢复后的瞬时 TopK 直接确认根因。"
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "namespace": {
                            "type": "string",
                            "description": "必填。Pod 所在命名空间。",
                        },
                        "pod_name": {
                            "type": "string",
                            "description": "必填。TopK 返回的完整 Pod 名。",
                        },
                        "resource_type": {
                            "type": "string",
                            "enum": ["cpu", "memory"],
                            "description": "必填。需要验证的资源类型。",
                        },
                        "start_at": {
                            "type": "string",
                            "description": "必填。带时区的 ISO 8601 告警窗口开始时间。",
                        },
                        "end_at": {
                            "type": "string",
                            "description": "必填。带时区的 ISO 8601 告警窗口结束时间。",
                        },
                        "step": {
                            "type": "string",
                            "description": "可选。Prometheus 采样步长，默认 1m。",
                        },
                        "node_name": {
                            "type": "string",
                            "description": (
                                "可选。Pod 所在节点。CPU 分析时传入后会查询节点 CPU 核数，"
                                "并返回 Pod 峰值占节点总容量的百分比。"
                            ),
                        },
                    },
                    "required": [
                        "namespace",
                        "pod_name",
                        "resource_type",
                        "start_at",
                        "end_at"
                    ],
                },
            },
        },
        "handler": get_pod_resource_trend,
    },
    {
        "name": "get_service_golden_signals",
        "label": "黄金指标",
        "spec": {
            "type": "function",
            "function": {
                "name": "get_service_golden_signals",
                "description": (
                    "获取某个服务在最近一段时间内的黄金指标摘要。"
                    "主要返回请求量、错误量、错误率，以及可用时的 P95 延迟。"
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "service_name": {
                            "type": "string",
                            "description": "必填。服务名，例如 biz-gateway / biz-gateway-svc（业务网关，通常在 data-services；历史名 aiops-gateway）。",
                        },
                        "namespace": {
                            "type": "string",
                            "description": "必填。命名空间，例如 data-services、aiops、monitoring。",
                        },
                        "window": {
                            "type": "string",
                            "description": "可选。查询窗口，例如 5m、15m、30m。默认 5m。",
                        },
                        "path": {
                            "type": "string",
                            "description": "可选。限定 HTTP 路径，例如 /api/seckill/order。",
                        },
                    },
                    "required": ["service_name", "namespace"],
                },
            },
        },
        "handler": get_service_golden_signals,
    },
    {
        "name": "get_infrastructure_saturation",
        "label": "资源饱和度",
        "spec": {
            "type": "function",
            "function": {
                "name": "get_infrastructure_saturation",
                "description": (
                    "检查基础设施或关键组件是否处于资源饱和状态。"
                    "当前支持 node、mysql、redis 三类组件。"
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "component_type": {
                            "type": "string",
                            "description": "必填。组件类型，可传 node、mysql、redis。",
                        },
                        "target_name": {
                            "type": "string",
                            "description": "可选。指定节点名或组件关键字，例如 worker-ai、mysql、redis。",
                        },
                        "namespace": {
                            "type": "string",
                            "description": "可选。命名空间，mysql/redis 默认走 data-services。",
                        },
                        "window": {
                            "type": "string",
                            "description": "可选。查询窗口，例如 5m、15m。默认 5m。",
                        },
                    },
                    "required": ["component_type"],
                },
            },
        },
        "handler": get_infrastructure_saturation,
    },
]
