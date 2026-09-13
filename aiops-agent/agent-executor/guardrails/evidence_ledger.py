from __future__ import annotations

from datetime import timedelta
from typing import Any
from uuid import uuid4

from guardrails.models import (
    EvidenceRecord,
    EvidenceStatus,
    utc_now,
)


NO_DATA_STATUSES = {
    "no_data",
    "no_samples",
    "no_match",
    "empty",
}

TIMEOUT_MARKERS = (
    "timeout",
    "timed out",
    "deadline exceeded",
)


def build_evidence_record(
    tool_name: str,
    arguments: dict[str, Any],
    result: Any,
    *,
    tool_call_id: str = "",
    ttl_seconds: int = 300,
) -> EvidenceRecord:
    observed_at = utc_now()
    status: EvidenceStatus = "success"
    summary = ""
    query_used = ""
    error = ""

    if isinstance(result, dict):
        trace = result.get("trace")
        trace = trace if isinstance(trace, dict) else {}

        summary = str(
            result.get("summary")
            or result.get("message")
            or ""
        )
        query_used = str(
            result.get("query_used")
            or result.get("query")
            or ""
        )
        error = str(result.get("error") or "")

        trace_status = str(
            trace.get("status") or ""
        ).lower()
        result_status = str(
            result.get("status") or ""
        ).lower()

        if error or trace_status in {"failed", "error"}:
            lowered_error = error.lower()
            if any(
                marker in lowered_error
                for marker in TIMEOUT_MARKERS
            ):
                status = "timeout"
            else:
                status = "failed"
        elif result_status in NO_DATA_STATUSES:
            status = "no_data"

        data = {
            key: value
            for key, value in result.items()
            if key not in {"trace", "_evidence"}
        }
    else:
        data = result

    return EvidenceRecord(
        evidence_id=f"ev_{uuid4().hex[:16]}",
        tool_name=tool_name,
        tool_call_id=tool_call_id,
        status=status,
        arguments=arguments,
        observed_at=observed_at,
        expires_at=observed_at + timedelta(
            seconds=max(1, ttl_seconds)
        ),
        summary=summary,
        query_used=query_used,
        data=data if status in {"success", "no_data"} else None,
        error=error,
    )
