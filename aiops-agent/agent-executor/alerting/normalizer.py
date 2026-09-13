from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Any

from alerting.models import NormalizedAlert
from memory.models import parse_utc_datetime


ZERO_ENDS_AT_PREFIX = "0001-01-01T00:00:00"
TARGET_LABELS = (
    "pod",
    "deployment",
    "service",
    "node",
    "instance",
    "job",
)

ALERT_SCOPE_DEFAULTS: dict[str, tuple[str, str]] = {
    "OrderTechnicalAvailabilityLow": ("data-services", "biz-gateway"),
}


def _string_map(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    return {
        str(key): str(item)
        for key, item in value.items()
        if item is not None
    }


def build_fallback_fingerprint(labels: dict[str, str]) -> str:
    """Generate a stable fallback only when Alertmanager omits fingerprint."""
    canonical = json.dumps(
        sorted(labels.items()),
        ensure_ascii=False,
        separators=(",", ":"),
    )
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return f"generated-{digest[:32]}"


def _normalize_status(alert_status: Any, batch_status: Any) -> str:
    value = str(alert_status or batch_status or "").strip().lower()
    if value not in {"firing", "resolved"}:
        raise ValueError(f"unsupported alert status: {value or 'missing'}")
    return value


def _normalize_time(value: Any, *, allow_zero: bool = False) -> datetime | None:
    if value in (None, ""):
        return None
    text = str(value).strip() if not isinstance(value, datetime) else value
    if allow_zero and isinstance(text, str) and text.startswith(ZERO_ENDS_AT_PREFIX):
        return None
    return parse_utc_datetime(text)


def normalize_alertmanager_alert(
    alert: dict[str, Any],
    *,
    batch_status: str = "",
    group_key: str = "",
    receiver: str = "",
    webhook_source: str = "",
) -> NormalizedAlert:
    if not isinstance(alert, dict):
        raise ValueError("alert must be an object")

    labels = _string_map(alert.get("labels"))
    annotations = _string_map(alert.get("annotations"))
    alert_name = labels.get("alertname", "").strip()
    if not alert_name:
        raise ValueError("labels.alertname is required")

    fingerprint = str(alert.get("fingerprint") or "").strip()
    if not fingerprint:
        fingerprint = build_fallback_fingerprint(labels)

    target = next(
        (labels[name] for name in TARGET_LABELS if labels.get(name)),
        "",
    )
    default_namespace, default_target = ALERT_SCOPE_DEFAULTS.get(
        alert_name,
        ("", ""),
    )

    return NormalizedAlert(
        fingerprint=fingerprint,
        alert_name=alert_name,
        status=_normalize_status(alert.get("status"), batch_status),
        severity=labels.get("severity", ""),
        namespace=labels.get("namespace", "") or default_namespace,
        target=target or default_target,
        starts_at=_normalize_time(alert.get("startsAt")),
        ends_at=_normalize_time(alert.get("endsAt"), allow_zero=True),
        group_key=group_key,
        receiver=receiver,
        generator_url=str(
            alert.get("generatorURL") or ""
        ).strip(),
        source=labels.get("source", "").strip(),
        webhook_source=webhook_source.strip(),
        labels=labels,
        annotations=annotations,
    )
