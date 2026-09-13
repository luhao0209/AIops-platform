from __future__ import annotations

from datetime import datetime
from typing import Any

from alerting.models import AlertIngestionItem, AlertIngestionResult
from alerting.normalizer import normalize_alertmanager_alert
from memory import IncidentMemoryStore, parse_utc_datetime, utc_now


def ingest_alertmanager_payload(
    payload: dict[str, Any],
    store: IncidentMemoryStore,
    *,
    received_at: datetime | str | None = None,
    webhook_source: str = "",
) -> AlertIngestionResult:
    """Normalize and persist one Alertmanager webhook batch."""
    if not isinstance(payload, dict):
        raise ValueError("payload must be an object")

    alerts = payload.get("alerts", [])
    if not isinstance(alerts, list):
        raise ValueError("payload.alerts must be a list")

    received_at_value = parse_utc_datetime(received_at) or utc_now()
    batch_status = str(payload.get("status") or "")
    group_key = str(payload.get("groupKey") or "")
    receiver = str(payload.get("receiver") or "")
    items: list[AlertIngestionItem] = []

    for index, raw_alert in enumerate(alerts):
        try:
            normalized = normalize_alertmanager_alert(
                raw_alert,
                batch_status=batch_status,
                group_key=group_key,
                receiver=receiver,
                webhook_source=webhook_source,
            )
            stored = store.record_notification(
                fingerprint=normalized.fingerprint,
                alert_name=normalized.alert_name,
                alert_status=normalized.status,
                starts_at=normalized.starts_at,
                ends_at=normalized.ends_at,
                received_at=received_at_value,
                severity=normalized.severity,
                namespace=normalized.namespace,
                target=normalized.target,
                group_key=normalized.group_key,
                receiver=normalized.receiver,
                generator_url=normalized.generator_url,
                source=normalized.source,
                webhook_source=normalized.webhook_source,
                labels=normalized.labels,
                annotations=normalized.annotations,
            )
            items.append(
                AlertIngestionItem(
                    index=index,
                    status="accepted",
                    incident_id=stored.incident.incident_id,
                    fingerprint=normalized.fingerprint,
                    alert_name=normalized.alert_name,
                    created=stored.created,
                )
            )
        except (TypeError, ValueError) as exc:
            items.append(
                AlertIngestionItem(
                    index=index,
                    status="rejected",
                    error=str(exc),
                )
            )

    accepted = sum(item.status == "accepted" for item in items)
    return AlertIngestionResult(
        received_at=received_at_value,
        total=len(alerts),
        accepted=accepted,
        rejected=len(items) - accepted,
        items=items,
    )
