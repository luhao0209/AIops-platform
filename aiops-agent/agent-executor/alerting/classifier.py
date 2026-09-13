from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


AlertClassification = Literal[
    "real_resource_anomaly",
    "synthetic_test_alert",
    "monitoring_configuration_issue",
    "stale_or_orphan_alert",
    "unknown",
]

ClassificationConfidence = Literal[
    "low",
    "medium",
    "high",
    "confirmed",
]


@dataclass(frozen=True)
class ClassificationHint:
    classification: AlertClassification
    confidence: ClassificationConfidence
    reason: str
    deterministic: bool = False


def classify_alert_labels(
    labels: dict[str, str],
) -> ClassificationHint:
    synthetic = (
        labels.get("synthetic", "")
        .strip()
        .lower()
    )

    if synthetic in {"true", "1", "yes"}:
        return ClassificationHint(
            classification="synthetic_test_alert",
            confidence="confirmed",
            reason="告警标签明确包含 synthetic=true。",
            deterministic=True,
        )

    return ClassificationHint(
        classification="unknown",
        confidence="low",
        reason="暂无结构化标签可以确认告警类型。",
    )
