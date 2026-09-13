from alerting.analysis_models import (
    IncidentAnalysisEvent,
    IncidentAnalysisRun,
)
from alerting.classifier import (
    AlertClassification,
    ClassificationConfidence,
    ClassificationHint,
    classify_alert_labels,
)
from alerting.models import (
    AlertIngestionItem,
    AlertIngestionResult,
    NormalizedAlert,
)
from alerting.normalizer import (
    build_fallback_fingerprint,
    normalize_alertmanager_alert,
)


def ingest_alertmanager_payload(*args, **kwargs):
    from alerting.ingestion import ingest_alertmanager_payload as _ingest

    return _ingest(*args, **kwargs)


def __getattr__(name: str):
    if name == "IncidentAnalysisRunner":
        from alerting.analysis_runner import IncidentAnalysisRunner

        return IncidentAnalysisRunner
    if name == "IncidentAnalysisAgent":
        from alerting.analysis_agent import IncidentAnalysisAgent

        return IncidentAnalysisAgent
    if name == "IncidentRecheckScheduler":
        from alerting.recheck_scheduler import IncidentRecheckScheduler

        return IncidentRecheckScheduler
    if name == "INCIDENT_READ_ONLY_TOOL_NAMES":
        from alerting.analysis_agent import INCIDENT_READ_ONLY_TOOL_NAMES

        return INCIDENT_READ_ONLY_TOOL_NAMES
    if name == "filter_incident_read_only_tool_specs":
        from alerting.analysis_agent import filter_incident_read_only_tool_specs

        return filter_incident_read_only_tool_specs
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "AlertClassification",
    "AlertIngestionItem",
    "AlertIngestionResult",
    "ClassificationConfidence",
    "ClassificationHint",
    "INCIDENT_READ_ONLY_TOOL_NAMES",
    "IncidentAnalysisAgent",
    "IncidentAnalysisEvent",
    "IncidentAnalysisRunner",
    "IncidentAnalysisRun",
    "IncidentRecheckScheduler",
    "NormalizedAlert",
    "build_fallback_fingerprint",
    "classify_alert_labels",
    "filter_incident_read_only_tool_specs",
    "ingest_alertmanager_payload",
    "normalize_alertmanager_alert",
]
