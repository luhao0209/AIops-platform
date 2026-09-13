from memory.chat_memory_store import ChatMemoryStore
from memory.chat_session_store import ChatSessionStore
from memory.chat_summary_store import ChatSummaryStore
from memory.incident_memory_store import IncidentMemoryStore
from memory.context_builder import (
    build_chat_memory_context,
    build_chat_summary_context,
    is_tool_memory_fresh,
)
from memory.summary_service import (
    build_summary_messages,
    generate_chat_summary,
    is_summary_model_configured,
)
from memory.summary_manager import (
    maybe_update_chat_summary,
)
from memory.models import (
    ChatMemory,
    ChatMemoryLimits,
    ChatMessage,
    ChatSession,
    ChatSummary,
    EntityMemory,
    FactMemory,
    Incident,
    IncidentEvent,
    IncidentRecordResult,
    KnowledgeChunkMemory,
    PendingEntityClarification,
    ToolMemory,
    UserCorrectionMemory,
    ensure_utc,
    format_utc_datetime,
    parse_utc_datetime,
    utc_now,
)

__all__ = [
    "ChatMemory",
    "ChatMemoryLimits",
    "ChatMemoryStore",
    "ChatMessage",
    "ChatSession",
    "ChatSessionStore",
    "ChatSummaryStore",
    "ChatSummary",
    "EntityMemory",
    "FactMemory",
    "Incident",
    "IncidentAnalysisEvent",
    "IncidentAnalysisRun",
    "IncidentAnalysisStore",
    "IncidentEvent",
    "IncidentMemoryStore",
    "IncidentRecordResult",
    "KnowledgeChunkMemory",
    "PendingEntityClarification",
    "ToolMemory",
    "UserCorrectionMemory",
    "build_chat_memory_context",
    "build_chat_summary_context",
    "build_summary_messages",
    "ensure_utc",
    "format_utc_datetime",
    "generate_chat_summary",
    "is_tool_memory_fresh",
    "is_summary_model_configured",
    "maybe_update_chat_summary",
    "parse_utc_datetime",
    "RemediationAction",
    "RemediationStore",
    "utc_now",
]


def __getattr__(name: str):



    if name == "IncidentAnalysisStore":
        from memory.incident_analysis_store import IncidentAnalysisStore

        return IncidentAnalysisStore
    if name == "IncidentAnalysisEvent":
        from alerting.analysis_models import IncidentAnalysisEvent

        return IncidentAnalysisEvent
    if name == "IncidentAnalysisRun":
        from alerting.analysis_models import IncidentAnalysisRun

        return IncidentAnalysisRun
    if name == "RemediationAction":
        from memory.remediation_store import RemediationAction

        return RemediationAction
    if name == "RemediationStore":
        from memory.remediation_store import RemediationStore

        return RemediationStore
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
