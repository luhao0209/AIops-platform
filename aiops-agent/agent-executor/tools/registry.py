from __future__ import annotations

from typing import Any

from tool_runtime import execute_registered_tool

from .alert_tools import ALERT_TOOLS
from .change_tools import CHANGE_TOOLS
from .incident_tools import INCIDENT_TOOLS
from .incident_skill_tools import INCIDENT_SKILL_TOOLS
from .knowledge_tools import KNOWLEDGE_TOOLS
from .kubernetes_event_tools import KUBERNETES_EVENT_TOOLS
from .log_tools import LOG_TOOLS
from .metrics_tools import METRICS_TOOLS
from .reliability_tools import RELIABILITY_TOOLS
from .topology_tools import TOPOLOGY_TOOLS
from .workload_tools import WORKLOAD_TOOLS

ALL_TOOLS = (
    METRICS_TOOLS
    + RELIABILITY_TOOLS
    + TOPOLOGY_TOOLS
    + CHANGE_TOOLS
    + ALERT_TOOLS
    + INCIDENT_TOOLS
    + KUBERNETES_EVENT_TOOLS
    + LOG_TOOLS
    + KNOWLEDGE_TOOLS
    + WORKLOAD_TOOLS
)


INCIDENT_WORKFLOW_TOOLS = INCIDENT_SKILL_TOOLS

TOOL_REGISTRY: dict[str, dict[str, Any]] = {
    tool["name"]: tool
    for tool in (ALL_TOOLS + INCIDENT_WORKFLOW_TOOLS)
}

ALL_TOOL_SPECS: list[dict[str, Any]] = [
    tool["spec"]
    for tool in ALL_TOOLS
]

INCIDENT_TOOL_SPECS: list[dict[str, Any]] = [
    *ALL_TOOL_SPECS,
    *(tool["spec"] for tool in INCIDENT_WORKFLOW_TOOLS),
]


def execute_tool_call(tool_name: str, arguments: dict[str, Any]) -> Any:
    return execute_registered_tool(
        TOOL_REGISTRY,
        tool_name,
        arguments,
    )
