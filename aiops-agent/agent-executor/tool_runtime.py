from __future__ import annotations

import json
import time
from datetime import datetime
from typing import Any, Mapping


def parse_tool_arguments(arguments: Any) -> dict[str, Any]:
    if arguments is None:
        return {}
    if isinstance(arguments, dict):
        return arguments
    if isinstance(arguments, str):
        text = arguments.strip()
        if not text:
            return {}
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                f"tool arguments is not valid JSON: {arguments}"
            ) from exc
        if isinstance(parsed, dict):
            return parsed
        raise RuntimeError(
            f"tool arguments must be an object: {arguments}"
        )
    raise RuntimeError(
        "unsupported tool arguments type: "
        f"{type(arguments)}"
    )


def execute_registered_tool(
    registry: Mapping[str, dict[str, Any]],
    tool_name: str,
    arguments: Any,
) -> dict[str, Any]:
    tool = registry.get(tool_name)
    if not tool:
        raise RuntimeError(f"unsupported tool: {tool_name}")

    parsed_arguments = parse_tool_arguments(arguments)
    handler = tool["handler"]
    tool_label = tool.get("label", tool_name)
    started_at = time.time()

    try:
        result = handler(**parsed_arguments)
        status = "success"
    except Exception as exc:
        duration_ms = int((time.time() - started_at) * 1000)
        return {
            "error": str(exc),
            "trace": {
                "tool_name": tool_name,
                "tool_label": tool_label,
                "arguments": parsed_arguments,
                "status": "failed",
                "duration_ms": duration_ms,
                "timestamp": datetime.now().strftime("%H:%M:%S"),
            },
        }

    duration_ms = int((time.time() - started_at) * 1000)
    trace = {
        "tool_name": tool_name,
        "tool_label": tool_label,
        "arguments": parsed_arguments,
        "status": status,
        "duration_ms": duration_ms,
        "timestamp": datetime.now().strftime("%H:%M:%S"),
    }

    if isinstance(result, dict):
        trace["summary"] = (
            result.get("summary")
            or result.get("message")
            or ""
        )
        trace["query_used"] = (
            result.get("query_used")
            or result.get("query")
            or ""
        )
        result["trace"] = trace
        return result

    return {
        "result": result,
        "trace": trace,
    }
