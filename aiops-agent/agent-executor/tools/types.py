from __future__ import annotations

from typing import Any, Callable

ToolHandler = Callable[..., Any]
ToolSpec = dict[str, Any]
ToolDefinition = dict[str, Any]
