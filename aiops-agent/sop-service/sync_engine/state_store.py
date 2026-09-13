from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class SyncStateStore:
    def __init__(self, state_file: str | Path) -> None:
        self.state_file = Path(state_file)
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        self.state: dict[str, Any] = self._load()

    def _load(self) -> dict[str, Any]:
        if not self.state_file.exists():
            return {"version": 1, "files": {}}

        try:
            return json.loads(self.state_file.read_text(encoding="utf-8"))
        except Exception:
            return {"version": 1, "files": {}}

    def save(self) -> None:
        self.state_file.write_text(
            json.dumps(self.state, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    def get_file_state(self, doc_id: str) -> dict[str, Any]:
        return self.state.setdefault("files", {}).get(doc_id, {})

    def update_file_state(self, doc_id: str, payload: dict[str, Any]) -> None:
        self.state.setdefault("files", {})[doc_id] = payload

    def remove_file_state(self, doc_id: str) -> None:
        self.state.setdefault("files", {}).pop(doc_id, None)

    def list_known_files(self) -> list[str]:
        return list(self.state.setdefault("files", {}).keys())