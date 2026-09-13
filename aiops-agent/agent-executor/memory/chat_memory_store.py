from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from memory.models import ChatMemory, ChatMemoryLimits, utc_now


DEFAULT_DB_PATH = (
    Path(__file__).resolve().parents[1] / "data" / "memory" / "chat_memory.db"
)


class ChatMemoryStore:
    def __init__(
        self,
        db_path: str | Path | None = None,
        limits: ChatMemoryLimits | None = None,
    ) -> None:
        self.db_path = Path(db_path) if db_path else DEFAULT_DB_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.limits = limits or ChatMemoryLimits()
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS chat_memories (
                    session_id TEXT PRIMARY KEY,
                    memory_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            conn.commit()

    def _normalize_memory(self, memory: ChatMemory) -> ChatMemory:
        memory.recent_tools = memory.recent_tools[-self.limits.recent_tools :]
        memory.confirmed_facts = memory.confirmed_facts[
            -self.limits.confirmed_facts :
        ]
        memory.open_questions = [
            item.strip()
            for item in memory.open_questions
            if isinstance(item, str) and item.strip()
        ][-self.limits.open_questions :]
        memory.last_knowledge_chunks = memory.last_knowledge_chunks[
            -self.limits.last_knowledge_chunks :
        ]
        memory.user_corrections = memory.user_corrections[
            -self.limits.user_corrections :
        ]
        memory.updated_at = utc_now()
        return memory

    def get(self, session_id: str) -> ChatMemory | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT memory_json FROM chat_memories WHERE session_id = ?",
                (session_id,),
            ).fetchone()
        if not row:
            return None
        payload = json.loads(row["memory_json"])
        return ChatMemory.model_validate(payload)

    def get_or_create(self, session_id: str) -> ChatMemory:
        memory = self.get(session_id)
        if memory is not None:
            return memory
        memory = ChatMemory(session_id=session_id)
        self.save(memory)
        return memory

    def save(self, memory: ChatMemory) -> ChatMemory:
        normalized = self._normalize_memory(memory)
        payload = normalized.model_dump(mode="json")
        body = json.dumps(payload, ensure_ascii=False)
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO chat_memories (session_id, memory_json, created_at, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(session_id) DO UPDATE SET
                    memory_json = excluded.memory_json,
                    updated_at = excluded.updated_at
                """,
                (
                    normalized.session_id,
                    body,
                    normalized.created_at.isoformat(),
                    normalized.updated_at.isoformat(),
                ),
            )
            conn.commit()
        return normalized

    def delete(self, session_id: str) -> bool:
        with self._connect() as conn:
            cursor = conn.execute(
                "DELETE FROM chat_memories WHERE session_id = ?",
                (session_id,),
            )
            conn.commit()
        return cursor.rowcount > 0

    def clear_all(self) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM chat_memories")
            conn.commit()

    def list_sessions(self, limit: int = 100) -> list[str]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT session_id
                FROM chat_memories
                ORDER BY updated_at DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [row["session_id"] for row in rows]
