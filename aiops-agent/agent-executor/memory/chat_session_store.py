from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from uuid import uuid4

from memory.chat_memory_store import DEFAULT_DB_PATH
from memory.models import ChatMessage, ChatSession, utc_now


class ChatSessionStore:
    def __init__(self, db_path: str | Path | None = None) -> None:
        self.db_path = Path(db_path) if db_path else DEFAULT_DB_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=5)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS chat_sessions (
                    session_id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS chat_messages (
                    message_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    role TEXT NOT NULL,
                    content TEXT NOT NULL,
                    metadata_json TEXT NOT NULL DEFAULT '{}',
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(session_id)
                        REFERENCES chat_sessions(session_id)
                        ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS idx_chat_sessions_updated_at
                    ON chat_sessions(updated_at DESC);

                CREATE INDEX IF NOT EXISTS idx_chat_messages_session
                    ON chat_messages(session_id, message_id);
                """
            )
            conn.commit()

    def create_session(
        self,
        session_id: str | None = None,
        title: str = "新对话",
    ) -> ChatSession:
        session = ChatSession(
            session_id=session_id or f"chat-{uuid4()}",
            title=title.strip() or "新对话",
        )

        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO chat_sessions (
                    session_id, title, status, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    session.session_id,
                    session.title,
                    session.status,
                    session.created_at.isoformat(),
                    session.updated_at.isoformat(),
                ),
            )
            conn.commit()

        return session

    def get_or_create(self, session_id: str) -> ChatSession:
        existing = self.get_session(session_id)
        if existing is not None:
            return existing
        return self.create_session(session_id=session_id)

    def get_session(self, session_id: str) -> ChatSession | None:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT session_id, title, status, created_at, updated_at
                FROM chat_sessions
                WHERE session_id = ?
                """,
                (session_id,),
            ).fetchone()

        if row is None:
            return None
        return ChatSession.model_validate(dict(row))

    def list_sessions(
        self,
        limit: int = 50,
        status: str = "active",
    ) -> list[ChatSession]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT session_id, title, status, created_at, updated_at
                FROM chat_sessions
                WHERE status = ?
                ORDER BY updated_at DESC
                LIMIT ?
                """,
                (status, max(1, min(limit, 100))),
            ).fetchall()

        return [ChatSession.model_validate(dict(row)) for row in rows]

    def append_message(
        self,
        session_id: str,
        role: str,
        content: str,
        metadata: dict | None = None,
    ) -> ChatMessage:
        session = self.get_or_create(session_id)
        message = ChatMessage(
            session_id=session_id,
            role=role,
            content=content.strip(),
            metadata=metadata or {},
        )

        with self._connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO chat_messages (
                    session_id, role, content, metadata_json, created_at
                )
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    message.session_id,
                    message.role,
                    message.content,
                    json.dumps(message.metadata, ensure_ascii=False),
                    message.created_at.isoformat(),
                ),
            )

            title = session.title
            if role == "user" and title == "新对话" and message.content:
                title = message.content[:30]

            now = utc_now().isoformat()
            conn.execute(
                """
                UPDATE chat_sessions
                SET title = ?, updated_at = ?
                WHERE session_id = ?
                """,
                (title, now, session_id),
            )
            conn.commit()

        message.message_id = int(cursor.lastrowid)
        return message

    def list_messages(
        self,
        session_id: str,
        limit: int = 200,
    ) -> list[ChatMessage]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT message_id, session_id, role, content,
                       metadata_json, created_at
                FROM chat_messages
                WHERE session_id = ?
                ORDER BY message_id ASC
                LIMIT ?
                """,
                (session_id, max(1, min(limit, 500))),
            ).fetchall()

        messages: list[ChatMessage] = []
        for row in rows:
            messages.append(
                ChatMessage(
                    message_id=row["message_id"],
                    session_id=row["session_id"],
                    role=row["role"],
                    content=row["content"],
                    metadata=json.loads(row["metadata_json"] or "{}"),
                    created_at=row["created_at"],
                )
            )
        return messages

    def list_messages_after(
        self,
        session_id: str,
        after_message_id: int = 0,
        limit: int = 200,
    ) -> list[ChatMessage]:
        normalized_after_id = max(
            0,
            int(after_message_id),
        )
        normalized_limit = max(
            1,
            min(int(limit), 500),
        )

        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT message_id,
                       session_id,
                       role,
                       content,
                       metadata_json,
                       created_at
                FROM chat_messages
                WHERE session_id = ?
                  AND message_id > ?
                ORDER BY message_id ASC
                LIMIT ?
                """,
                (
                    session_id,
                    normalized_after_id,
                    normalized_limit,
                ),
            ).fetchall()

        messages: list[ChatMessage] = []

        for row in rows:
            messages.append(
                ChatMessage(
                    message_id=row["message_id"],
                    session_id=row["session_id"],
                    role=row["role"],
                    content=row["content"],
                    metadata=json.loads(
                        row["metadata_json"] or "{}"
                    ),
                    created_at=row["created_at"],
                )
            )

        return messages

    def rename_session(self, session_id: str, title: str) -> bool:
        with self._connect() as conn:
            cursor = conn.execute(
                """
                UPDATE chat_sessions
                SET title = ?, updated_at = ?
                WHERE session_id = ?
                """,
                (title.strip() or "新对话", utc_now().isoformat(), session_id),
            )
            conn.commit()
        return cursor.rowcount > 0

    def archive_session(self, session_id: str) -> bool:
        with self._connect() as conn:
            cursor = conn.execute(
                """
                UPDATE chat_sessions
                SET status = 'archived', updated_at = ?
                WHERE session_id = ?
                """,
                (utc_now().isoformat(), session_id),
            )
            conn.commit()
        return cursor.rowcount > 0

    def delete_session(self, session_id: str) -> bool:
        with self._connect() as conn:
            cursor = conn.execute(
                "DELETE FROM chat_sessions WHERE session_id = ?",
                (session_id,),
            )
            conn.commit()
        return cursor.rowcount > 0
