from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from memory.models import ChatSummary, utc_now


DEFAULT_DB_PATH = (
    Path(__file__).resolve().parents[1]
    / "data"
    / "memory"
    / "chat_memory.db"
)


class ChatSummaryStore:
    def __init__(
        self,
        db_path: str | Path | None = None,
    ) -> None:
        self.db_path = (
            Path(db_path)
            if db_path
            else DEFAULT_DB_PATH
        )
        self.db_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )
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
                CREATE TABLE IF NOT EXISTS chat_summaries (
                    session_id TEXT PRIMARY KEY,
                    summary_json TEXT NOT NULL,
                    summarized_until_message_id INTEGER NOT NULL,
                    summarized_message_count INTEGER NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            conn.commit()

    @staticmethod
    def _clean_items(
        items: list[str],
        *,
        limit: int = 10,
        item_length: int = 500,
    ) -> list[str]:
        cleaned: list[str] = []

        for item in items:
            if not isinstance(item, str):
                continue

            value = item.strip()
            if not value:
                continue

            if value not in cleaned:
                cleaned.append(value[:item_length])

        return cleaned[-limit:]

    def _normalize(
        self,
        summary: ChatSummary,
    ) -> ChatSummary:
        summary.conversation_goal = (
            summary.conversation_goal.strip()[:500]
        )
        summary.discussion_summary = (
            summary.discussion_summary.strip()[:6000]
        )

        summary.confirmed_context = self._clean_items(
            summary.confirmed_context
        )
        summary.hypotheses = self._clean_items(
            summary.hypotheses
        )
        summary.open_questions = self._clean_items(
            summary.open_questions
        )
        summary.user_corrections = self._clean_items(
            summary.user_corrections
        )

        summary.summarized_until_message_id = max(
            0,
            summary.summarized_until_message_id,
        )
        summary.summarized_message_count = max(
            0,
            summary.summarized_message_count,
        )
        summary.updated_at = utc_now()

        return summary

    def get(
        self,
        session_id: str,
    ) -> ChatSummary | None:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT summary_json
                FROM chat_summaries
                WHERE session_id = ?
                """,
                (session_id,),
            ).fetchone()

        if row is None:
            return None

        payload = json.loads(row["summary_json"])
        return ChatSummary.model_validate(payload)

    def get_or_create(
        self,
        session_id: str,
    ) -> ChatSummary:
        summary = self.get(session_id)

        if summary is not None:
            return summary

        summary = ChatSummary(session_id=session_id)
        return self.save(summary)

    def save(
        self,
        summary: ChatSummary,
    ) -> ChatSummary:
        normalized = self._normalize(summary)
        payload = normalized.model_dump(mode="json")
        body = json.dumps(
            payload,
            ensure_ascii=False,
        )

        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO chat_summaries (
                    session_id,
                    summary_json,
                    summarized_until_message_id,
                    summarized_message_count,
                    created_at,
                    updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(session_id) DO UPDATE SET
                    summary_json = excluded.summary_json,
                    summarized_until_message_id =
                        excluded.summarized_until_message_id,
                    summarized_message_count =
                        excluded.summarized_message_count,
                    updated_at = excluded.updated_at
                """,
                (
                    normalized.session_id,
                    body,
                    normalized.summarized_until_message_id,
                    normalized.summarized_message_count,
                    normalized.created_at.isoformat(),
                    normalized.updated_at.isoformat(),
                ),
            )
            conn.commit()

        return normalized

    def delete(
        self,
        session_id: str,
    ) -> bool:
        with self._connect() as conn:
            cursor = conn.execute(
                """
                DELETE FROM chat_summaries
                WHERE session_id = ?
                """,
                (session_id,),
            )
            conn.commit()

        return cursor.rowcount > 0

    def clear_all(self) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM chat_summaries")
            conn.commit()
