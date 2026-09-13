from __future__ import annotations

import os
from threading import Lock

from memory.chat_session_store import ChatSessionStore
from memory.chat_summary_store import ChatSummaryStore
from memory.models import ChatMessage
from memory.summary_service import (
    generate_chat_summary,
    is_summary_model_configured,
)


SUMMARY_TRIGGER_MESSAGES = int(
    os.getenv(
        "SUMMARY_TRIGGER_MESSAGES",
        "16",
    )
)

SUMMARY_KEEP_RECENT_MESSAGES = int(
    os.getenv(
        "SUMMARY_KEEP_RECENT_MESSAGES",
        "8",
    )
)

SUMMARY_MAX_BATCH_MESSAGES = int(
    os.getenv(
        "SUMMARY_MAX_BATCH_MESSAGES",
        "20",
    )
)

SUMMARY_TRIGGER_CHARS = int(
    os.getenv(
        "SUMMARY_TRIGGER_CHARS",
        "12000",
    )
)


_SESSION_LOCKS: dict[str, Lock] = {}
_SESSION_LOCKS_GUARD = Lock()


def _get_session_lock(
    session_id: str,
) -> Lock:
    with _SESSION_LOCKS_GUARD:
        lock = _SESSION_LOCKS.get(session_id)

        if lock is None:
            lock = Lock()
            _SESSION_LOCKS[session_id] = lock

        return lock


def _select_complete_turns(
    messages: list[ChatMessage],
) -> list[ChatMessage]:
    if not messages:
        return []

    last_assistant_index = -1

    for index in range(
        len(messages) - 1,
        -1,
        -1,
    ):
        if messages[index].role == "assistant":
            last_assistant_index = index
            break

    if last_assistant_index < 0:
        return []

    return messages[
        : last_assistant_index + 1
    ]


def maybe_update_chat_summary(
    session_id: str,
    session_store: ChatSessionStore,
    summary_store: ChatSummaryStore,
) -> dict:
    lock = _get_session_lock(session_id)

    if not lock.acquire(blocking=False):
        return {
            "updated": False,
            "reason": "summary_already_running",
            "usage": {},
        }

    try:
        previous_summary = summary_store.get(
            session_id
        )

        summarized_until = (
            previous_summary.summarized_until_message_id
            if previous_summary
            else 0
        )

        pending_messages = (
            session_store.list_messages_after(
                session_id,
                after_message_id=summarized_until,
                limit=500,
            )
        )

        pending_count = len(pending_messages)
        pending_chars = sum(
            len(message.content)
            for message in pending_messages
        )

        if (
            pending_count
            <= SUMMARY_KEEP_RECENT_MESSAGES
        ):
            return {
                "updated": False,
                "reason": "not_enough_messages",
                "pending_message_count":
                    pending_count,
                "usage": {},
            }

        reached_message_threshold = (
            pending_count
            >= SUMMARY_TRIGGER_MESSAGES
        )
        reached_character_threshold = (
            pending_chars
            >= SUMMARY_TRIGGER_CHARS
        )

        if not (
            reached_message_threshold
            or reached_character_threshold
        ):
            return {
                "updated": False,
                "reason": "below_threshold",
                "pending_message_count":
                    pending_count,
                "pending_chars": pending_chars,
                "usage": {},
            }

        candidates = pending_messages[
            :-SUMMARY_KEEP_RECENT_MESSAGES
        ]

        candidates = candidates[
            :SUMMARY_MAX_BATCH_MESSAGES
        ]

        candidates = _select_complete_turns(
            candidates
        )

        if not candidates:
            return {
                "updated": False,
                "reason": "no_complete_turn",
                "pending_message_count":
                    pending_count,
                "usage": {},
            }

        if not is_summary_model_configured():
            return {
                "updated": False,
                "reason":
                    "summary_model_not_configured",
                "candidate_message_count":
                    len(candidates),
                "usage": {},
            }

        try:
            new_summary, usage = (
                generate_chat_summary(
                    session_id=session_id,
                    previous_summary=previous_summary,
                    new_messages=candidates,
                )
            )

            saved_summary = summary_store.save(
                new_summary
            )
        except Exception as exc:
            return {
                "updated": False,
                "reason": "summary_failed",
                "error": str(exc),
                "candidate_message_count":
                    len(candidates),
                "usage": {},
            }

        return {
            "updated": True,
            "reason": "summary_updated",
            "summarized_batch_count":
                len(candidates),
            "summarized_until_message_id":
                saved_summary
                .summarized_until_message_id,
            "summarized_message_count":
                saved_summary
                .summarized_message_count,
            "pending_message_count":
                pending_count,
            "usage": usage,
        }
    finally:
        lock.release()
