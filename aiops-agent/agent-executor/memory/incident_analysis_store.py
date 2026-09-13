from __future__ import annotations

import json
import sqlite3
import uuid
from contextlib import closing
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from alerting.analysis_models import (
    AnalysisEventType,
    AnalysisPhase,
    AnalysisRunStatus,
    IncidentAnalysisEvent,
    IncidentAnalysisRun,
)
from alerting.classifier import (
    AlertClassification,
    ClassificationConfidence,
)
from memory.incident_memory_store import DEFAULT_DB_PATH, IncidentMemoryStore
from memory.models import format_utc_datetime, parse_utc_datetime, utc_now


class IncidentAnalysisStore:
    """Persist Agent analysis runs separately from alert lifecycles."""

    def __init__(self, db_path: str | Path | None = None) -> None:
        self.db_path = Path(db_path) if db_path else DEFAULT_DB_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        IncidentMemoryStore(self.db_path)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=10000")
        return conn

    @staticmethod
    def _json(value: Any) -> str:
        return json.dumps(value if value is not None else {}, ensure_ascii=False)

    @staticmethod
    def _row_to_run(row: sqlite3.Row) -> IncidentAnalysisRun:
        keys = set(row.keys())
        return IncidentAnalysisRun(
            analysis_id=row["analysis_id"],
            incident_id=row["incident_id"],
            status=row["status"],
            phase=row["phase"] if "phase" in keys else "received",
            classification=(
                row["classification"] if "classification" in keys else "unknown"
            ),
            classification_confidence=(
                row["classification_confidence"]
                if "classification_confidence" in keys
                else "low"
            ),
            classification_reason=(
                row["classification_reason"]
                if "classification_reason" in keys
                else ""
            ),
            classified_at=(
                row["classified_at"] if "classified_at" in keys else None
            ),
            current_round=row["current_round"],
            started_at=row["started_at"],
            next_recheck_at=row["next_recheck_at"],
            completed_at=row["completed_at"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )

    @staticmethod
    def _row_to_event(row: sqlite3.Row) -> IncidentAnalysisEvent:
        evidence = json.loads(row["evidence_json"] or "{}")
        return IncidentAnalysisEvent(
            event_id=row["event_id"],
            analysis_id=row["analysis_id"],
            incident_id=row["incident_id"],
            sequence_no=row["sequence_no"],
            round_index=row["round_index"],
            event_type=row["event_type"],
            title=row["title"],
            content_md=row["content_md"],
            tool_name=row["tool_name"],
            tool_call_id=row["tool_call_id"],
            evidence=evidence,
            created_at=row["created_at"],
        )

    def _require_incident(self, conn: sqlite3.Connection, incident_id: str) -> None:
        row = conn.execute(
            "SELECT 1 FROM incidents WHERE incident_id = ?",
            (incident_id,),
        ).fetchone()
        if row is None:
            raise ValueError(f"incident not found: {incident_id}")

    def get_run(self, analysis_id: str) -> IncidentAnalysisRun | None:
        normalized_id = (analysis_id or "").strip()
        if not normalized_id:
            return None

        with closing(self._connect()) as conn:
            row = conn.execute(
                "SELECT * FROM incident_analysis_runs WHERE analysis_id = ?",
                (normalized_id,),
            ).fetchone()
        return self._row_to_run(row) if row else None

    def get_run_by_incident(self, incident_id: str) -> IncidentAnalysisRun | None:
        normalized_id = (incident_id or "").strip()
        if not normalized_id:
            return None

        with closing(self._connect()) as conn:
            row = conn.execute(
                "SELECT * FROM incident_analysis_runs WHERE incident_id = ?",
                (normalized_id,),
            ).fetchone()
        return self._row_to_run(row) if row else None

    def get_or_create_run(self, incident_id: str) -> IncidentAnalysisRun:
        normalized_id = (incident_id or "").strip()
        if not normalized_id:
            raise ValueError("incident_id is required")

        with closing(self._connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._require_incident(conn, normalized_id)

            existing = conn.execute(
                "SELECT * FROM incident_analysis_runs WHERE incident_id = ?",
                (normalized_id,),
            ).fetchone()
            if existing is not None:
                conn.commit()
                return self._row_to_run(existing)

            now = utc_now()
            now_text = format_utc_datetime(now)
            analysis_id = f"anl-{uuid.uuid4().hex[:16]}"
            conn.execute(
                """
                INSERT INTO incident_analysis_runs (
                    analysis_id, incident_id, status, phase,
                    classification, classification_confidence,
                    classification_reason, classified_at, current_round,
                    started_at, next_recheck_at, completed_at,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    analysis_id,
                    normalized_id,
                    "pending",
                    "received",
                    "unknown",
                    "low",
                    "",
                    None,
                    1,
                    now_text,
                    None,
                    None,
                    now_text,
                    now_text,
                ),
            )
            conn.commit()
            row = conn.execute(
                "SELECT * FROM incident_analysis_runs WHERE analysis_id = ?",
                (analysis_id,),
            ).fetchone()

        return self._row_to_run(row)

    def list_runs(
        self,
        status: AnalysisRunStatus | None = None,
        limit: int = 100,
    ) -> list[IncidentAnalysisRun]:
        clauses: list[str] = []
        parameters: list[object] = []
        if status:
            clauses.append("status = ?")
            parameters.append(status)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        parameters.append(max(1, min(int(limit), 500)))

        with closing(self._connect()) as conn:
            rows = conn.execute(
                f"""
                SELECT * FROM incident_analysis_runs
                {where}
                ORDER BY updated_at DESC
                LIMIT ?
                """,
                parameters,
            ).fetchall()
        return [self._row_to_run(row) for row in rows]

    def update_run(
        self,
        analysis_id: str,
        *,
        status: AnalysisRunStatus | None = None,
        current_round: int | None = None,
        next_recheck_at: datetime | str | None = None,
        completed_at: datetime | str | None = None,
        clear_next_recheck_at: bool = False,
        phase: AnalysisPhase | None = None,
        classification: AlertClassification | None = None,
        classification_confidence: ClassificationConfidence | None = None,
        classification_reason: str | None = None,
        classified_at: datetime | str | None = None,
    ) -> IncidentAnalysisRun:
        normalized_id = (analysis_id or "").strip()
        if not normalized_id:
            raise ValueError("analysis_id is required")

        with closing(self._connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT * FROM incident_analysis_runs WHERE analysis_id = ?",
                (normalized_id,),
            ).fetchone()
            if row is None:
                conn.rollback()
                raise ValueError(f"analysis run not found: {normalized_id}")

            keys = set(row.keys())
            next_status = status if status is not None else row["status"]
            next_round = (
                current_round if current_round is not None else row["current_round"]
            )
            if next_round < 1:
                conn.rollback()
                raise ValueError("current_round must be >= 1")

            if clear_next_recheck_at:
                next_recheck_value = None
            elif next_recheck_at is not None:
                next_recheck_value = format_utc_datetime(
                    parse_utc_datetime(next_recheck_at)
                )
            else:
                next_recheck_value = row["next_recheck_at"]

            if completed_at is not None:
                completed_value = format_utc_datetime(
                    parse_utc_datetime(completed_at)
                )
            elif next_status == "completed" and not row["completed_at"]:
                completed_value = format_utc_datetime(utc_now())
            else:
                completed_value = row["completed_at"]

            next_phase = (
                phase
                if phase is not None
                else (row["phase"] if "phase" in keys else "received")
            )
            next_classification = (
                classification
                if classification is not None
                else (
                    row["classification"]
                    if "classification" in keys
                    else "unknown"
                )
            )
            next_confidence = (
                classification_confidence
                if classification_confidence is not None
                else (
                    row["classification_confidence"]
                    if "classification_confidence" in keys
                    else "low"
                )
            )
            next_reason = (
                classification_reason
                if classification_reason is not None
                else (
                    row["classification_reason"]
                    if "classification_reason" in keys
                    else ""
                )
            )
            if classified_at is not None:
                next_classified_at = format_utc_datetime(
                    parse_utc_datetime(classified_at)
                )
            else:
                next_classified_at = (
                    row["classified_at"] if "classified_at" in keys else None
                )

            now_text = format_utc_datetime(utc_now())
            conn.execute(
                """
                UPDATE incident_analysis_runs
                SET status = ?,
                    current_round = ?,
                    next_recheck_at = ?,
                    completed_at = ?,
                    phase = ?,
                    classification = ?,
                    classification_confidence = ?,
                    classification_reason = ?,
                    classified_at = ?,
                    updated_at = ?
                WHERE analysis_id = ?
                """,
                (
                    next_status,
                    next_round,
                    next_recheck_value,
                    completed_value,
                    next_phase,
                    next_classification,
                    next_confidence,
                    next_reason,
                    next_classified_at,
                    now_text,
                    normalized_id,
                ),
            )
            conn.commit()
            updated = conn.execute(
                "SELECT * FROM incident_analysis_runs WHERE analysis_id = ?",
                (normalized_id,),
            ).fetchone()

        return self._row_to_run(updated)

    def append_event(
        self,
        analysis_id: str,
        event_type: AnalysisEventType,
        title: str,
        content_md: str = "",
        round_index: int = 1,
        tool_name: str = "",
        tool_call_id: str = "",
        evidence: dict[str, Any] | list[Any] | None = None,
    ) -> IncidentAnalysisEvent:
        normalized_id = (analysis_id or "").strip()
        if not normalized_id:
            raise ValueError("analysis_id is required")
        if not (title or "").strip():
            raise ValueError("title is required")
        if round_index < 1:
            raise ValueError("round_index must be >= 1")

        with closing(self._connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            run = conn.execute(
                "SELECT * FROM incident_analysis_runs WHERE analysis_id = ?",
                (normalized_id,),
            ).fetchone()
            if run is None:
                conn.rollback()
                raise ValueError(f"analysis run not found: {normalized_id}")

            sequence_row = conn.execute(
                """
                SELECT COALESCE(MAX(sequence_no), 0) AS max_seq
                FROM incident_analysis_events
                WHERE analysis_id = ?
                """,
                (normalized_id,),
            ).fetchone()
            sequence_no = int(sequence_row["max_seq"]) + 1
            event_id = f"aev-{uuid.uuid4().hex[:16]}"
            created_at = format_utc_datetime(utc_now())

            conn.execute(
                """
                INSERT INTO incident_analysis_events (
                    event_id, analysis_id, incident_id, sequence_no,
                    round_index, event_type, title, content_md,
                    tool_name, tool_call_id, evidence_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_id,
                    normalized_id,
                    run["incident_id"],
                    sequence_no,
                    round_index,
                    event_type,
                    title.strip(),
                    content_md or "",
                    tool_name or "",
                    tool_call_id or "",
                    self._json(evidence if evidence is not None else {}),
                    created_at,
                ),
            )
            conn.execute(
                """
                UPDATE incident_analysis_runs
                SET updated_at = ?
                WHERE analysis_id = ?
                """,
                (created_at, normalized_id),
            )
            conn.commit()
            row = conn.execute(
                "SELECT * FROM incident_analysis_events WHERE event_id = ?",
                (event_id,),
            ).fetchone()

        return self._row_to_event(row)

    def list_events(
        self,
        analysis_id: str,
        *,
        after_sequence: int = 0,
        limit: int = 500,
    ) -> list[IncidentAnalysisEvent]:
        normalized_id = (analysis_id or "").strip()
        if not normalized_id:
            return []

        sequence_floor = max(0, int(after_sequence))
        with closing(self._connect()) as conn:
            rows = conn.execute(
                """
                SELECT * FROM incident_analysis_events
                WHERE analysis_id = ?
                  AND sequence_no > ?
                ORDER BY sequence_no ASC
                LIMIT ?
                """,
                (
                    normalized_id,
                    sequence_floor,
                    max(1, min(int(limit), 1000)),
                ),
            ).fetchall()
        return [self._row_to_event(row) for row in rows]

    def list_due_rechecks(
        self,
        *,
        now: datetime | str | None = None,
        limit: int = 100,
    ) -> list[IncidentAnalysisRun]:
        cutoff = format_utc_datetime(
            parse_utc_datetime(now) or utc_now()
        )

        with closing(self._connect()) as conn:
            rows = conn.execute(
                """
                SELECT *
                FROM incident_analysis_runs
                WHERE status = 'waiting_recheck'
                  AND next_recheck_at IS NOT NULL
                  AND next_recheck_at <= ?
                ORDER BY next_recheck_at ASC
                LIMIT ?
                """,
                (cutoff, max(1, min(int(limit), 500))),
            ).fetchall()

        return [self._row_to_run(row) for row in rows]

    def list_stale_running(
        self,
        *,
        now: datetime | str | None = None,
        stale_after_seconds: int = 180,
        limit: int = 100,
    ) -> list[IncidentAnalysisRun]:
        """Return runs whose worker disappeared without releasing running state."""
        current_time = parse_utc_datetime(now) or utc_now()
        cutoff = format_utc_datetime(
            current_time - timedelta(
                seconds=max(60, int(stale_after_seconds)),
            )
        )

        with closing(self._connect()) as conn:
            rows = conn.execute(
                """
                SELECT *
                FROM incident_analysis_runs
                WHERE status = 'running'
                  AND updated_at <= ?
                ORDER BY updated_at ASC
                LIMIT ?
                """,
                (cutoff, max(1, min(int(limit), 500))),
            ).fetchall()

        return [self._row_to_run(row) for row in rows]

    def claim_recheck(
        self,
        analysis_id: str,
        *,
        now: datetime | str | None = None,
    ) -> IncidentAnalysisRun | None:
        normalized_id = (analysis_id or "").strip()
        if not normalized_id:
            return None

        cutoff = format_utc_datetime(
            parse_utc_datetime(now) or utc_now()
        )

        with closing(self._connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            cursor = conn.execute(
                """
                UPDATE incident_analysis_runs
                SET status = 'running',
                    current_round = current_round + 1,
                    next_recheck_at = NULL,
                    updated_at = ?
                WHERE analysis_id = ?
                  AND status = 'waiting_recheck'
                  AND next_recheck_at IS NOT NULL
                  AND next_recheck_at <= ?
                """,
                (cutoff, normalized_id, cutoff),
            )

            if cursor.rowcount != 1:
                conn.rollback()
                return None

            conn.commit()
            row = conn.execute(
                "SELECT * FROM incident_analysis_runs WHERE analysis_id = ?",
                (normalized_id,),
            ).fetchone()

        return self._row_to_run(row) if row else None
