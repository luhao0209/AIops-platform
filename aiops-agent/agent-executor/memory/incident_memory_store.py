from __future__ import annotations

import json
import sqlite3
import uuid
from contextlib import closing
from datetime import datetime
from pathlib import Path
from typing import Literal

from memory.models import (
    Incident,
    IncidentEvent,
    IncidentRecordResult,
    format_utc_datetime,
    parse_utc_datetime,
    utc_now,
)


DEFAULT_DB_PATH = (
    Path(__file__).resolve().parents[1]
    / "data"
    / "memory"
    / "incident_memory.db"
)


class IncidentMemoryStore:
    """Persist alert lifecycles separately from their notification timeline."""

    def __init__(self, db_path: str | Path | None = None) -> None:
        self.db_path = Path(db_path) if db_path else DEFAULT_DB_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=10000")
        return conn

    def _init_db(self) -> None:
        with closing(self._connect()) as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS incidents (
                    incident_id TEXT PRIMARY KEY,
                    fingerprint TEXT NOT NULL,
                    occurrence_index INTEGER NOT NULL,
                    alert_name TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    status TEXT NOT NULL,
                    namespace TEXT NOT NULL,
                    target TEXT NOT NULL,
                    generator_url TEXT NOT NULL DEFAULT '',
                    source TEXT NOT NULL DEFAULT '',
                    receiver TEXT NOT NULL DEFAULT '',
                    webhook_source TEXT NOT NULL DEFAULT '',
                    started_at TEXT,
                    last_seen_at TEXT,
                    last_received_at TEXT,
                    resolved_at TEXT,
                    resolved_at_source TEXT NOT NULL,
                    notification_count INTEGER NOT NULL,
                    unmatched_start INTEGER NOT NULL,
                    labels_json TEXT NOT NULL,
                    annotations_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(fingerprint, occurrence_index)
                );

                CREATE INDEX IF NOT EXISTS idx_incidents_fingerprint
                ON incidents(fingerprint, occurrence_index DESC);

                CREATE INDEX IF NOT EXISTS idx_incidents_status_updated
                ON incidents(status, updated_at DESC);

                CREATE TABLE IF NOT EXISTS incident_events (
                    event_id TEXT PRIMARY KEY,
                    incident_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    received_at TEXT NOT NULL,
                    alert_status TEXT NOT NULL,
                    starts_at TEXT,
                    ends_at TEXT,
                    group_key TEXT NOT NULL,
                    receiver TEXT NOT NULL,
                    generator_url TEXT NOT NULL DEFAULT '',
                    source TEXT NOT NULL DEFAULT '',
                    webhook_source TEXT NOT NULL DEFAULT '',
                    labels_json TEXT NOT NULL,
                    annotations_json TEXT NOT NULL,
                    FOREIGN KEY(incident_id)
                        REFERENCES incidents(incident_id)
                        ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS idx_incident_events_timeline
                ON incident_events(incident_id, received_at, event_id);

                CREATE TABLE IF NOT EXISTS incident_analysis_runs (
                    analysis_id TEXT PRIMARY KEY,
                    incident_id TEXT NOT NULL UNIQUE,
                    status TEXT NOT NULL,
                    phase TEXT NOT NULL DEFAULT 'received',
                    classification TEXT NOT NULL DEFAULT 'unknown',
                    classification_confidence TEXT NOT NULL DEFAULT 'low',
                    classification_reason TEXT NOT NULL DEFAULT '',
                    classified_at TEXT,
                    current_round INTEGER NOT NULL,
                    started_at TEXT,
                    next_recheck_at TEXT,
                    completed_at TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY(incident_id)
                        REFERENCES incidents(incident_id)
                        ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS idx_analysis_runs_status_updated
                ON incident_analysis_runs(status, updated_at DESC);

                CREATE TABLE IF NOT EXISTS incident_analysis_events (
                    event_id TEXT PRIMARY KEY,
                    analysis_id TEXT NOT NULL,
                    incident_id TEXT NOT NULL,
                    sequence_no INTEGER NOT NULL,
                    round_index INTEGER NOT NULL,
                    event_type TEXT NOT NULL,
                    title TEXT NOT NULL,
                    content_md TEXT NOT NULL,
                    tool_name TEXT NOT NULL,
                    tool_call_id TEXT NOT NULL,
                    evidence_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(analysis_id, sequence_no),
                    FOREIGN KEY(analysis_id)
                        REFERENCES incident_analysis_runs(analysis_id)
                        ON DELETE CASCADE,
                    FOREIGN KEY(incident_id)
                        REFERENCES incidents(incident_id)
                        ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS idx_analysis_events_timeline
                ON incident_analysis_events(analysis_id, sequence_no);
                """
            )
            self._add_column_if_missing(
                conn, "incidents", "generator_url",
                "TEXT NOT NULL DEFAULT ''",
            )
            self._add_column_if_missing(
                conn, "incidents", "source",
                "TEXT NOT NULL DEFAULT ''",
            )
            self._add_column_if_missing(
                conn, "incidents", "receiver",
                "TEXT NOT NULL DEFAULT ''",
            )
            self._add_column_if_missing(
                conn, "incidents", "webhook_source",
                "TEXT NOT NULL DEFAULT ''",
            )
            self._add_column_if_missing(
                conn, "incidents", "last_received_at",
                "TEXT",
            )
            self._add_column_if_missing(
                conn, "incident_events", "generator_url",
                "TEXT NOT NULL DEFAULT ''",
            )
            self._add_column_if_missing(
                conn, "incident_events", "source",
                "TEXT NOT NULL DEFAULT ''",
            )
            self._add_column_if_missing(
                conn, "incident_events", "webhook_source",
                "TEXT NOT NULL DEFAULT ''",
            )
            self._add_column_if_missing(
                conn, "incident_analysis_runs", "phase",
                "TEXT NOT NULL DEFAULT 'received'",
            )
            self._add_column_if_missing(
                conn, "incident_analysis_runs", "classification",
                "TEXT NOT NULL DEFAULT 'unknown'",
            )
            self._add_column_if_missing(
                conn, "incident_analysis_runs", "classification_confidence",
                "TEXT NOT NULL DEFAULT 'low'",
            )
            self._add_column_if_missing(
                conn, "incident_analysis_runs", "classification_reason",
                "TEXT NOT NULL DEFAULT ''",
            )
            self._add_column_if_missing(
                conn, "incident_analysis_runs", "classified_at",
                "TEXT",
            )
            conn.commit()

    @staticmethod
    def _add_column_if_missing(
        conn: sqlite3.Connection,
        table: str,
        column: str,
        definition: str,
    ) -> None:
        allowed_tables = {
            "incidents",
            "incident_events",
            "incident_analysis_runs",
        }
        if table not in allowed_tables:
            raise ValueError(f"unsupported table: {table}")

        columns = {
            row["name"]
            for row in conn.execute(
                f"PRAGMA table_info({table})"
            )
        }
        if column not in columns:
            conn.execute(
                f"ALTER TABLE {table} "
                f"ADD COLUMN {column} {definition}"
            )

    @staticmethod
    def _json(value: dict[str, str]) -> str:
        return json.dumps(value, ensure_ascii=False, sort_keys=True)

    @staticmethod
    def _row_to_incident(row: sqlite3.Row) -> Incident:
        keys = set(row.keys())
        return Incident(
            incident_id=row["incident_id"],
            fingerprint=row["fingerprint"],
            occurrence_index=row["occurrence_index"],
            alert_name=row["alert_name"],
            severity=row["severity"],
            status=row["status"],
            namespace=row["namespace"],
            target=row["target"],
            generator_url=row["generator_url"] if "generator_url" in keys else "",
            source=row["source"] if "source" in keys else "",
            receiver=row["receiver"] if "receiver" in keys else "",
            webhook_source=(
                row["webhook_source"] if "webhook_source" in keys else ""
            ),
            started_at=row["started_at"],
            last_seen_at=row["last_seen_at"],
            last_received_at=(
                row["last_received_at"] if "last_received_at" in keys else None
            ),
            resolved_at=row["resolved_at"],
            resolved_at_source=row["resolved_at_source"],
            notification_count=row["notification_count"],
            unmatched_start=bool(row["unmatched_start"]),
            labels=json.loads(row["labels_json"]),
            annotations=json.loads(row["annotations_json"]),
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )

    @staticmethod
    def _row_to_event(row: sqlite3.Row) -> IncidentEvent:
        keys = set(row.keys())
        return IncidentEvent(
            event_id=row["event_id"],
            incident_id=row["incident_id"],
            event_type=row["event_type"],
            received_at=row["received_at"],
            alert_status=row["alert_status"],
            starts_at=row["starts_at"],
            ends_at=row["ends_at"],
            group_key=row["group_key"],
            receiver=row["receiver"],
            generator_url=row["generator_url"] if "generator_url" in keys else "",
            source=row["source"] if "source" in keys else "",
            webhook_source=(
                row["webhook_source"] if "webhook_source" in keys else ""
            ),
            labels=json.loads(row["labels_json"]),
            annotations=json.loads(row["annotations_json"]),
        )

    @staticmethod
    def _normalize_time(value: datetime | str | None) -> datetime | None:
        return parse_utc_datetime(value)

    def _find_matching_incident(
        self,
        conn: sqlite3.Connection,
        fingerprint: str,
        started_at: datetime | None,
        alert_status: Literal["firing", "resolved"],
    ) -> sqlite3.Row | None:
        if started_at is not None:
            return conn.execute(
                """
                SELECT * FROM incidents
                WHERE fingerprint = ? AND started_at = ?
                ORDER BY occurrence_index DESC
                LIMIT 1
                """,
                (fingerprint, format_utc_datetime(started_at)),
            ).fetchone()

        active = conn.execute(
            """
            SELECT * FROM incidents
            WHERE fingerprint = ? AND status = 'firing'
            ORDER BY occurrence_index DESC
            LIMIT 1
            """,
            (fingerprint,),
        ).fetchone()
        if active is not None or alert_status == "firing":
            return active



        return conn.execute(
            """
            SELECT * FROM incidents
            WHERE fingerprint = ?
              AND status = 'resolved'
              AND unmatched_start = 1
            ORDER BY occurrence_index DESC
            LIMIT 1
            """,
            (fingerprint,),
        ).fetchone()

    @staticmethod
    def _next_occurrence_index(
        conn: sqlite3.Connection,
        fingerprint: str,
    ) -> int:
        row = conn.execute(
            """
            SELECT COALESCE(MAX(occurrence_index), 0) AS current_index
            FROM incidents
            WHERE fingerprint = ?
            """,
            (fingerprint,),
        ).fetchone()
        return int(row["current_index"]) + 1

    def _insert_event(
        self,
        conn: sqlite3.Connection,
        *,
        incident_id: str,
        event_type: str,
        received_at: datetime,
        alert_status: str,
        starts_at: datetime | None,
        ends_at: datetime | None,
        group_key: str,
        receiver: str,
        generator_url: str = "",
        source: str = "",
        webhook_source: str = "",
        labels: dict[str, str],
        annotations: dict[str, str],
    ) -> None:
        conn.execute(
            """
            INSERT INTO incident_events (
                event_id, incident_id, event_type, received_at,
                alert_status, starts_at, ends_at, group_key, receiver,
                generator_url, source, webhook_source,
                labels_json, annotations_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                f"evt-{uuid.uuid4().hex}",
                incident_id,
                event_type,
                format_utc_datetime(received_at),
                alert_status,
                format_utc_datetime(starts_at),
                format_utc_datetime(ends_at),
                group_key,
                receiver,
                generator_url,
                source,
                webhook_source,
                self._json(labels),
                self._json(annotations),
            ),
        )

    def record_notification(
        self,
        *,
        fingerprint: str,
        alert_name: str,
        alert_status: Literal["firing", "resolved"],
        starts_at: datetime | str | None,
        ends_at: datetime | str | None = None,
        received_at: datetime | str | None = None,
        severity: str = "",
        namespace: str = "",
        target: str = "",
        group_key: str = "",
        receiver: str = "",
        generator_url: str = "",
        source: str = "",
        webhook_source: str = "",
        labels: dict[str, str] | None = None,
        annotations: dict[str, str] | None = None,
    ) -> IncidentRecordResult:
        """Record one Alertmanager notification without treating retries as recurrences."""
        fingerprint = fingerprint.strip()
        alert_name = alert_name.strip()
        if not fingerprint or not alert_name:
            raise ValueError("fingerprint and alert_name are required")

        starts_at_value = self._normalize_time(starts_at)
        ends_at_value = self._normalize_time(ends_at)
        received_at_value = self._normalize_time(received_at) or utc_now()
        labels_value = dict(labels or {})
        annotations_value = dict(annotations or {})
        generator_url_value = (generator_url or "").strip()
        source_value = (source or "").strip()
        receiver_value = (receiver or "").strip()
        webhook_source_value = (webhook_source or "").strip()
        event_type = f"{alert_status}_notification"

        with closing(self._connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = self._find_matching_incident(
                conn,
                fingerprint,
                starts_at_value,
                alert_status,
            )
            created = row is None

            if created:
                incident_id = f"inc-{uuid.uuid4().hex}"
                occurrence_index = self._next_occurrence_index(
                    conn,
                    fingerprint,
                )
                resolved_at = None
                resolved_at_source = ""
                if alert_status == "resolved":
                    resolved_at = ends_at_value or received_at_value
                    resolved_at_source = (
                        "alertmanager"
                        if ends_at_value is not None
                        else "received_at_fallback"
                    )

                conn.execute(
                    """
                    INSERT INTO incidents (
                        incident_id, fingerprint, occurrence_index,
                        alert_name, severity, status, namespace, target,
                        generator_url, source, receiver, webhook_source,
                        started_at, last_seen_at, last_received_at, resolved_at,
                        resolved_at_source, notification_count,
                        unmatched_start, labels_json, annotations_json,
                        created_at, updated_at
                    ) VALUES (
                        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                    )
                    """,
                    (
                        incident_id,
                        fingerprint,
                        occurrence_index,
                        alert_name,
                        severity,
                        alert_status,
                        namespace,
                        target,
                        generator_url_value,
                        source_value,
                        receiver_value,
                        webhook_source_value,
                        format_utc_datetime(starts_at_value),
                        format_utc_datetime(received_at_value)
                        if alert_status == "firing"
                        else None,
                        format_utc_datetime(received_at_value),
                        format_utc_datetime(resolved_at),
                        resolved_at_source,
                        1,
                        int(alert_status == "resolved"),
                        self._json(labels_value),
                        self._json(annotations_value),
                        format_utc_datetime(received_at_value),
                        format_utc_datetime(received_at_value),
                    ),
                )
                self._insert_event(
                    conn,
                    incident_id=incident_id,
                    event_type="incident_created",
                    received_at=received_at_value,
                    alert_status=alert_status,
                    starts_at=starts_at_value,
                    ends_at=ends_at_value,
                    group_key=group_key,
                    receiver=receiver_value,
                    generator_url=generator_url_value,
                    source=source_value,
                    webhook_source=webhook_source_value,
                    labels=labels_value,
                    annotations=annotations_value,
                )
            else:
                incident_id = row["incident_id"]
                current_status = row["status"]
                next_status = (
                    "resolved"
                    if alert_status == "resolved" or current_status == "resolved"
                    else "firing"
                )
                last_seen_at = row["last_seen_at"]
                if alert_status == "firing":
                    last_seen_at = format_utc_datetime(received_at_value)

                resolved_at = row["resolved_at"]
                resolved_at_source = row["resolved_at_source"]
                if alert_status == "resolved" and not resolved_at:
                    resolved_at = format_utc_datetime(
                        ends_at_value or received_at_value
                    )
                    resolved_at_source = (
                        "alertmanager"
                        if ends_at_value is not None
                        else "received_at_fallback"
                    )

                conn.execute(
                    """
                    UPDATE incidents SET
                        alert_name = ?, severity = ?, status = ?,
                        namespace = ?, target = ?, last_seen_at = ?,
                        generator_url = CASE
                            WHEN ? != '' THEN ?
                            ELSE generator_url
                        END,
                        source = CASE
                            WHEN ? != '' THEN ?
                            ELSE source
                        END,
                        receiver = CASE
                            WHEN ? != '' THEN ?
                            ELSE receiver
                        END,
                        webhook_source = CASE
                            WHEN ? != '' THEN ?
                            ELSE webhook_source
                        END,
                        last_received_at = ?,
                        resolved_at = ?, resolved_at_source = ?,
                        notification_count = notification_count + 1,
                        labels_json = ?, annotations_json = ?,
                        updated_at = ?
                    WHERE incident_id = ?
                    """,
                    (
                        alert_name,
                        severity,
                        next_status,
                        namespace,
                        target,
                        last_seen_at,
                        generator_url_value,
                        generator_url_value,
                        source_value,
                        source_value,
                        receiver_value,
                        receiver_value,
                        webhook_source_value,
                        webhook_source_value,
                        format_utc_datetime(received_at_value),
                        resolved_at,
                        resolved_at_source,
                        self._json(labels_value),
                        self._json(annotations_value),
                        format_utc_datetime(received_at_value),
                        incident_id,
                    ),
                )

            self._insert_event(
                conn,
                incident_id=incident_id,
                event_type=event_type,
                received_at=received_at_value,
                alert_status=alert_status,
                starts_at=starts_at_value,
                ends_at=ends_at_value,
                group_key=group_key,
                receiver=receiver_value,
                generator_url=generator_url_value,
                source=source_value,
                webhook_source=webhook_source_value,
                labels=labels_value,
                annotations=annotations_value,
            )
            saved = conn.execute(
                "SELECT * FROM incidents WHERE incident_id = ?",
                (incident_id,),
            ).fetchone()
            conn.commit()

        return IncidentRecordResult(
            incident=self._row_to_incident(saved),
            created=created,
            event_type=event_type,
        )

    def get(self, incident_id: str) -> Incident | None:
        with closing(self._connect()) as conn:
            row = conn.execute(
                "SELECT * FROM incidents WHERE incident_id = ?",
                (incident_id,),
            ).fetchone()
        return self._row_to_incident(row) if row else None

    def list_incidents(
        self,
        *,
        status: Literal["firing", "resolved"] | None = None,
        fingerprint: str | None = None,
        alert_name: str | None = None,
        limit: int = 100,
    ) -> list[Incident]:
        clauses: list[str] = []
        parameters: list[object] = []
        if status:
            clauses.append("status = ?")
            parameters.append(status)
        if fingerprint:
            clauses.append("fingerprint = ?")
            parameters.append(fingerprint)
        if alert_name:
            clauses.append("alert_name = ?")
            parameters.append(alert_name)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        parameters.append(max(1, min(limit, 500)))

        with closing(self._connect()) as conn:
            rows = conn.execute(
                f"""
                SELECT * FROM incidents
                {where}
                ORDER BY updated_at DESC, occurrence_index DESC
                LIMIT ?
                """,
                parameters,
            ).fetchall()
        return [self._row_to_incident(row) for row in rows]

    def list_events(
        self,
        incident_id: str,
        *,
        limit: int = 500,
    ) -> list[IncidentEvent]:
        with closing(self._connect()) as conn:
            rows = conn.execute(
                """
                SELECT * FROM incident_events
                WHERE incident_id = ?
                ORDER BY received_at, rowid
                LIMIT ?
                """,
                (incident_id, max(1, min(limit, 1000))),
            ).fetchall()
        return [self._row_to_event(row) for row in rows]

    def count_occurrences(self, fingerprint: str) -> int:
        with closing(self._connect()) as conn:
            row = conn.execute(
                """
                SELECT COUNT(*) AS total
                FROM incidents
                WHERE fingerprint = ?
                """,
                (fingerprint,),
            ).fetchone()
        return int(row["total"])

    def delete(self, incident_id: str) -> bool:
        with closing(self._connect()) as conn:
            cursor = conn.execute(
                "DELETE FROM incidents WHERE incident_id = ?",
                (incident_id,),
            )
            conn.commit()
        return cursor.rowcount > 0
