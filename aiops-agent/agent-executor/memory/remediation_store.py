from __future__ import annotations

import json
import sqlite3
import uuid
from contextlib import closing
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field

from memory.incident_memory_store import DEFAULT_DB_PATH, IncidentMemoryStore
from memory.models import format_utc_datetime, utc_now


RemediationStatus = Literal[
    "pending_approval",
    "executing",
    "rejected",
    "succeeded",
    "failed",
]


class RemediationAction(BaseModel):
    action_id: str
    incident_id: str
    analysis_id: str
    skill_name: str
    action_type: Literal["rollback_deployment", "scale_deployment"]
    namespace: str
    target_name: str
    container_name: str
    current_image: str
    target_image: str
    current_replicas: int = 0
    target_replicas: int = 0
    reason: str
    risk: str
    expected_outcome: str
    verification: list[str] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)
    status: RemediationStatus
    requested_at: str
    decided_at: str = ""
    decided_by: str = ""
    decision_comment: str = ""
    completed_at: str = ""
    result: dict[str, Any] = Field(default_factory=dict)


class RemediationStore:
    """Persist approval requests separately from analysis events."""

    def __init__(self, db_path: str | Path | None = None) -> None:
        self.db_path = Path(db_path) if db_path else DEFAULT_DB_PATH
        IncidentMemoryStore(self.db_path)
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
                CREATE TABLE IF NOT EXISTS remediation_actions (
                    action_id TEXT PRIMARY KEY,
                    incident_id TEXT NOT NULL,
                    analysis_id TEXT NOT NULL,
                    skill_name TEXT NOT NULL,
                    action_type TEXT NOT NULL,
                    namespace TEXT NOT NULL,
                    target_name TEXT NOT NULL,
                    container_name TEXT NOT NULL,
                    current_image TEXT NOT NULL,
                    target_image TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    risk TEXT NOT NULL,
                    expected_outcome TEXT NOT NULL,
                    verification_json TEXT NOT NULL DEFAULT '[]',
                    evidence_refs_json TEXT NOT NULL DEFAULT '[]',
                    status TEXT NOT NULL,
                    requested_at TEXT NOT NULL,
                    decided_at TEXT NOT NULL DEFAULT '',
                    decided_by TEXT NOT NULL DEFAULT '',
                    decision_comment TEXT NOT NULL DEFAULT '',
                    completed_at TEXT NOT NULL DEFAULT '',
                    result_json TEXT NOT NULL DEFAULT '{}',
                    FOREIGN KEY(incident_id) REFERENCES incidents(incident_id)
                        ON DELETE CASCADE,
                    FOREIGN KEY(analysis_id) REFERENCES incident_analysis_runs(analysis_id)
                        ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS idx_remediation_incident_requested
                ON remediation_actions(incident_id, requested_at DESC);
                """
            )
            columns = {
                str(row["name"])
                for row in conn.execute(
                    "PRAGMA table_info(remediation_actions)"
                ).fetchall()
            }
            if "current_replicas" not in columns:
                conn.execute(
                    "ALTER TABLE remediation_actions "
                    "ADD COLUMN current_replicas INTEGER NOT NULL DEFAULT 0"
                )
            if "target_replicas" not in columns:
                conn.execute(
                    "ALTER TABLE remediation_actions "
                    "ADD COLUMN target_replicas INTEGER NOT NULL DEFAULT 0"
                )
            conn.commit()

    @staticmethod
    def _row_to_action(row: sqlite3.Row) -> RemediationAction:
        return RemediationAction(
            action_id=row["action_id"],
            incident_id=row["incident_id"],
            analysis_id=row["analysis_id"],
            skill_name=row["skill_name"],
            action_type=row["action_type"],
            namespace=row["namespace"],
            target_name=row["target_name"],
            container_name=row["container_name"],
            current_image=row["current_image"],
            target_image=row["target_image"],
            current_replicas=int(row["current_replicas"] or 0),
            target_replicas=int(row["target_replicas"] or 0),
            reason=row["reason"],
            risk=row["risk"],
            expected_outcome=row["expected_outcome"],
            verification=json.loads(row["verification_json"] or "[]"),
            evidence_refs=json.loads(row["evidence_refs_json"] or "[]"),
            status=row["status"],
            requested_at=row["requested_at"],
            decided_at=row["decided_at"],
            decided_by=row["decided_by"],
            decision_comment=row["decision_comment"],
            completed_at=row["completed_at"],
            result=json.loads(row["result_json"] or "{}"),
        )

    def get(self, action_id: str) -> RemediationAction | None:
        with closing(self._connect()) as conn:
            row = conn.execute(
                "SELECT * FROM remediation_actions WHERE action_id = ?",
                ((action_id or "").strip(),),
            ).fetchone()
        return self._row_to_action(row) if row else None

    def list_for_incident(self, incident_id: str) -> list[RemediationAction]:
        with closing(self._connect()) as conn:
            rows = conn.execute(
                "SELECT * FROM remediation_actions WHERE incident_id = ? "
                "ORDER BY requested_at DESC",
                ((incident_id or "").strip(),),
            ).fetchall()
        return [self._row_to_action(row) for row in rows]

    def create_request(
        self,
        *,
        incident_id: str,
        analysis_id: str,
        skill_name: str,
        namespace: str,
        target_name: str,
        container_name: str,
        current_image: str,
        target_image: str,
        reason: str,
        risk: str,
        expected_outcome: str,
        verification: list[str],
        evidence_refs: list[str],
    ) -> tuple[RemediationAction, bool]:
        """Create at most one identical rollback attempt per Incident."""
        with closing(self._connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            existing = conn.execute(
                "SELECT * FROM remediation_actions WHERE incident_id = ? "
                "AND action_type = 'rollback_deployment' "
                "AND namespace = ? AND target_name = ? AND target_image = ? "
                "ORDER BY requested_at DESC LIMIT 1",
                (incident_id, namespace, target_name, target_image),
            ).fetchone()
            if existing is not None:
                conn.commit()
                return self._row_to_action(existing), False

            action_id = f"rem-{uuid.uuid4().hex[:16]}"
            requested_at = format_utc_datetime(utc_now()) or ""
            conn.execute(
                """
                INSERT INTO remediation_actions (
                    action_id, incident_id, analysis_id, skill_name,
                    action_type, namespace, target_name, container_name,
                    current_image, target_image, reason, risk,
                    expected_outcome, verification_json, evidence_refs_json,
                    status, requested_at
                ) VALUES (?, ?, ?, ?, 'rollback_deployment', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                          'pending_approval', ?)
                """,
                (
                    action_id,
                    incident_id,
                    analysis_id,
                    skill_name,
                    namespace,
                    target_name,
                    container_name,
                    current_image,
                    target_image,
                    reason,
                    risk,
                    expected_outcome,
                    json.dumps(verification, ensure_ascii=False),
                    json.dumps(evidence_refs, ensure_ascii=False),
                    requested_at,
                ),
            )
            conn.commit()
            row = conn.execute(
                "SELECT * FROM remediation_actions WHERE action_id = ?",
                (action_id,),
            ).fetchone()
        return self._row_to_action(row), True

    def create_scale_request(
        self,
        *,
        incident_id: str,
        analysis_id: str,
        skill_name: str,
        namespace: str,
        target_name: str,
        current_replicas: int,
        target_replicas: int,
        reason: str,
        risk: str,
        expected_outcome: str,
        verification: list[str],
        evidence_refs: list[str],
    ) -> tuple[RemediationAction, bool]:
        """Create at most one identical scale attempt per Incident."""
        with closing(self._connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            existing = conn.execute(
                "SELECT * FROM remediation_actions WHERE incident_id = ? "
                "AND action_type = 'scale_deployment' "
                "AND namespace = ? AND target_name = ? "
                "AND current_replicas = ? AND target_replicas = ? "
                "ORDER BY requested_at DESC LIMIT 1",
                (
                    incident_id,
                    namespace,
                    target_name,
                    current_replicas,
                    target_replicas,
                ),
            ).fetchone()
            if existing is not None:
                conn.commit()
                return self._row_to_action(existing), False

            action_id = f"rem-{uuid.uuid4().hex[:16]}"
            requested_at = format_utc_datetime(utc_now()) or ""
            conn.execute(
                """
                INSERT INTO remediation_actions (
                    action_id, incident_id, analysis_id, skill_name,
                    action_type, namespace, target_name, container_name,
                    current_image, target_image,
                    current_replicas, target_replicas,
                    reason, risk, expected_outcome, verification_json,
                    evidence_refs_json, status, requested_at
                ) VALUES (?, ?, ?, ?, 'scale_deployment', ?, ?, '', '', '',
                          ?, ?, ?, ?, ?, ?, ?, 'pending_approval', ?)
                """,
                (
                    action_id,
                    incident_id,
                    analysis_id,
                    skill_name,
                    namespace,
                    target_name,
                    current_replicas,
                    target_replicas,
                    reason,
                    risk,
                    expected_outcome,
                    json.dumps(verification, ensure_ascii=False),
                    json.dumps(evidence_refs, ensure_ascii=False),
                    requested_at,
                ),
            )
            conn.commit()
            row = conn.execute(
                "SELECT * FROM remediation_actions WHERE action_id = ?",
                (action_id,),
            ).fetchone()
        return self._row_to_action(row), True

    def claim_approval(
        self,
        action_id: str,
        *,
        decided_by: str,
        comment: str = "",
    ) -> RemediationAction:
        decided_at = format_utc_datetime(utc_now()) or ""
        with closing(self._connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            cursor = conn.execute(
                "UPDATE remediation_actions SET status = 'executing', "
                "decided_at = ?, decided_by = ?, decision_comment = ? "
                "WHERE action_id = ? AND status = 'pending_approval'",
                (decided_at, decided_by, comment, action_id),
            )
            if cursor.rowcount != 1:
                conn.rollback()
                current = self.get(action_id)
                if current is None:
                    raise ValueError("remediation action not found")
                raise ValueError(f"remediation action is already {current.status}")
            conn.commit()
        action = self.get(action_id)
        assert action is not None
        return action

    def reject(
        self,
        action_id: str,
        *,
        decided_by: str,
        comment: str = "",
    ) -> RemediationAction:
        decided_at = format_utc_datetime(utc_now()) or ""
        with closing(self._connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            cursor = conn.execute(
                "UPDATE remediation_actions SET status = 'rejected', "
                "decided_at = ?, decided_by = ?, decision_comment = ?, "
                "completed_at = ? WHERE action_id = ? "
                "AND status = 'pending_approval'",
                (decided_at, decided_by, comment, decided_at, action_id),
            )
            if cursor.rowcount != 1:
                conn.rollback()
                current = self.get(action_id)
                if current is None:
                    raise ValueError("remediation action not found")
                raise ValueError(f"remediation action is already {current.status}")
            conn.commit()
        action = self.get(action_id)
        assert action is not None
        return action

    def finish(
        self,
        action_id: str,
        *,
        succeeded: bool,
        result: dict[str, Any],
    ) -> RemediationAction:
        completed_at = format_utc_datetime(utc_now()) or ""
        with closing(self._connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            cursor = conn.execute(
                "UPDATE remediation_actions SET status = ?, completed_at = ?, "
                "result_json = ? WHERE action_id = ? AND status = 'executing'",
                (
                    "succeeded" if succeeded else "failed",
                    completed_at,
                    json.dumps(result, ensure_ascii=False, sort_keys=True),
                    action_id,
                ),
            )
            if cursor.rowcount != 1:
                conn.rollback()
                raise ValueError("remediation action is not executing")
            conn.commit()
        action = self.get(action_id)
        assert action is not None
        return action
