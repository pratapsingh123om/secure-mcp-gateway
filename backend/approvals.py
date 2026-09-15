from __future__ import annotations

import sqlite3
import threading
import time
import uuid
from pathlib import Path
from typing import Any

from backend.models import Principal


class ApprovalStore:
    def __init__(self, path: Path, ttl_seconds: int = 300):
        self.path = path
        self.ttl_seconds = ttl_seconds
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS approvals (
                    id TEXT PRIMARY KEY,
                    principal_id TEXT NOT NULL,
                    tenant_id TEXT NOT NULL,
                    tool_name TEXT NOT NULL,
                    resource_id TEXT NOT NULL,
                    arguments_hash TEXT NOT NULL,
                    status TEXT NOT NULL,
                    requested_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL,
                    approved_by TEXT,
                    approved_at INTEGER,
                    consumed_at INTEGER
                )
                """
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS approvals_lookup ON approvals "
                "(principal_id, tenant_id, tool_name, resource_id, arguments_hash, status, expires_at)"
            )

    def request(
        self,
        principal: Principal,
        *,
        tool_name: str,
        resource_id: str,
        arguments_hash: str,
    ) -> str:
        now = int(time.time())
        with self._lock, self._connect() as connection:
            row = connection.execute(
                """
                SELECT id FROM approvals
                WHERE principal_id = ? AND tenant_id = ? AND tool_name = ? AND resource_id = ?
                  AND arguments_hash = ? AND status IN ('PENDING', 'APPROVED') AND expires_at >= ?
                ORDER BY requested_at DESC LIMIT 1
                """,
                (principal.subject, principal.tenant_id, tool_name, resource_id, arguments_hash, now),
            ).fetchone()
            if row:
                return str(row["id"])
            approval_id = f"apr_{uuid.uuid4().hex}"
            connection.execute(
                """
                INSERT INTO approvals
                (id, principal_id, tenant_id, tool_name, resource_id, arguments_hash, status, requested_at, expires_at)
                VALUES (?, ?, ?, ?, ?, ?, 'PENDING', ?, ?)
                """,
                (
                    approval_id,
                    principal.subject,
                    principal.tenant_id,
                    tool_name,
                    resource_id,
                    arguments_hash,
                    now,
                    now + self.ttl_seconds,
                ),
            )
            return approval_id

    def approve(self, approval_id: str, approver: Principal) -> bool:
        now = int(time.time())
        with self._lock, self._connect() as connection:
            cursor = connection.execute(
                """
                UPDATE approvals SET status = 'APPROVED', approved_by = ?, approved_at = ?
                WHERE id = ? AND tenant_id = ? AND status = 'PENDING' AND expires_at >= ?
                """,
                (approver.subject, now, approval_id, approver.tenant_id, now),
            )
            return cursor.rowcount == 1

    def consume(
        self,
        approval_id: str,
        principal: Principal,
        *,
        tool_name: str,
        resource_id: str,
        arguments_hash: str,
    ) -> bool:
        now = int(time.time())
        with self._lock, self._connect() as connection:
            cursor = connection.execute(
                """
                UPDATE approvals SET status = 'CONSUMED', consumed_at = ?
                WHERE id = ? AND principal_id = ? AND tenant_id = ? AND tool_name = ?
                  AND resource_id = ? AND arguments_hash = ? AND status = 'APPROVED' AND expires_at >= ?
                """,
                (
                    now,
                    approval_id,
                    principal.subject,
                    principal.tenant_id,
                    tool_name,
                    resource_id,
                    arguments_hash,
                    now,
                ),
            )
            return cursor.rowcount == 1

    def list(self, *, tenant_id: str, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock, self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM approvals WHERE tenant_id = ? ORDER BY requested_at DESC LIMIT ?",
                (tenant_id, max(1, min(limit, 500))),
            ).fetchall()
        return [dict(row) for row in rows]
