"""
Audit Evidence Logger for Bayora Systems.
Every allowed and denied request records an immutable audit event with:
- timestamp (ISO-8601 UTC)
- test_id
- run_id
- actor / role
- action
- resource
- allow/deny decision (ALLOW | DENY)
- state_transition (e.g., Draft->Ready, Ready->Running, or attempted invalid transition)

NON-NEGOTIABLE: Never copy raw payloads, defense configs, or secrets into audit logs.
Audit events reference artifacts by ID and SHA-256 hash metadata only.
"""
from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .database import DatabaseManager


SECRET_REDACTION_PATTERNS = [
    re.compile(r"(api[_-]?key|secret|token|password|payload_text|defense_config_secret)\s*[:=]\s*\S+", re.IGNORECASE),
]


def sanitize_resource_ref(resource: str) -> str:
    """Ensures resource references only contain safe identifiers/paths and never raw secrets."""
    cleaned = resource.strip()
    for pattern in SECRET_REDACTION_PATTERNS:
        cleaned = pattern.sub("[REDACTED_METADATA_ONLY]", cleaned)
    if len(cleaned) > 180:
        cleaned = cleaned[:180] + "...[TRUNCATED_REF]"
    return cleaned


class AuditLogger:
    def __init__(self, db: DatabaseManager):
        self.db = db

    def record(
        self,
        *,
        test_id: str,
        actor: str,
        role: str,
        action: str,
        resource: str,
        decision: str,
        run_id: Optional[str] = None,
        state_transition: Optional[str] = None,
        reason_code: str = "OK",
    ) -> Dict[str, Any]:
        if decision not in ("ALLOW", "DENY"):
            raise ValueError("Audit decision must be ALLOW or DENY")

        event_id = f"aud-{uuid.uuid4().hex[:12]}"
        timestamp = datetime.now(timezone.utc).isoformat()
        safe_resource = sanitize_resource_ref(resource)

        with self.db.connection() as conn:
            conn.execute(
                """
                INSERT INTO audit_events (
                    id, timestamp, test_id, run_id, actor, role,
                    action, resource, decision, state_transition, reason_code
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_id,
                    timestamp,
                    test_id,
                    run_id,
                    actor,
                    role,
                    action,
                    safe_resource,
                    decision,
                    state_transition,
                    reason_code,
                ),
            )

        return {
            "id": event_id,
            "timestamp": timestamp,
            "test_id": test_id,
            "run_id": run_id,
            "actor": actor,
            "role": role,
            "action": action,
            "resource": safe_resource,
            "decision": decision,
            "state_transition": state_transition,
            "reason_code": reason_code,
        }

    def list_events(self, test_id: Optional[str] = None, limit: int = 200) -> List[Dict[str, Any]]:
        with self.db.connection() as conn:
            cursor = conn.cursor()
            if test_id:
                cursor.execute(
                    """
                    SELECT id, timestamp, test_id, run_id, actor, role,
                           action, resource, decision, state_transition, reason_code
                    FROM audit_events
                    WHERE test_id = ?
                    ORDER BY timestamp DESC, rowid DESC
                    LIMIT ?
                    """,
                    (test_id, limit),
                )
            else:
                cursor.execute(
                    """
                    SELECT id, timestamp, test_id, run_id, actor, role,
                           action, resource, decision, state_transition, reason_code
                    FROM audit_events
                    ORDER BY timestamp DESC, rowid DESC
                    LIMIT ?
                    """,
                    (limit,),
                )
            rows = cursor.fetchall()
            return [dict(r) for r in rows]
