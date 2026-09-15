from __future__ import annotations

import hashlib
import json
import threading
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


GENESIS_HASH = "0" * 64


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def hash_value(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


class AuditLog:
    """Append-only, hash-chained JSONL audit storage without raw tool arguments."""

    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def _read_unlocked(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        events: list[dict[str, Any]] = []
        with self.path.open("r", encoding="utf-8") as stream:
            for line in stream:
                if line.strip():
                    events.append(json.loads(line))
        return events

    def append(self, event: dict[str, Any]) -> dict[str, Any]:
        forbidden = {"arguments", "raw_arguments", "output", "access_token", "authorization"}
        if forbidden.intersection(event):
            raise ValueError("Audit events may not contain raw arguments, outputs, or credentials")
        with self._lock:
            existing = self._read_unlocked()
            previous_hash = existing[-1]["event_hash"] if existing else GENESIS_HASH
            record = {
                "event_id": f"evt_{uuid.uuid4().hex}",
                "timestamp": datetime.now(UTC).isoformat(),
                **event,
                "previous_event_hash": previous_hash,
            }
            record["event_hash"] = hash_value(record)
            with self.path.open("a", encoding="utf-8", newline="\n") as stream:
                stream.write(canonical_json(record) + "\n")
            return record

    def read(self, *, limit: int = 100, tenant_id: str | None = None) -> list[dict[str, Any]]:
        with self._lock:
            events = self._read_unlocked()
        if tenant_id is not None:
            events = [event for event in events if event.get("tenant_id") == tenant_id]
        return events[-max(0, min(limit, 1000)):]

    def verify_chain(self) -> tuple[bool, str]:
        try:
            with self._lock:
                events = self._read_unlocked()
            expected_previous = GENESIS_HASH
            for event in events:
                if event.get("previous_event_hash") != expected_previous:
                    return False, f"broken predecessor at {event.get('event_id', 'unknown')}"
                claimed = event.get("event_hash")
                unsigned = {key: value for key, value in event.items() if key != "event_hash"}
                if claimed != hash_value(unsigned):
                    return False, f"modified event {event.get('event_id', 'unknown')}"
                expected_previous = str(claimed)
            return True, f"verified {len(events)} event(s)"
        except (OSError, json.JSONDecodeError, KeyError) as exc:
            return False, f"audit log unreadable: {exc}"
