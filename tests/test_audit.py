import json

import pytest

from backend.audit import AuditLog, hash_value


def event(index: int) -> dict:
    return {
        "trace_id": f"trace-{index}",
        "tenant_id": "acme",
        "decision": "ALLOW",
        "arguments_hash": hash_value({"index": index}),
    }


def test_hash_chain_detects_modification(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.append(event(1))
    log.append(event(2))
    assert log.verify_chain()[0] is True
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    rows[0]["decision"] = "DENY"
    path.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")
    assert log.verify_chain()[0] is False


def test_audit_refuses_raw_sensitive_payloads(tmp_path):
    with pytest.raises(ValueError, match="may not contain raw"):
        AuditLog(tmp_path / "audit.jsonl").append({"arguments": {"password": "secret"}})
