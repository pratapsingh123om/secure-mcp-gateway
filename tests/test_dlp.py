from backend.dlp import DLPEngine


def test_inbound_dlp_redacts_common_pii_and_secrets():
    raw = (
        "email person@example.com, phone +1 415-555-0100, SSN 111-22-3333, "
        "key sk-live-ABCDEFGHIJKLMNOP, token eyJabcdefghij.abcdefghij.abcdefghij"
    )
    result = DLPEngine().inspect(raw, direction="inbound")
    assert result.redaction_count >= 5
    for secret in ("person@example.com", "+1 415-555-0100", "111-22-3333", "ABCDEFGHIJKLMNOP", "eyJabcdefghij"):
        assert secret not in result.value


def test_outbound_dlp_blocks_sensitive_values_and_fields_without_forwarding():
    payload = {"query": "send sk-live-ABCDEFGHIJKLMNOP", "password": "not-for-an-upstream"}
    result = DLPEngine().inspect(payload, direction="outbound")
    assert result.blocked
    assert {finding.kind for finding in result.findings} >= {"api_key", "sensitive_field"}
