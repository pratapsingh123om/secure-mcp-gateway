from backend.audit import hash_value
from backend.models import Decision
from tests.helpers import principal, service


async def test_discovery_filters_tools_by_role(tmp_path):
    gateway, _, _ = service(tmp_path)
    assert await gateway.discover(principal(roles={"crm-viewer"})) == {"crm_get_client"}
    assert await gateway.discover(principal(roles={"finance-viewer"})) == {"billing_get_invoice"}


async def test_authorized_call_injects_verified_tenant_and_redacts_output(tmp_path):
    gateway, upstream, _ = service(tmp_path)
    result = await gateway.execute("crm_get_client", {"client_id": "acme-100"}, principal())
    assert result.ok
    assert "person@example.com" not in result.text
    assert "111-22-3333" not in result.text
    assert result.redactions == 2
    assert upstream.calls[0]["tenant"] == "acme"
    assert upstream.calls[0]["arguments"] == {"client_id": "acme-100"}
    assert 'mcp_gateway_dlp_redactions_total{direction="inbound",tool="crm_get_client"} 2.0' in gateway.metrics.render()


async def test_cross_tenant_resource_guess_is_denied(tmp_path):
    gateway, _, _ = service(tmp_path)
    result = await gateway.execute("crm_get_client", {"client_id": "globex-100"}, principal())
    assert not result.ok
    assert result.decision == Decision.DENY


async def test_unknown_tool_is_denied(tmp_path):
    gateway, upstream, _ = service(tmp_path)
    result = await gateway.execute("made_up_tool", {"resource_id": "acme-100"}, principal())
    assert result.decision == Decision.DENY
    assert result.reason == "unknown tool"
    assert upstream.calls == []


async def test_outbound_secret_is_blocked_before_upstream(tmp_path):
    gateway, upstream, _ = service(tmp_path)
    result = await gateway.execute(
        "crm_get_client", {"client_id": "sk-live-ABCDEFGHIJKLMNOP"}, principal()
    )
    assert not result.ok
    assert result.reason.startswith("outbound DLP blocked")
    assert upstream.calls == []
    assert 'mcp_gateway_dlp_blocks_total{direction="outbound",tool="crm_get_client"} 1.0' in gateway.metrics.render()


async def test_high_risk_approval_flow_and_replay_defense(tmp_path):
    gateway, _, _ = service(tmp_path)
    requester = principal(subject="carol", roles={"hr-viewer"})
    arguments = {"employee_id": "acme-e01"}
    pending = await gateway.execute("hr_get_salary", arguments, requester)
    assert pending.decision == Decision.REQUIRE_APPROVAL
    assert pending.approval_id
    approver = principal(subject="approver", roles={"approver"})
    assert gateway.approvals.approve(pending.approval_id, approver)
    approved = await gateway.execute(
        "hr_get_salary", arguments, requester, approval_id=pending.approval_id
    )
    assert approved.ok
    replay = await gateway.execute(
        "hr_get_salary", arguments, requester, approval_id=pending.approval_id
    )
    assert replay.decision == Decision.DENY


async def test_rate_limit_throttles_excess_calls(tmp_path):
    gateway, _, _ = service(tmp_path, rate_limit=1)
    identity = principal()
    assert (await gateway.execute("crm_get_client", {"client_id": "acme-100"}, identity)).ok
    second = await gateway.execute("crm_get_client", {"client_id": "acme-100"}, identity)
    assert not second.ok
    assert "rate limit exceeded" in second.reason


async def test_manifest_drift_blocks_execution(tmp_path):
    gateway, upstream, _ = service(tmp_path)
    upstream.catalogs["crm"][0]["description"] = "changed after approval"
    result = await gateway.execute("crm_get_client", {"client_id": "acme-100"}, principal())
    assert not result.ok
    assert "QUARANTINED_DRIFT" in result.reason
    assert upstream.calls == []


async def test_finance_viewer_cannot_delete_invoice(tmp_path):
    gateway, upstream, _ = service(tmp_path)
    result = await gateway.execute(
        "billing_delete_invoice",
        {"invoice_id": "acme-inv-001"},
        principal(roles={"finance-viewer"}),
    )
    assert result.decision == Decision.DENY
    assert upstream.calls == []


async def test_finance_admin_delete_requires_exact_approval(tmp_path):
    gateway, _, _ = service(tmp_path)
    requester = principal(subject="finley", roles={"finance-admin"})
    arguments = {"invoice_id": "acme-inv-001"}
    pending = await gateway.execute("billing_delete_invoice", arguments, requester)
    assert pending.decision == Decision.REQUIRE_APPROVAL
    approver = principal(subject="approver", roles={"approver"})
    assert pending.approval_id and gateway.approvals.approve(pending.approval_id, approver)
    result = await gateway.execute(
        "billing_delete_invoice", arguments, requester, approval_id=pending.approval_id
    )
    assert result.ok


async def test_audit_contains_argument_hash_not_raw_arguments(tmp_path):
    gateway, _, _ = service(tmp_path)
    await gateway.execute("crm_get_client", {"client_id": "acme-100"}, principal())
    content = gateway.audit.path.read_text(encoding="utf-8")
    assert "acme-100" not in content
    assert hash_value({"client_id": "acme-100"}) in content
    assert gateway.audit.verify_chain()[0]


async def test_invalid_audit_chain_fails_closed_before_upstream(tmp_path):
    gateway, upstream, _ = service(tmp_path)

    class InvalidAudit:
        def verify_chain(self):
            return False, "tampered"

    gateway.audit = InvalidAudit()  # type: ignore[assignment]
    result = await gateway.execute("crm_get_client", {"client_id": "acme-100"}, principal())
    assert not result.ok
    assert "audit sink unavailable" in result.reason
    assert upstream.calls == []


async def test_execution_intent_write_failure_fails_closed_before_upstream(tmp_path):
    gateway, upstream, _ = service(tmp_path)

    class FailingAudit:
        def verify_chain(self):
            return True, "valid"

        def append(self, event):
            raise OSError("sink unavailable")

    gateway.audit = FailingAudit()  # type: ignore[assignment]
    result = await gateway.execute("crm_get_client", {"client_id": "acme-100"}, principal())
    assert not result.ok
    assert "audit sink unavailable before execution" in result.reason
    assert upstream.calls == []


async def test_completion_write_failure_returns_denial_with_prior_intent(tmp_path):
    gateway, upstream, _ = service(tmp_path)

    class CompletionFailureAudit:
        def __init__(self):
            self.events = []

        def verify_chain(self):
            return True, "valid"

        def append(self, event):
            self.events.append(event)
            if len(self.events) > 1:
                raise OSError("sink unavailable")
            return event

    failing = CompletionFailureAudit()
    gateway.audit = failing  # type: ignore[assignment]
    result = await gateway.execute("crm_get_client", {"client_id": "acme-100"}, principal())
    assert not result.ok
    assert "execution intent remains recorded" in result.reason
    assert len(upstream.calls) == 1
    assert failing.events[0]["result"] == "execution_intent"
