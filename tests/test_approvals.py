from backend.approvals import ApprovalStore
from backend.audit import hash_value
from tests.helpers import principal


def test_approval_is_tenant_bound_exact_and_single_use(tmp_path):
    store = ApprovalStore(tmp_path / "approvals.db")
    requester = principal(subject="alice", tenant="acme", roles={"hr-viewer"})
    approver = principal(subject="approver", tenant="acme", roles={"approver"})
    foreign_approver = principal(subject="mallory", tenant="globex", roles={"approver"})
    arguments_hash = hash_value({"employee_id": "acme-e01"})
    approval_id = store.request(
        requester,
        tool_name="hr_get_salary",
        resource_id="acme-e01",
        arguments_hash=arguments_hash,
    )
    assert store.approve(approval_id, foreign_approver) is False
    assert store.approve(approval_id, approver) is True
    assert store.consume(
        approval_id,
        requester,
        tool_name="hr_get_salary",
        resource_id="different",
        arguments_hash=arguments_hash,
    ) is False
    assert store.consume(
        approval_id,
        requester,
        tool_name="hr_get_salary",
        resource_id="acme-e01",
        arguments_hash=arguments_hash,
    ) is True
    assert store.consume(
        approval_id,
        requester,
        tool_name="hr_get_salary",
        resource_id="acme-e01",
        arguments_hash=arguments_hash,
    ) is False


def test_repeated_high_risk_request_is_idempotent(tmp_path):
    store = ApprovalStore(tmp_path / "approvals.db")
    requester = principal(subject="alice", roles={"hr-viewer"})
    arguments_hash = hash_value({"employee_id": "acme-e01"})
    first = store.request(
        requester, tool_name="hr_get_salary", resource_id="acme-e01", arguments_hash=arguments_hash
    )
    second = store.request(
        requester, tool_name="hr_get_salary", resource_id="acme-e01", arguments_hash=arguments_hash
    )
    assert first == second
