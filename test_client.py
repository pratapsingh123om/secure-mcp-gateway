"""Executable end-to-end security demo with assertions.

Run the full stack first, then execute ``python test_client.py``. Any violated
security invariant makes the process exit non-zero.
"""

from __future__ import annotations

import argparse
import asyncio
import json

import httpx
import httpx2
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamable_http_client


async def development_token(base_url: str, **payload) -> str:
    async with httpx.AsyncClient(base_url=base_url, timeout=10) as client:
        response = await client.post("/dev/token", json=payload)
        response.raise_for_status()
        return str(response.json()["access_token"])


def result_payload(result) -> dict:
    text = "\n".join(str(item.text) for item in result.content if hasattr(item, "text"))
    start = text.find("{")
    if start < 0:
        raise AssertionError(f"Tool returned no JSON security envelope: {text}")
    return json.loads(text[start:])


async def call(base_url: str, token: str, operation) -> object:
    async with httpx2.AsyncClient(headers={"Authorization": f"Bearer {token}"}, timeout=10) as client:
        async with streamable_http_client(f"{base_url}/mcp", http_client=client) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                return await operation(session)


async def run(base_url: str) -> None:
    common_scopes = ["mcp:tools", "control:read"]
    crm_token = await development_token(
        base_url,
        subject="alice",
        tenant_id="acme",
        roles=["crm-viewer"],
        scopes=common_scopes,
        agent_id="crm-agent",
    )

    tools = await call(base_url, crm_token, lambda session: session.list_tools())
    tool_names = {tool.name for tool in tools.tools}
    assert tool_names == {"crm_get_client"}, f"least-privilege discovery failed: {tool_names}"
    print("PASS: CRM viewer discovers only crm_get_client")

    crm_result = await call(
        base_url,
        crm_token,
        lambda session: session.call_tool("crm_get_client", {"client_id": "acme-100"}),
    )
    crm_payload = result_payload(crm_result)
    assert crm_payload["ok"] is True
    serialized = json.dumps(crm_payload)
    for secret in ("alice@acme.example", "+1 415-555-0100", "sk-live-ACMECRM123456789"):
        assert secret not in serialized, f"response DLP leaked {secret}"
    assert crm_payload["redactions"] >= 3
    print("PASS: authorized tenant read succeeds and response PII/secrets are redacted")

    cross_tenant = await call(
        base_url,
        crm_token,
        lambda session: session.call_tool("crm_get_client", {"client_id": "globex-100"}),
    )
    assert cross_tenant.is_error is True
    print("PASS: cross-tenant resource guessing is denied")

    finance_token = await development_token(
        base_url,
        subject="frank",
        tenant_id="acme",
        roles=["finance-viewer"],
        scopes=common_scopes,
        agent_id="finance-agent",
    )
    finance_tools = await call(base_url, finance_token, lambda session: session.list_tools())
    finance_names = {tool.name for tool in finance_tools.tools}
    assert finance_names == {"billing_get_invoice"}, f"finance discovery leaked tools: {finance_names}"
    unauthorized_delete = await call(
        base_url,
        finance_token,
        lambda session: session.call_tool("billing_delete_invoice", {"invoice_id": "acme-inv-001"}),
    )
    assert unauthorized_delete.is_error is True
    assert result_payload(unauthorized_delete)["decision"] == "DENY"
    print("PASS: finance viewer cannot discover or directly invoke invoice deletion")

    hr_token = await development_token(
        base_url,
        subject="carol",
        tenant_id="acme",
        roles=["hr-viewer"],
        scopes=common_scopes,
        agent_id="hr-agent",
    )
    pending = await call(
        base_url,
        hr_token,
        lambda session: session.call_tool("hr_get_salary", {"employee_id": "acme-e01"}),
    )
    assert pending.is_error is True
    pending_payload = result_payload(pending)
    approval_id = pending_payload.get("approval_id")
    assert pending_payload["decision"] == "REQUIRE_APPROVAL" and approval_id
    print("PASS: high-risk HR read creates an approval request")

    approver_token = await development_token(
        base_url,
        subject="security-approver",
        tenant_id="acme",
        roles=["approver"],
        scopes=["mcp:tools", "control:read", "approval:write"],
        agent_id="approval-console",
    )
    async with httpx.AsyncClient(base_url=base_url, headers={"Authorization": f"Bearer {approver_token}"}) as client:
        response = await client.post(f"/v1/approvals/{approval_id}/approve")
        response.raise_for_status()

    approved = await call(
        base_url,
        hr_token,
        lambda session: session.call_tool(
            "hr_get_salary", {"employee_id": "acme-e01", "approval_id": approval_id}
        ),
    )
    approved_payload = result_payload(approved)
    assert approved_payload["ok"] is True
    assert "111-22-3333" not in json.dumps(approved_payload)
    print("PASS: approved HR read succeeds and SSN is redacted")

    replay = await call(
        base_url,
        hr_token,
        lambda session: session.call_tool(
            "hr_get_salary", {"employee_id": "acme-e01", "approval_id": approval_id}
        ),
    )
    assert replay.is_error is True
    assert result_payload(replay)["decision"] == "DENY"
    print("PASS: approval replay is denied")

    admin_token = await development_token(
        base_url,
        subject="security-admin",
        tenant_id="acme",
        roles=["admin", "auditor"],
        scopes=["mcp:tools", "control:read", "audit:read"],
        agent_id="security-console",
    )
    async with httpx.AsyncClient(base_url=base_url, headers={"Authorization": f"Bearer {admin_token}"}) as client:
        response = await client.get("/v1/audit/events?limit=100")
        response.raise_for_status()
        audit_text = response.text
        for secret in ("alice@acme.example", "+1 415-555-0100", "sk-live-ACMECRM123456789", "111-22-3333"):
            assert secret not in audit_text, f"audit log leaked {secret}"
    print("PASS: audit export contains no synthetic secrets or PII")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    args = parser.parse_args()
    asyncio.run(run(args.base_url.rstrip("/")))
