from __future__ import annotations

import json
from typing import Any

from mcp.server.auth.settings import AuthSettings
from mcp.server.context import CallNext, HandlerResult, ServerRequestContext
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from backend.auth import OIDCTokenVerifier, principal_from_access_token
from backend.config import Settings
from backend.service import GatewayService


class LeastPrivilegeDiscoveryMiddleware:
    def __init__(self, service: GatewayService):
        self.service = service

    async def __call__(self, ctx: ServerRequestContext[Any, Any], call_next: CallNext) -> HandlerResult:
        result = await call_next(ctx)
        if ctx.method != "tools/list" or not isinstance(result, dict):
            return result
        principal = principal_from_access_token()
        visible = await self.service.discover(principal)
        return {
            **result,
            "tools": [tool for tool in result.get("tools", []) if tool.get("name") in visible],
        }


def _render(result) -> str:
    payload = {
        "ok": result.ok,
        "decision": result.decision.value,
        "reason": result.reason,
        "approval_id": result.approval_id,
        "redactions": result.redactions,
        "data": result.text if result.ok else None,
    }
    return json.dumps(payload, sort_keys=True)


def build_mcp_server(settings: Settings, verifier: OIDCTokenVerifier, service: GatewayService) -> MCPServer:
    server = MCPServer(
        "zero-trust-mcp-gateway",
        description="Identity-bound, policy-enforced, audited MCP security gateway",
        token_verifier=verifier,
        auth=AuthSettings(
            issuer_url=settings.oidc_issuer,
            resource_server_url=settings.oidc_audience,
            required_scopes=[settings.required_scope],
            validate_token_resource=True,
        ),
        middleware=[LeastPrivilegeDiscoveryMiddleware(service)],
    )

    async def run(name: str, arguments: dict[str, Any], approval_id: str | None = None) -> str:
        principal = principal_from_access_token()
        result = await service.execute(name, arguments, principal, approval_id=approval_id)
        rendered = _render(result)
        if not result.ok:
            raise ToolError(rendered)
        return rendered

    @server.tool(description="Read one client record from the authenticated tenant's CRM.")
    async def crm_get_client(client_id: str) -> str:
        return await run("crm_get_client", {"client_id": client_id})

    @server.tool(description="Read salary data with an expiring, single-use human approval.")
    async def hr_get_salary(employee_id: str, approval_id: str | None = None) -> str:
        return await run("hr_get_salary", {"employee_id": employee_id}, approval_id)

    @server.tool(description="Read one invoice from the authenticated tenant.")
    async def billing_get_invoice(invoice_id: str) -> str:
        return await run("billing_get_invoice", {"invoice_id": invoice_id})

    @server.tool(description="Delete one invoice with an expiring, single-use human approval.")
    async def billing_delete_invoice(invoice_id: str, approval_id: str | None = None) -> str:
        return await run("billing_delete_invoice", {"invoice_id": invoice_id}, approval_id)

    return server
