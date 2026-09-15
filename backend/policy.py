from __future__ import annotations

from typing import Any, Protocol

import httpx

from backend.models import Decision, PolicyResult, Principal, ToolDefinition


class PolicyEngine(Protocol):
    async def evaluate(
        self,
        principal: Principal,
        tool: ToolDefinition,
        *,
        action: str,
        resource_id: str | None,
        resource_tenant: str,
        human_approval: bool = False,
    ) -> PolicyResult: ...

    async def healthy(self) -> bool: ...


class OPAPolicyEngine:
    def __init__(self, url: str, health_url: str, timeout: float = 2.0):
        self.url = url
        self.health_url = health_url
        self.timeout = timeout

    def input_document(
        self,
        principal: Principal,
        tool: ToolDefinition,
        *,
        action: str,
        resource_id: str | None,
        resource_tenant: str,
        human_approval: bool,
    ) -> dict[str, Any]:
        return {
            "principal": {
                "id": principal.subject,
                "tenant": principal.tenant_id,
                "roles": sorted(principal.roles),
            },
            "agent": {"id": principal.agent_id},
            "action": action,
            "tool": {
                "server": tool.upstream,
                "name": tool.name,
                "risk": tool.risk,
                "operation": tool.operation,
            },
            "resource": {"id": resource_id, "tenant": resource_tenant},
            "context": {"human_approval": human_approval},
        }

    async def evaluate(
        self,
        principal: Principal,
        tool: ToolDefinition,
        *,
        action: str,
        resource_id: str | None,
        resource_tenant: str,
        human_approval: bool = False,
    ) -> PolicyResult:
        payload = {"input": self.input_document(
            principal,
            tool,
            action=action,
            resource_id=resource_id,
            resource_tenant=resource_tenant,
            human_approval=human_approval,
        )}
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(self.url, json=payload)
            response.raise_for_status()
            result = response.json().get("result") or {}
            decision = Decision(str(result.get("decision", Decision.DENY)))
            return PolicyResult(
                decision=decision,
                reason=str(result.get("reason", "OPA returned no reason")),
                policy_version=str(result.get("policy_version", "unknown")),
            )
        except (httpx.HTTPError, ValueError, TypeError):
            return PolicyResult(Decision.DENY, "policy engine unavailable; failed closed")

    async def healthy(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(self.health_url)
            return response.status_code == 200
        except httpx.HTTPError:
            return False
