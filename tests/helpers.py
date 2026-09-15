from __future__ import annotations

from pathlib import Path
from typing import Any

from backend.approvals import ApprovalStore
from backend.audit import AuditLog
from backend.catalog import TOOL_CATALOG
from backend.config import Settings
from backend.dlp import DLPEngine
from backend.manifest import ManifestRegistry
from backend.metrics import Metrics
from backend.models import Decision, PolicyResult, Principal, ToolDefinition
from backend.rate_limit import SlidingWindowRateLimiter
from backend.service import GatewayService
from backend.upstream import UpstreamError


CATALOGS = {
    "crm": [{"name": "crm_get_client", "description": "Tenant CRM read", "inputSchema": {"type": "object"}}],
    "hr": [{"name": "hr_get_salary", "description": "Tenant salary read", "inputSchema": {"type": "object"}}],
    "billing": [
        {"name": "billing_get_invoice", "description": "Tenant invoice read", "inputSchema": {"type": "object"}},
        {"name": "billing_delete_invoice", "description": "Tenant invoice delete", "inputSchema": {"type": "object"}},
    ],
}


def principal(
    *,
    subject: str = "alice",
    tenant: str = "acme",
    roles: set[str] | None = None,
    scopes: set[str] | None = None,
) -> Principal:
    return Principal(
        subject=subject,
        client_id="test-agent",
        tenant_id=tenant,
        roles=frozenset(roles or {"crm-viewer"}),
        scopes=frozenset(scopes or {"mcp:tools", "control:read"}),
        agent_id="test-agent",
        issuer="https://issuer.example",
    )


class FakePolicy:
    entitlement = {
        "crm_get_client": {"crm-viewer", "admin"},
        "hr_get_salary": {"hr-viewer", "admin"},
        "billing_get_invoice": {"finance-viewer", "finance-admin", "admin"},
        "billing_delete_invoice": {"finance-admin", "admin"},
    }

    async def evaluate(
        self,
        identity: Principal,
        tool: ToolDefinition,
        *,
        action: str,
        resource_id: str | None,
        resource_tenant: str,
        human_approval: bool = False,
    ) -> PolicyResult:
        if resource_tenant != identity.tenant_id or identity.roles.isdisjoint(self.entitlement.get(tool.name, set())):
            return PolicyResult(Decision.DENY, "not entitled", "test-policy")
        if action == "list_tools":
            return PolicyResult(Decision.ALLOW, "visible", "test-policy")
        if tool.risk in {"high", "critical"} and not human_approval:
            return PolicyResult(Decision.REQUIRE_APPROVAL, "approval required", "test-policy")
        return PolicyResult(Decision.ALLOW, "authorized", "test-policy")

    async def healthy(self) -> bool:
        return True


class FakeUpstream:
    def __init__(self):
        self.calls: list[dict[str, Any]] = []
        self.catalogs = {name: [dict(tool) for tool in tools] for name, tools in CATALOGS.items()}

    async def list_tools(self, upstream: str, *, tenant_id: str | None = None) -> list[dict[str, Any]]:
        return self.catalogs[upstream]

    async def call_tool(
        self,
        upstream: str,
        tool_name: str,
        arguments: dict[str, Any],
        *,
        tenant_id: str,
    ) -> str:
        self.calls.append({"upstream": upstream, "tool": tool_name, "arguments": arguments, "tenant": tenant_id})
        resource_id = str(next((value for key, value in arguments.items() if key.endswith("_id")), ""))
        if resource_id.startswith("globex-") and tenant_id != "globex":
            raise UpstreamError("resource does not exist in authenticated tenant")
        return f'{{"tenant_id":"{tenant_id}","email":"person@example.com","ssn":"111-22-3333"}}'


def settings(tmp_path: Path) -> Settings:
    return Settings(
        dev_signing_secret="test-signing-secret-that-is-long-enough",
        audit_path=tmp_path / "audit.jsonl",
        approvals_path=tmp_path / "approvals.db",
        manifests_path=tmp_path / "manifests.json",
    )


def service(tmp_path: Path, *, rate_limit: int = 60) -> tuple[GatewayService, FakeUpstream, Settings]:
    config = settings(tmp_path)
    config.rate_limit_per_minute = rate_limit
    upstream = FakeUpstream()
    manifests = ManifestRegistry(config.manifests_path)
    for name, catalog in upstream.catalogs.items():
        manifests.approve(name, catalog)
    gateway = GatewayService(
        config,
        FakePolicy(),
        upstream,  # type: ignore[arg-type]
        ApprovalStore(config.approvals_path, config.approval_ttl_seconds),
        AuditLog(config.audit_path),
        manifests,
        DLPEngine(),
        SlidingWindowRateLimiter(),
        Metrics(),
    )
    return gateway, upstream, config
