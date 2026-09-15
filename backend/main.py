from __future__ import annotations

from contextlib import asynccontextmanager
from dataclasses import asdict
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field
from mcp.server.transport_security import TransportSecuritySettings

from backend.approvals import ApprovalStore
from backend.audit import AuditLog
from backend.auth import OIDCTokenVerifier, issue_development_token, principal_from_access_token
from backend.catalog import TOOL_CATALOG
from backend.config import Settings
from backend.dlp import DLPEngine
from backend.manifest import ManifestRegistry
from backend.mcp_gateway import build_mcp_server
from backend.metrics import Metrics
from backend.models import Principal
from backend.policy import OPAPolicyEngine
from backend.rate_limit import SlidingWindowRateLimiter
from backend.service import GatewayService
from backend.telemetry import configure_telemetry
from backend.upstream import MCPUpstreamClient, UpstreamError


class DevelopmentTokenRequest(BaseModel):
    subject: str = Field(min_length=1, max_length=100)
    tenant_id: str = Field(min_length=1, max_length=64)
    roles: list[str] = Field(min_length=1, max_length=10)
    scopes: list[str] = Field(default_factory=lambda: ["mcp:tools", "control:read"])
    agent_id: str = Field(default="demo-agent", min_length=1, max_length=100)
    lifetime_seconds: int = Field(default=3600, ge=60, le=86400)


class PolicySimulationRequest(BaseModel):
    tool_name: str
    resource_id: str | None = None
    resource_tenant: str | None = None
    human_approval: bool = False
    action: str = "call_tool"


class ManifestApprovalRequest(BaseModel):
    allow_suspicious: bool = False


class Components:
    def __init__(self, settings: Settings):
        self.settings = settings
        configure_telemetry(settings)
        self.verifier = OIDCTokenVerifier(settings)
        self.policy = OPAPolicyEngine(settings.opa_url, settings.opa_health_url)
        self.upstream = MCPUpstreamClient(settings)
        self.approvals = ApprovalStore(settings.approvals_path, settings.approval_ttl_seconds)
        self.audit = AuditLog(settings.audit_path)
        self.manifests = ManifestRegistry(settings.manifests_path, settings.manifest_cache_seconds)
        self.dlp = DLPEngine()
        self.rate_limiter = SlidingWindowRateLimiter()
        self.metrics = Metrics()
        self.service = GatewayService(
            settings,
            self.policy,
            self.upstream,
            self.approvals,
            self.audit,
            self.manifests,
            self.dlp,
            self.rate_limiter,
            self.metrics,
        )
        self.mcp = build_mcp_server(settings, self.verifier, self.service)
        self.mcp_app = self.mcp.streamable_http_app(
            streamable_http_path="/mcp",
            json_response=True,
            stateless_http=True,
            max_request_body_size=1_048_576,
            host=settings.host,
            transport_security=TransportSecuritySettings(
                enable_dns_rebinding_protection=True,
                allowed_hosts=list(settings.allowed_hosts),
                allowed_origins=list(settings.allowed_origins),
            ),
        )


def create_app(settings: Settings | None = None) -> FastAPI:
    selected = settings or Settings.from_env()
    selected.validate()
    components = Components(selected)

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        valid, reason = components.audit.verify_chain()
        if not valid:
            raise RuntimeError(reason)
        async with components.mcp_app.router.lifespan_context(components.mcp_app):
            yield

    app = FastAPI(
        title="Zero-Trust MCP Security Gateway",
        version="1.0.0",
        description="Control plane for the identity-bound and policy-enforced MCP data plane.",
        lifespan=lifespan,
    )
    app.state.components = components
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(selected.allowed_origins),
        allow_credentials=True,
        allow_methods=["GET", "POST"],
        allow_headers=["Authorization", "Content-Type"],
    )

    async def current_principal(authorization: str | None = Header(default=None)) -> Principal:
        if not authorization or not authorization.lower().startswith("bearer "):
            raise HTTPException(status_code=401, detail="Bearer authentication required")
        access_token = await components.verifier.verify_token(authorization[7:])
        if not access_token:
            raise HTTPException(status_code=401, detail="Invalid, expired, or incorrectly-audienced token")
        try:
            return principal_from_access_token(access_token)
        except PermissionError as exc:
            raise HTTPException(status_code=401, detail=str(exc)) from exc

    def require(principal: Principal, *, scope: str, roles: set[str] | None = None) -> None:
        if scope not in principal.scopes:
            raise HTTPException(status_code=403, detail=f"Required scope: {scope}")
        if roles and principal.roles.isdisjoint(roles):
            raise HTTPException(status_code=403, detail=f"Required role: one of {sorted(roles)}")

    @app.get("/health")
    async def health() -> dict[str, Any]:
        return {"status": "ok", "service": "zero-trust-mcp-gateway", "version": "1.0.0"}

    @app.get("/ready")
    async def ready() -> JSONResponse:
        opa = await components.policy.healthy()
        audit_valid, audit_reason = components.audit.verify_chain()
        manifests: dict[str, str] = {}
        upstreams_ready = True
        for upstream_name in selected.upstream_urls:
            try:
                discovered = await components.upstream.list_tools(upstream_name)
                status = components.manifests.evaluate(upstream_name, discovered)
                manifests[upstream_name] = status.status
                upstreams_ready &= status.status in {"TRUSTED", "TRUSTED_WITH_WARNINGS"}
            except UpstreamError:
                manifests[upstream_name] = "UNAVAILABLE"
                upstreams_ready = False
        is_ready = opa and audit_valid and upstreams_ready
        return JSONResponse(
            status_code=200 if is_ready else 503,
            content={
                "status": "ready" if is_ready else "not_ready",
                "checks": {
                    "policy_engine": opa,
                    "audit_chain": {"valid": audit_valid, "detail": audit_reason},
                    "manifests": manifests,
                },
            },
        )

    @app.get("/metrics", response_class=PlainTextResponse)
    async def metrics() -> str:
        return components.metrics.render()

    @app.get("/api/status")
    async def legacy_status() -> JSONResponse:
        return await ready()

    @app.post("/dev/token")
    async def development_token(request: DevelopmentTokenRequest) -> dict[str, Any]:
        if not selected.dev_auth_enabled:
            raise HTTPException(status_code=404, detail="Not found")
        if request.tenant_id not in selected.downstream_credentials:
            raise HTTPException(status_code=400, detail="Unknown development tenant")
        token = issue_development_token(
            selected,
            subject=request.subject,
            tenant_id=request.tenant_id,
            roles=request.roles,
            scopes=request.scopes,
            agent_id=request.agent_id,
            lifetime_seconds=request.lifetime_seconds,
        )
        return {
            "access_token": token,
            "token_type": "Bearer",
            "expires_in": request.lifetime_seconds,
            "warning": "Development-only issuer; configure an external OIDC JWKS URL in production.",
        }

    @app.get("/dev-issuer/.well-known/openid-configuration")
    async def development_oidc_metadata() -> dict[str, Any]:
        if not selected.dev_auth_enabled:
            raise HTTPException(status_code=404, detail="Not found")
        return {
            "issuer": selected.oidc_issuer,
            "token_endpoint": f"{selected.public_url}/dev/token",
            "scopes_supported": ["mcp:tools", "control:read", "approval:write", "manifest:write", "audit:read"],
            "id_token_signing_alg_values_supported": ["HS256"],
        }

    @app.get("/v1/tools")
    async def tools(principal: Principal = Depends(current_principal)) -> list[dict[str, Any]]:
        require(principal, scope="control:read")
        visible = await components.service.discover(principal)
        return [asdict(tool) for name, tool in TOOL_CATALOG.items() if name in visible]

    @app.get("/api/tools")
    async def legacy_tools(principal: Principal = Depends(current_principal)) -> list[dict[str, Any]]:
        return await tools(principal)

    @app.get("/v1/tenants")
    async def tenants(principal: Principal = Depends(current_principal)) -> dict[str, Any]:
        require(principal, scope="control:read")
        return {"tenants": [principal.tenant_id], "isolation": "token-bound"}

    @app.get("/v1/upstreams")
    async def upstreams(principal: Principal = Depends(current_principal)) -> list[dict[str, str]]:
        require(principal, scope="control:read")
        return [{"name": name, "url": url, "credential": "tenant-bound"} for name, url in selected.upstream_urls.items()]

    @app.post("/v1/policies/simulate")
    async def simulate(
        request: PolicySimulationRequest,
        principal: Principal = Depends(current_principal),
    ) -> dict[str, Any]:
        require(principal, scope="control:read")
        tool = TOOL_CATALOG.get(request.tool_name)
        if not tool:
            return {"decision": "DENY", "reason": "unknown tool", "policy_version": "unknown"}
        decision = await components.policy.evaluate(
            principal,
            tool,
            action=request.action,
            resource_id=request.resource_id,
            resource_tenant=request.resource_tenant or principal.tenant_id,
            human_approval=request.human_approval,
        )
        return asdict(decision)

    @app.get("/v1/approvals")
    async def approvals(
        principal: Principal = Depends(current_principal),
        limit: int = Query(default=100, ge=1, le=500),
    ) -> list[dict[str, Any]]:
        require(principal, scope="control:read", roles={"approver", "admin"})
        return components.approvals.list(tenant_id=principal.tenant_id, limit=limit)

    @app.post("/v1/approvals/{approval_id}/approve")
    async def approve(
        approval_id: str,
        principal: Principal = Depends(current_principal),
    ) -> dict[str, Any]:
        require(principal, scope="approval:write", roles={"approver", "admin"})
        if not components.approvals.approve(approval_id, principal):
            raise HTTPException(status_code=409, detail="Approval is absent, expired, wrong-tenant, or not pending")
        return {"id": approval_id, "status": "APPROVED", "approved_by": principal.subject}

    @app.get("/v1/audit/events")
    async def audit_events(
        principal: Principal = Depends(current_principal),
        limit: int = Query(default=100, ge=1, le=1000),
    ) -> list[dict[str, Any]]:
        require(principal, scope="audit:read", roles={"auditor", "admin"})
        return components.audit.read(limit=limit, tenant_id=principal.tenant_id)

    @app.get("/v1/audit/verify")
    async def audit_verify(principal: Principal = Depends(current_principal)) -> dict[str, Any]:
        require(principal, scope="audit:read", roles={"auditor", "admin"})
        valid, detail = components.audit.verify_chain()
        return {"valid": valid, "detail": detail}

    @app.get("/v1/tool-manifests")
    async def tool_manifests(principal: Principal = Depends(current_principal)) -> list[dict[str, Any]]:
        require(principal, scope="control:read")
        statuses = []
        for upstream_name in selected.upstream_urls:
            try:
                discovered = await components.upstream.list_tools(upstream_name, tenant_id=principal.tenant_id)
                statuses.append(asdict(components.manifests.evaluate(upstream_name, discovered)))
            except UpstreamError as exc:
                statuses.append({"upstream": upstream_name, "status": "UNAVAILABLE", "reason": str(exc)})
        return statuses

    @app.post("/v1/tool-manifests/{upstream_name}/approve")
    async def approve_manifest(
        upstream_name: str,
        request: ManifestApprovalRequest,
        principal: Principal = Depends(current_principal),
    ) -> dict[str, Any]:
        require(principal, scope="manifest:write", roles={"admin"})
        if upstream_name not in selected.upstream_urls:
            raise HTTPException(status_code=404, detail="Unknown upstream")
        try:
            discovered = await components.upstream.list_tools(upstream_name, tenant_id=principal.tenant_id)
        except UpstreamError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        return asdict(components.manifests.approve(
            upstream_name, discovered, allow_suspicious=request.allow_suspicious
        ))

    app.mount("/mcp", components.mcp_app)
    return app


api_app = create_app()
app = FastAPI()
app.mount("/api", api_app)

