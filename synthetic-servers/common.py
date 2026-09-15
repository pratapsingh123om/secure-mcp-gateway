from __future__ import annotations

import json
import os
from typing import Any

from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import AccessToken
from mcp.server.auth.settings import AuthSettings
from mcp.server.mcpserver import MCPServer
from mcp.server.transport_security import TransportSecuritySettings


DEFAULT_TOKENS: dict[str, dict[str, str]] = {
    "dev-acme-crm": {"tenant_id": "acme", "service": "crm"},
    "dev-acme-hr": {"tenant_id": "acme", "service": "hr"},
    "dev-acme-billing": {"tenant_id": "acme", "service": "billing"},
    "dev-globex-crm": {"tenant_id": "globex", "service": "crm"},
    "dev-globex-hr": {"tenant_id": "globex", "service": "hr"},
    "dev-globex-billing": {"tenant_id": "globex", "service": "billing"},
}


class TenantCredentialVerifier:
    def __init__(self, service: str, resource_url: str):
        self.service = service
        self.resource_url = resource_url
        self.tokens: dict[str, dict[str, Any]] = json.loads(
            os.getenv("DOWNSTREAM_TOKEN_MAP_JSON", json.dumps(DEFAULT_TOKENS))
        )

    async def verify_token(self, token: str) -> AccessToken | None:
        claims = self.tokens.get(token)
        if not claims or claims.get("service") != self.service:
            return None
        return AccessToken(
            token=token,
            client_id="zero-trust-mcp-gateway",
            scopes=["downstream:call"],
            resource=self.resource_url,
            subject="gateway",
            claims={"tenant_id": claims["tenant_id"], "service": self.service, "iss": "internal-gateway"},
        )


def build_server(service: str, resource_url: str) -> MCPServer:
    verifier = TenantCredentialVerifier(service, resource_url)
    return MCPServer(
        f"synthetic-{service}",
        token_verifier=verifier,
        auth=AuthSettings(
            issuer_url="http://internal-gateway",
            resource_server_url=resource_url,
            required_scopes=["downstream:call"],
            validate_token_resource=True,
        ),
    )


def require_tenant(requested_tenant: str) -> str:
    token = get_access_token()
    token_tenant = token.claims.get("tenant_id") if token and token.claims else None
    if token_tenant != requested_tenant:
        raise PermissionError("Downstream credential is not valid for the requested tenant")
    return requested_tenant


def transport_security(service: str, port: int) -> TransportSecuritySettings:
    defaults = f"127.0.0.1:*,localhost:*,{service}:{port}"
    allowed_hosts = [item.strip() for item in os.getenv("ALLOWED_HOSTS", defaults).split(",") if item.strip()]
    allowed_origins = [
        item.strip()
        for item in os.getenv("ALLOWED_ORIGINS", "http://127.0.0.1:*,http://localhost:*").split(",")
        if item.strip()
    ]
    return TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=allowed_hosts,
        allowed_origins=allowed_origins,
    )
