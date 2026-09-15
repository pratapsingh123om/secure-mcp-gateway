from __future__ import annotations

import asyncio
import time
from typing import Any

import jwt
from jwt import PyJWKClient
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import AccessToken

from backend.config import Settings
from backend.models import Principal


def _as_strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return value.split()
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return value
    return []


class OIDCTokenVerifier:
    """Validate audience-bound JWT access tokens from an OIDC issuer."""

    def __init__(self, settings: Settings):
        self.settings = settings
        self._jwks = PyJWKClient(settings.oidc_jwks_url, cache_keys=True) if settings.oidc_jwks_url else None

    async def verify_token(self, token: str) -> AccessToken | None:
        try:
            if self._jwks:
                signing_key = await asyncio.to_thread(self._jwks.get_signing_key_from_jwt, token)
                key = signing_key.key
                algorithms = list(self.settings.oidc_algorithms)
            elif self.settings.dev_auth_enabled:
                key = self.settings.dev_signing_secret
                algorithms = ["HS256"]
            else:
                return None

            claims = jwt.decode(
                token,
                key=key,
                algorithms=algorithms,
                audience=self.settings.oidc_audience,
                issuer=self.settings.oidc_issuer,
                leeway=30,
                options={"require": ["exp", "iat", "iss", "aud", "sub", "tenant_id", "roles"]},
            )
            scopes = _as_strings(claims.get("scope", claims.get("scp", [])))
            roles = _as_strings(claims.get("roles", []))
            tenant_id = claims.get("tenant_id")
            if not isinstance(tenant_id, str) or not tenant_id or not roles:
                return None
            client_id = str(claims.get("azp") or claims.get("client_id") or claims["sub"])
            audience = claims.get("aud")
            resource = self.settings.oidc_audience if (
                audience == self.settings.oidc_audience
                or isinstance(audience, list) and self.settings.oidc_audience in audience
            ) else None
            return AccessToken(
                token=token,
                client_id=client_id,
                scopes=scopes,
                expires_at=int(claims["exp"]),
                resource=resource,
                subject=str(claims["sub"]),
                claims=claims,
            )
        except (jwt.PyJWTError, ValueError, KeyError, TypeError):
            return None


def principal_from_access_token(token: AccessToken | None = None) -> Principal:
    access_token = token or get_access_token()
    if access_token is None or not access_token.claims:
        raise PermissionError("A verified access token is required")
    claims = access_token.claims
    tenant_id = claims.get("tenant_id")
    roles = _as_strings(claims.get("roles", []))
    if not isinstance(tenant_id, str) or not tenant_id or not roles:
        raise PermissionError("The access token is missing tenant or role claims")
    return Principal(
        subject=str(access_token.subject or claims.get("sub") or ""),
        client_id=access_token.client_id,
        tenant_id=tenant_id,
        roles=frozenset(roles),
        scopes=frozenset(access_token.scopes),
        agent_id=str(claims.get("agent_id") or access_token.client_id),
        issuer=str(claims.get("iss") or ""),
    )


def issue_development_token(
    settings: Settings,
    *,
    subject: str,
    tenant_id: str,
    roles: list[str],
    scopes: list[str],
    agent_id: str,
    lifetime_seconds: int = 3600,
) -> str:
    if not settings.dev_auth_enabled:
        raise PermissionError("Development token issuance is disabled")
    now = int(time.time())
    claims = {
        "iss": settings.oidc_issuer,
        "aud": settings.oidc_audience,
        "sub": subject,
        "azp": agent_id,
        "agent_id": agent_id,
        "tenant_id": tenant_id,
        "roles": roles,
        "scope": " ".join(scopes),
        "iat": now,
        "nbf": now,
        "exp": now + lifetime_seconds,
    }
    return jwt.encode(claims, settings.dev_signing_secret, algorithm="HS256")
