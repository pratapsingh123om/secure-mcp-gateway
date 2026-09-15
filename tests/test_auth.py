from __future__ import annotations

import time

import jwt
import pytest

from backend.auth import OIDCTokenVerifier, issue_development_token, principal_from_access_token
from tests.helpers import settings


@pytest.mark.asyncio
async def test_valid_token_resolves_verified_tenant_identity(tmp_path):
    config = settings(tmp_path)
    encoded = issue_development_token(
        config,
        subject="alice",
        tenant_id="acme",
        roles=["crm-viewer"],
        scopes=["mcp:tools"],
        agent_id="agent-1",
    )
    token = await OIDCTokenVerifier(config).verify_token(encoded)
    identity = principal_from_access_token(token)
    assert identity.subject == "alice"
    assert identity.tenant_id == "acme"
    assert identity.roles == {"crm-viewer"}
    assert identity.agent_id == "agent-1"


@pytest.mark.asyncio
@pytest.mark.parametrize("change", ["aud", "iss", "exp"])
async def test_wrong_audience_issuer_and_expired_tokens_are_rejected(tmp_path, change):
    config = settings(tmp_path)
    now = int(time.time())
    claims = {
        "iss": config.oidc_issuer,
        "aud": config.oidc_audience,
        "sub": "alice",
        "tenant_id": "acme",
        "roles": ["crm-viewer"],
        "scope": "mcp:tools",
        "iat": now - 120,
        "exp": now + 3600,
    }
    claims[change] = {"aud": "https://wrong.example", "iss": "https://wrong.example", "exp": now - 120}[change]
    encoded = jwt.encode(claims, config.dev_signing_secret, algorithm="HS256")
    assert await OIDCTokenVerifier(config).verify_token(encoded) is None


def test_production_rejects_development_auth_and_plain_http(tmp_path):
    config = settings(tmp_path)
    config.environment = "production"
    with pytest.raises(RuntimeError, match="DEV_AUTH_ENABLED"):
        config.validate()


def test_production_rejects_placeholder_downstream_credentials(tmp_path):
    config = settings(tmp_path)
    config.environment = "production"
    config.dev_auth_enabled = False
    config.public_url = "https://gateway.example"
    config.oidc_issuer = "https://identity.example"
    config.oidc_jwks_url = "https://identity.example/.well-known/jwks.json"
    with pytest.raises(RuntimeError, match="downstream credentials"):
        config.validate()


def test_production_accepts_external_oidc_and_non_placeholder_credentials(tmp_path):
    config = settings(tmp_path)
    config.environment = "production"
    config.dev_auth_enabled = False
    config.public_url = "https://gateway.example"
    config.oidc_issuer = "https://identity.example"
    config.oidc_jwks_url = "https://identity.example/.well-known/jwks.json"
    config.downstream_credentials = {"acme": {"crm": "secret-manager-reference"}}
    config.validate()
