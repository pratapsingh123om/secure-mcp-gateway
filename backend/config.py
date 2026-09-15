from __future__ import annotations

import json
import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv


BASE_DIR = Path(__file__).resolve().parents[1]


def _bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _json(name: str, default: dict) -> dict:
    raw = os.getenv(name)
    return json.loads(raw) if raw else default


@dataclass(slots=True)
class Settings:
    environment: str = "development"
    host: str = "127.0.0.1"
    port: int = 8000
    public_url: str = "http://127.0.0.1:8000"
    oidc_issuer: str = "http://127.0.0.1:8000/dev-issuer"
    oidc_audience: str = "http://127.0.0.1:8000/mcp"
    oidc_jwks_url: str | None = None
    oidc_algorithms: tuple[str, ...] = ("RS256",)
    required_scope: str = "mcp:tools"
    dev_auth_enabled: bool = True
    dev_signing_secret: str = field(default_factory=lambda: secrets.token_urlsafe(48))
    opa_url: str = "http://127.0.0.1:8181/v1/data/mcp/authz/decision"
    opa_health_url: str = "http://127.0.0.1:8181/health"
    upstream_urls: dict[str, str] = field(default_factory=lambda: {
        "crm": "http://127.0.0.1:8001/mcp",
        "hr": "http://127.0.0.1:8002/mcp",
        "billing": "http://127.0.0.1:8003/mcp",
    })
    downstream_credentials: dict[str, dict[str, str]] = field(default_factory=lambda: {
        "acme": {"crm": "dev-acme-crm", "hr": "dev-acme-hr", "billing": "dev-acme-billing"},
        "globex": {"crm": "dev-globex-crm", "hr": "dev-globex-hr", "billing": "dev-globex-billing"},
    })
    audit_path: Path = BASE_DIR / "state" / "audit.jsonl"
    approvals_path: Path = BASE_DIR / "state" / "approvals.db"
    manifests_path: Path = BASE_DIR / "manifests" / "approved.json"
    approval_ttl_seconds: int = 300
    manifest_cache_seconds: int = 30
    rate_limit_per_minute: int = 60
    high_risk_rate_limit_per_minute: int = 10
    upstream_timeout_seconds: float = 10.0
    allowed_origins: tuple[str, ...] = ("http://localhost:5173", "http://127.0.0.1:5173")
    allowed_hosts: tuple[str, ...] = ("127.0.0.1:*", "localhost:*")
    otel_console_exporter: bool = False

    @classmethod
    def from_env(cls) -> "Settings":
        load_dotenv(BASE_DIR / ".env")
        environment = os.getenv("GATEWAY_ENV", "development")
        public_url = os.getenv("GATEWAY_PUBLIC_URL", "http://127.0.0.1:8000").rstrip("/")
        dev_enabled = _bool("DEV_AUTH_ENABLED", environment == "development")
        algorithms = tuple(part.strip() for part in os.getenv("OIDC_ALGORITHMS", "RS256").split(",") if part.strip())
        return cls(
            environment=environment,
            host=os.getenv("GATEWAY_HOST", "127.0.0.1"),
            port=int(os.getenv("GATEWAY_PORT", "8000")),
            public_url=public_url,
            oidc_issuer=os.getenv("OIDC_ISSUER", f"{public_url}/dev-issuer"),
            oidc_audience=os.getenv("OIDC_AUDIENCE", f"{public_url}/mcp"),
            oidc_jwks_url=os.getenv("OIDC_JWKS_URL") or None,
            oidc_algorithms=algorithms,
            required_scope=os.getenv("OIDC_REQUIRED_SCOPE", "mcp:tools"),
            dev_auth_enabled=dev_enabled,
            dev_signing_secret=os.getenv("DEV_SIGNING_SECRET", secrets.token_urlsafe(48)),
            opa_url=os.getenv("OPA_URL", "http://127.0.0.1:8181/v1/data/mcp/authz/decision"),
            opa_health_url=os.getenv("OPA_HEALTH_URL", "http://127.0.0.1:8181/health"),
            upstream_urls=_json("UPSTREAM_URLS_JSON", {
                "crm": "http://127.0.0.1:8001/mcp",
                "hr": "http://127.0.0.1:8002/mcp",
                "billing": "http://127.0.0.1:8003/mcp",
            }),
            downstream_credentials=_json("DOWNSTREAM_CREDENTIALS_JSON", {
                "acme": {"crm": "dev-acme-crm", "hr": "dev-acme-hr", "billing": "dev-acme-billing"},
                "globex": {"crm": "dev-globex-crm", "hr": "dev-globex-hr", "billing": "dev-globex-billing"},
            }),
            audit_path=Path(os.getenv("AUDIT_PATH", str(BASE_DIR / "state" / "audit.jsonl"))),
            approvals_path=Path(os.getenv("APPROVALS_PATH", str(BASE_DIR / "state" / "approvals.db"))),
            manifests_path=Path(os.getenv("MANIFESTS_PATH", str(BASE_DIR / "manifests" / "approved.json"))),
            approval_ttl_seconds=int(os.getenv("APPROVAL_TTL_SECONDS", "300")),
            manifest_cache_seconds=int(os.getenv("MANIFEST_CACHE_SECONDS", "30")),
            rate_limit_per_minute=int(os.getenv("RATE_LIMIT_PER_MINUTE", "60")),
            high_risk_rate_limit_per_minute=int(os.getenv("HIGH_RISK_RATE_LIMIT_PER_MINUTE", "10")),
            upstream_timeout_seconds=float(os.getenv("UPSTREAM_TIMEOUT_SECONDS", "10")),
            allowed_origins=tuple(item.strip() for item in os.getenv(
                "ALLOWED_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173"
            ).split(",") if item.strip()),
            allowed_hosts=tuple(item.strip() for item in os.getenv(
                "ALLOWED_HOSTS", "127.0.0.1:*,localhost:*"
            ).split(",") if item.strip()),
            otel_console_exporter=_bool("OTEL_CONSOLE_EXPORTER", False),
        )

    def validate(self) -> None:
        if self.environment == "production" and self.dev_auth_enabled:
            raise RuntimeError("DEV_AUTH_ENABLED must be false in production")
        if not self.dev_auth_enabled and not self.oidc_jwks_url:
            raise RuntimeError("OIDC_JWKS_URL is required when development authentication is disabled")
        if self.environment == "production" and not self.public_url.startswith("https://"):
            raise RuntimeError("GATEWAY_PUBLIC_URL must use HTTPS in production")
        if self.environment == "production":
            if not self.oidc_issuer.startswith("https://"):
                raise RuntimeError("OIDC_ISSUER must use HTTPS in production")
            if not str(self.oidc_jwks_url).startswith("https://"):
                raise RuntimeError("OIDC_JWKS_URL must use HTTPS in production")
            if any(algorithm.upper().startswith("HS") for algorithm in self.oidc_algorithms):
                raise RuntimeError("symmetric OIDC signing algorithms are forbidden in production")
            credentials = [
                credential
                for tenant_credentials in self.downstream_credentials.values()
                for credential in tenant_credentials.values()
            ]
            if not credentials or any(
                not credential
                or credential.lower().startswith("dev-")
                or credential.upper() == "REPLACE"
                for credential in credentials
            ):
                raise RuntimeError("production downstream credentials must come from a secret manager")
