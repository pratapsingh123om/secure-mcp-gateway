from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class Decision(StrEnum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"


@dataclass(frozen=True, slots=True)
class Principal:
    subject: str
    client_id: str
    tenant_id: str
    roles: frozenset[str]
    scopes: frozenset[str]
    agent_id: str
    issuer: str


@dataclass(frozen=True, slots=True)
class ToolDefinition:
    name: str
    upstream: str
    upstream_tool: str
    description: str
    risk: str
    operation: str
    resource_argument: str


@dataclass(frozen=True, slots=True)
class PolicyResult:
    decision: Decision
    reason: str
    policy_version: str = "unknown"


@dataclass(frozen=True, slots=True)
class DLPFinding:
    kind: str
    path: str
    action: str


@dataclass(frozen=True, slots=True)
class DLPResult:
    value: Any
    findings: tuple[DLPFinding, ...] = ()

    @property
    def blocked(self) -> bool:
        return any(item.action == "BLOCK" for item in self.findings)

    @property
    def redaction_count(self) -> int:
        return sum(item.action == "REDACT" for item in self.findings)


@dataclass(frozen=True, slots=True)
class ExecutionResult:
    ok: bool
    text: str
    decision: Decision
    reason: str
    approval_id: str | None = None
    redactions: int = 0


@dataclass(slots=True)
class ManifestStatus:
    upstream: str
    approved_hash: str | None
    current_hash: str | None
    status: str
    suspicious_descriptions: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)
