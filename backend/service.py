from __future__ import annotations

import time
import uuid
from typing import Any

from opentelemetry import trace

from backend.approvals import ApprovalStore
from backend.audit import AuditLog, hash_value
from backend.catalog import TOOL_CATALOG
from backend.config import Settings
from backend.dlp import DLPEngine
from backend.manifest import ManifestRegistry
from backend.metrics import Metrics
from backend.models import Decision, ExecutionResult, Principal, ToolDefinition
from backend.policy import PolicyEngine
from backend.rate_limit import SlidingWindowRateLimiter
from backend.upstream import MCPUpstreamClient, UpstreamError


class GatewayService:
    def __init__(
        self,
        settings: Settings,
        policy: PolicyEngine,
        upstream: MCPUpstreamClient,
        approvals: ApprovalStore,
        audit: AuditLog,
        manifests: ManifestRegistry,
        dlp: DLPEngine,
        rate_limiter: SlidingWindowRateLimiter,
        metrics: Metrics,
    ):
        self.settings = settings
        self.policy = policy
        self.upstream = upstream
        self.approvals = approvals
        self.audit = audit
        self.manifests = manifests
        self.dlp = dlp
        self.rate_limiter = rate_limiter
        self.metrics = metrics
        self.tracer = trace.get_tracer("secure-mcp-gateway")

    async def discover(self, principal: Principal) -> set[str]:
        visible: set[str] = set()
        for tool in TOOL_CATALOG.values():
            result = await self.policy.evaluate(
                principal,
                tool,
                action="list_tools",
                resource_id=None,
                resource_tenant=principal.tenant_id,
            )
            if result.decision == Decision.ALLOW:
                visible.add(tool.name)
        self.audit.append({
            "trace_id": self._trace_id(),
            "principal_id": principal.subject,
            "agent_id": principal.agent_id,
            "tenant_id": principal.tenant_id,
            "upstream": "gateway",
            "tool": "tools/list",
            "tool_manifest_hash": None,
            "policy_version": "opa",
            "decision": "ALLOW" if visible else "DENY",
            "decision_reason": f"returned {len(visible)} authorized tool(s)",
            "arguments_hash": hash_value({}),
            "redactions": 0,
            "latency_ms": 0.0,
            "result": "success",
        })
        return visible

    async def execute(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        principal: Principal,
        *,
        approval_id: str | None = None,
    ) -> ExecutionResult:
        started = time.perf_counter()
        audit_valid, audit_reason = self.audit.verify_chain()
        if not audit_valid:
            self.metrics.increment("audit_failures_total", reason="chain_invalid")
            return ExecutionResult(
                ok=False,
                text=f"audit sink unavailable; failed closed: {audit_reason}",
                decision=Decision.DENY,
                reason=f"audit sink unavailable; failed closed: {audit_reason}",
            )
        tool = TOOL_CATALOG.get(tool_name)
        if tool is None:
            return self._finish(
                principal, None, arguments, started, Decision.DENY, "unknown tool", "policy_denied"
            )

        with self.tracer.start_as_current_span("mcp.tools.call") as span:
            span.set_attribute("mcp.tool.name", tool.name)
            span.set_attribute("mcp.tenant.id", principal.tenant_id)
            span.set_attribute("mcp.agent.id", principal.agent_id)

            limit = (
                self.settings.high_risk_rate_limit_per_minute
                if tool.risk in {"high", "critical"}
                else self.settings.rate_limit_per_minute
            )
            allowed, retry_after = self.rate_limiter.allow(
                f"{principal.tenant_id}:{principal.subject}:{tool.name}", limit
            )
            if not allowed:
                return self._finish(
                    principal,
                    tool,
                    arguments,
                    started,
                    Decision.DENY,
                    f"rate limit exceeded; retry after {retry_after:.1f}s",
                    "throttled",
                )

            resource_id = str(arguments.get(tool.resource_argument, ""))
            if not resource_id:
                return self._finish(
                    principal, tool, arguments, started, Decision.DENY, "resource identifier is required", "invalid"
                )

            outbound = self.dlp.inspect(arguments, direction="outbound")
            if outbound.blocked:
                kinds = sorted({finding.kind for finding in outbound.findings})
                self.metrics.increment(
                    "dlp_blocks_total",
                    len(outbound.findings),
                    tool=tool.name,
                    direction="outbound",
                )
                return self._finish(
                    principal,
                    tool,
                    arguments,
                    started,
                    Decision.DENY,
                    f"outbound DLP blocked sensitive data: {', '.join(kinds)}",
                    "dlp_blocked",
                )

            policy = await self.policy.evaluate(
                principal,
                tool,
                action="call_tool",
                resource_id=resource_id,
                resource_tenant=principal.tenant_id,
            )
            if policy.decision == Decision.DENY:
                return self._finish(
                    principal, tool, arguments, started, policy.decision, policy.reason, "policy_denied",
                    policy_version=policy.policy_version,
                )

            try:
                tools = await self.upstream.list_tools(tool.upstream, tenant_id=principal.tenant_id)
                manifest = self.manifests.evaluate(tool.upstream, tools)
                if manifest.status not in {"TRUSTED", "TRUSTED_WITH_WARNINGS"}:
                    return self._finish(
                        principal,
                        tool,
                        arguments,
                        started,
                        Decision.DENY,
                        f"upstream quarantined: {manifest.status}",
                        "manifest_denied",
                        manifest_hash=manifest.current_hash,
                        policy_version=policy.policy_version,
                    )
            except UpstreamError as exc:
                return self._finish(
                    principal, tool, arguments, started, Decision.DENY, str(exc), "upstream_error",
                    policy_version=policy.policy_version,
                )

            if not self._record_execution_intent(
                principal, tool, arguments, policy.decision, policy.reason, manifest.current_hash, policy.policy_version
            ):
                reason = "audit sink unavailable before execution; failed closed"
                return ExecutionResult(False, reason, Decision.DENY, reason)

            arguments_hash = hash_value(arguments)
            if policy.decision == Decision.REQUIRE_APPROVAL:
                if not approval_id:
                    request_id = self.approvals.request(
                        principal,
                        tool_name=tool.name,
                        resource_id=resource_id,
                        arguments_hash=arguments_hash,
                    )
                    return self._finish(
                        principal,
                        tool,
                        arguments,
                        started,
                        Decision.REQUIRE_APPROVAL,
                        "human approval required",
                        "approval_required",
                        approval_id=request_id,
                        policy_version=policy.policy_version,
                    )
                if not self.approvals.consume(
                    approval_id,
                    principal,
                    tool_name=tool.name,
                    resource_id=resource_id,
                    arguments_hash=arguments_hash,
                ):
                    return self._finish(
                        principal,
                        tool,
                        arguments,
                        started,
                        Decision.DENY,
                        "approval is missing, expired, already used, or does not match this exact request",
                        "approval_denied",
                        approval_id=approval_id,
                        policy_version=policy.policy_version,
                    )
                approved_policy = await self.policy.evaluate(
                    principal,
                    tool,
                    action="call_tool",
                    resource_id=resource_id,
                    resource_tenant=principal.tenant_id,
                    human_approval=True,
                )
                if approved_policy.decision != Decision.ALLOW:
                    return self._finish(
                        principal,
                        tool,
                        arguments,
                        started,
                        Decision.DENY,
                        approved_policy.reason,
                        "policy_denied",
                        approval_id=approval_id,
                        policy_version=approved_policy.policy_version,
                    )
                policy = approved_policy

            try:
                output = await self.upstream.call_tool(
                    tool.upstream,
                    tool.upstream_tool,
                    dict(outbound.value),
                    tenant_id=principal.tenant_id,
                )
            except UpstreamError as exc:
                return self._finish(
                    principal, tool, arguments, started, Decision.DENY, str(exc), "upstream_error",
                    policy_version=policy.policy_version,
                )

            inbound = self.dlp.inspect(output, direction="inbound")
            return self._finish(
                principal,
                tool,
                arguments,
                started,
                Decision.ALLOW,
                policy.reason,
                "success",
                text=str(inbound.value),
                redactions=inbound.redaction_count,
                manifest_hash=manifest.current_hash,
                policy_version=policy.policy_version,
            )

    def _record_execution_intent(
        self,
        principal: Principal,
        tool: ToolDefinition,
        arguments: dict[str, Any],
        decision: Decision,
        reason: str,
        manifest_hash: str | None,
        policy_version: str,
    ) -> bool:
        try:
            self.audit.append({
                "trace_id": self._trace_id(),
                "principal_id": principal.subject,
                "agent_id": principal.agent_id,
                "tenant_id": principal.tenant_id,
                "upstream": tool.upstream,
                "tool": tool.name,
                "tool_manifest_hash": manifest_hash,
                "policy_version": policy_version,
                "decision": decision.value,
                "decision_reason": reason,
                "arguments_hash": hash_value(arguments),
                "redactions": 0,
                "latency_ms": 0.0,
                "result": "execution_intent",
            })
            return True
        except (OSError, ValueError):
            self.metrics.increment("audit_failures_total", reason="intent_write")
            return False

    def _trace_id(self) -> str:
        context = trace.get_current_span().get_span_context()
        return format(context.trace_id, "032x") if context.is_valid else uuid.uuid4().hex

    def _finish(
        self,
        principal: Principal,
        tool: ToolDefinition | None,
        arguments: dict[str, Any],
        started: float,
        decision: Decision,
        reason: str,
        result: str,
        *,
        text: str | None = None,
        approval_id: str | None = None,
        redactions: int = 0,
        manifest_hash: str | None = None,
        policy_version: str = "unknown",
    ) -> ExecutionResult:
        elapsed_ms = (time.perf_counter() - started) * 1000
        tool_name = tool.name if tool else "unknown"
        self.metrics.increment("requests_total", tool=tool_name, decision=decision.value, result=result)
        self.metrics.increment("request_latency_ms_sum", elapsed_ms, tool=tool_name)
        if redactions:
            self.metrics.increment("dlp_redactions_total", redactions, tool=tool_name, direction="inbound")
        try:
            self.audit.append({
                "trace_id": self._trace_id(),
                "principal_id": principal.subject,
                "agent_id": principal.agent_id,
                "tenant_id": principal.tenant_id,
                "upstream": tool.upstream if tool else "none",
                "tool": tool_name,
                "tool_manifest_hash": manifest_hash,
                "policy_version": policy_version,
                "decision": decision.value,
                "decision_reason": reason,
                "arguments_hash": hash_value(arguments),
                "redactions": redactions,
                "latency_ms": round(elapsed_ms, 3),
                "result": result,
                "approval_id": approval_id,
            })
        except (OSError, ValueError):
            self.metrics.increment("audit_failures_total", reason="completion_write")
            audit_reason = "audit completion write failed; execution intent remains recorded"
            return ExecutionResult(False, audit_reason, Decision.DENY, audit_reason, approval_id, redactions)
        return ExecutionResult(
            ok=decision == Decision.ALLOW and result == "success",
            text=text or reason,
            decision=decision,
            reason=reason,
            approval_id=approval_id,
            redactions=redactions,
        )
