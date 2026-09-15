package mcp.authz

import rego.v1

policy_version := "rego-v1-2026-09-14"

default decision := {
    "decision": "DENY",
    "reason": "no policy rule matched",
    "policy_version": "rego-v1-2026-09-14",
}

known_tool if input.tool.name in {
    "crm_get_client",
    "hr_get_salary",
    "billing_get_invoice",
    "billing_delete_invoice",
}

tenant_matches if {
    is_string(input.principal.tenant)
    input.principal.tenant != ""
    input.resource.tenant == input.principal.tenant
}

entitled if {
    input.tool.name == "crm_get_client"
    some role in input.principal.roles
    role in {"crm-viewer", "admin"}
}

entitled if {
    input.tool.name == "hr_get_salary"
    some role in input.principal.roles
    role in {"hr-viewer", "admin"}
}

entitled if {
    input.tool.name == "billing_get_invoice"
    some role in input.principal.roles
    role in {"finance-viewer", "finance-admin", "admin"}
}

entitled if {
    input.tool.name == "billing_delete_invoice"
    some role in input.principal.roles
    role in {"finance-admin", "admin"}
}

high_risk if input.tool.risk in {"high", "critical"}

decision := {
    "decision": "ALLOW",
    "reason": "tool is visible to an entitled principal in the same tenant",
    "policy_version": policy_version,
} if {
    input.action == "list_tools"
    known_tool
    tenant_matches
    entitled
}

decision := {
    "decision": "ALLOW",
    "reason": "low-risk tool call authorized for principal and tenant",
    "policy_version": policy_version,
} if {
    input.action == "call_tool"
    known_tool
    tenant_matches
    entitled
    not high_risk
}

decision := {
    "decision": "REQUIRE_APPROVAL",
    "reason": "high-risk tool requires a matching, unexpired human approval",
    "policy_version": policy_version,
} if {
    input.action == "call_tool"
    known_tool
    tenant_matches
    entitled
    high_risk
    input.context.human_approval != true
}

decision := {
    "decision": "ALLOW",
    "reason": "high-risk tool authorized with matching human approval",
    "policy_version": policy_version,
} if {
    input.action == "call_tool"
    known_tool
    tenant_matches
    entitled
    high_risk
    input.context.human_approval == true
}
