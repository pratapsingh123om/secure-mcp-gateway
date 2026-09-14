package mcp.authz

import future.keywords.in

default allow := false
default require_approval := false

# Allow list tools for anyone authenticated (discovery filtering happens in gateway)
allow if {
    input.action == "list_tools"
}

# Allow calling CRM read tools
allow if {
    input.action == "call_tool"
    input.tool_name == "crm_get_client"
}

# Require approval for high-risk HR tools
require_approval if {
    input.action == "call_tool"
    input.tool_name == "hr_get_salary"
}

# If approval is required and we have it, allow.
allow if {
    require_approval
    input.context.human_approval == true
}

# If no approval is required, but it's a known low-risk tool
allow if {
    input.action == "call_tool"
    not require_approval
    input.tool_name == "crm_get_client"
}
