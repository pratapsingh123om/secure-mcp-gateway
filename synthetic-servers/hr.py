from __future__ import annotations

import json
import os

from mcp.server.mcpserver.exceptions import ToolError

from .common import build_server, require_tenant, transport_security


RESOURCE_URL = os.getenv("HR_RESOURCE_URL", "http://127.0.0.1:8002/mcp")
mcp = build_server("hr", RESOURCE_URL)

EMPLOYEES = {
    "acme": {
        "acme-e01": {"name": "Alice Example", "salary_usd": 120000, "ssn": "111-22-3333"},
    },
    "globex": {
        "globex-e01": {"name": "Bob Example", "salary_usd": 115000, "ssn": "222-33-4444"},
    },
}


@mcp.tool(description="Return one salary record belonging to the credential-bound tenant.")
def hr_get_salary(employee_id: str, tenant_id: str) -> str:
    tenant = require_tenant(tenant_id)
    record = EMPLOYEES.get(tenant, {}).get(employee_id)
    if record is None:
        raise ToolError("Employee does not exist in the authenticated tenant")
    return json.dumps({"tenant_id": tenant, "employee_id": employee_id, **record}, sort_keys=True)


app = mcp.streamable_http_app(
    streamable_http_path="/mcp",
    json_response=True,
    stateless_http=True,
    host=os.getenv("MCP_HOST", "127.0.0.1"),
    transport_security=transport_security("hr", 8002),
)
