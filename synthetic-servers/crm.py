from __future__ import annotations

import json
import os

from mcp.server.mcpserver.exceptions import ToolError

from .common import build_server, require_tenant, transport_security


RESOURCE_URL = os.getenv("CRM_RESOURCE_URL", "http://127.0.0.1:8001/mcp")
mcp = build_server("crm", RESOURCE_URL)

CLIENTS = {
    "acme": {
        "acme-100": {
            "company": "Acme Corporation",
            "contact_email": "alice@acme.example",
            "phone": "+1 415-555-0100",
            "api_key": "sk-live-ACMECRM123456789",
        }
    },
    "globex": {
        "globex-100": {
            "company": "Globex Corporation",
            "contact_email": "bob@globex.example",
            "phone": "+1 212-555-0199",
            "api_key": "sk-live-GLOBEXCRM987654",
        }
    },
}


@mcp.tool(description="Return exactly one CRM client belonging to the credential-bound tenant.")
def crm_get_client(client_id: str, tenant_id: str) -> str:
    tenant = require_tenant(tenant_id)
    record = CLIENTS.get(tenant, {}).get(client_id)
    if record is None:
        raise ToolError("Client does not exist in the authenticated tenant")
    return json.dumps({"tenant_id": tenant, "client_id": client_id, **record}, sort_keys=True)


app = mcp.streamable_http_app(
    streamable_http_path="/mcp",
    json_response=True,
    stateless_http=True,
    host=os.getenv("MCP_HOST", "127.0.0.1"),
    transport_security=transport_security("crm", 8001),
)
