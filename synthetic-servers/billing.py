from __future__ import annotations

import json
import os

from mcp.server.mcpserver.exceptions import ToolError

from .common import build_server, require_tenant, transport_security


RESOURCE_URL = os.getenv("BILLING_RESOURCE_URL", "http://127.0.0.1:8003/mcp")
mcp = build_server("billing", RESOURCE_URL)

INVOICES = {
    "acme": {
        "acme-inv-001": {"customer": "Acme Buyer", "amount_usd": 4200, "status": "open"},
    },
    "globex": {
        "globex-inv-001": {"customer": "Globex Buyer", "amount_usd": 7300, "status": "open"},
    },
}


@mcp.tool(description="Return one invoice belonging to the credential-bound tenant.")
def billing_get_invoice(invoice_id: str, tenant_id: str) -> str:
    tenant = require_tenant(tenant_id)
    record = INVOICES.get(tenant, {}).get(invoice_id)
    if record is None:
        raise ToolError("Invoice does not exist in the authenticated tenant")
    return json.dumps({"tenant_id": tenant, "invoice_id": invoice_id, **record}, sort_keys=True)


@mcp.tool(description="Delete one invoice belonging to the credential-bound tenant.")
def billing_delete_invoice(invoice_id: str, tenant_id: str) -> str:
    tenant = require_tenant(tenant_id)
    record = INVOICES.get(tenant, {}).pop(invoice_id, None)
    if record is None:
        raise ToolError("Invoice does not exist in the authenticated tenant")
    return json.dumps({"tenant_id": tenant, "invoice_id": invoice_id, "deleted": True}, sort_keys=True)


app = mcp.streamable_http_app(
    streamable_http_path="/mcp",
    json_response=True,
    stateless_http=True,
    host=os.getenv("MCP_HOST", "127.0.0.1"),
    transport_security=transport_security("billing", 8003),
)
