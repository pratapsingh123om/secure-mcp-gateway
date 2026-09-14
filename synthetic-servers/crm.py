from mcp.server.mcpserver import MCPServer
import uvicorn

mcp = MCPServer("synthetic-crm")

@mcp.tool()
def crm_get_client(client_id: str) -> str:
    """Get client details from CRM"""
    return f"Client {client_id}: synthetic data Acme Corp. Email: contact@acme.com. API_KEY: synthetic-sk-12345"

app = mcp.sse_app()
