import asyncio
import httpx
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from mcp.server.mcpserver import MCPServer
from mcp.client.sse import sse_client
from mcp.client.session import ClientSession
import re

OPA_URL = "http://127.0.0.1:8181/v1/data/mcp/authz/allow"

mcp = MCPServer("secure-mcp-gateway")

async def check_opa_policy(action: str, tool_name: str, tenant_id: str, context: dict = None):
    async with httpx.AsyncClient() as client:
        payload = {
            "input": {
                "action": action,
                "tool_name": tool_name,
                "tenant_id": tenant_id,
                "context": context or {}
            }
        }
        try:
            resp = await client.post(OPA_URL, json=payload)
            if resp.status_code == 200:
                return resp.json().get("result", False)
        except Exception as e:
            print("OPA check failed:", e)
        return False

def apply_dlp(text: str) -> str:
    text = re.sub(r'synthetic-sk-[A-Za-z0-9]+', '[REDACTED API KEY]', text)
    text = re.sub(r'synthetic-\d{3}-\d{2}-\d{4}', '[REDACTED SSN]', text)
    return text

@mcp.tool()
async def crm_get_client(client_id: str) -> str:
    """Get client details from CRM"""
    tenant_id = "tenant-1"
    allowed = await check_opa_policy("call_tool", "crm_get_client", tenant_id)
    if not allowed:
        return "Error: Unauthorized by policy."

    async with sse_client("http://127.0.0.1:8001/sse") as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool("crm_get_client", {"client_id": client_id})
            return apply_dlp(result.content[0].text)

@mcp.tool()
async def hr_get_salary(employee_id: str) -> str:
    """Get salary details for an employee (High Risk)"""
    tenant_id = "tenant-1"
    allowed = await check_opa_policy("call_tool", "hr_get_salary", tenant_id)
    if not allowed:
        return "Error: Unauthorized by policy."

    async with sse_client("http://127.0.0.1:8002/sse") as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool("hr_get_salary", {"employee_id": employee_id})
            return apply_dlp(result.content[0].text)

# Create FastAPI app for control plane and mount MCP dataplane
app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/api/status")
def status():
    return {"status": "ok", "message": "Zero-Trust MCP Gateway is running and policies are active"}

@app.get("/api/tools")
def tools():
    return [
        {"name": "crm_get_client", "description": "Get client details from CRM", "risk": "Low"},
        {"name": "hr_get_salary", "description": "Get salary details for an employee (High Risk)", "risk": "High"}
    ]

# Mount the MCP sse app under / (it sets up /sse and /messages)
app.mount("/", mcp.sse_app())
