import asyncio
import httpx
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.types import CallToolRequest, CallToolResult

async def get_token(base_url: str, subject: str, role: str) -> str:
    async with httpx.AsyncClient(base_url=base_url) as client:
        response = await client.post("/dev/token", json={
            "subject": subject,
            "tenant_id": "acme",
            "roles": [role],
            "scopes": ["mcp:tools", "control:read", "approval:write"]
        })
        response.raise_for_status()
        return response.json()["access_token"]

async def main():
    base_url = "http://127.0.0.1:8000"
    
    # 1. Agent logs in (Finance Admin)
    print("\n[Agent] Logging in as Finance Admin...")
    agent_token = await get_token(base_url, "finley", "finance-admin")
    
    # 2. Agent connects to the Gateway via MCP
    print("[Agent] Connecting to Zero-Trust Gateway via MCP SSE...")
    sse_url = f"{base_url}/mcp"
    
    import httpx2
    async with httpx2.AsyncClient(headers={"Authorization": f"Bearer {agent_token}"}, timeout=10) as client:
        async with streamable_http_client(sse_url, http_client=client) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                
                # 3. Agent lists tools
                print("\n[Agent] Discovering tools...")
                tools_response = await session.list_tools()
                tools = [t.name for t in tools_response.tools]
                print(f"[Agent] Found tools: {tools}")
                
                # 4. Agent attempts destructive action (Delete Invoice)
                print("\n[Agent] Attempting destructive action: billing_delete_invoice...")
                result = await session.call_tool("billing_delete_invoice", arguments={"invoice_id": "acme-inv-002", "tenant_id": "acme"})
                
                if result.is_error:
                    print(f"[Gateway] Blocked destructive action! Reason: {result.content[0].text}")
                    
                    # Extract approval ID
                    import json
                    try:
                        # Extract JSON from the error message string (e.g. 'Error executing tool...: {"approval_id"...}')
                        json_str = result.content[0].text.split(": ", 1)[1]
                        error_data = json.loads(json_str)
                        approval_id = error_data.get("approval_id")
                        
                        if approval_id:
                            # 5. Human Security Admin approves the request
                            print("\n[Human] Logging in as Security Admin to review...")
                            admin_token = await get_token(base_url, "security-admin", "admin")
                            async with httpx.AsyncClient(base_url=base_url, headers={"Authorization": f"Bearer {admin_token}"}) as client2:
                                print(f"[Human] Approving Request {approval_id}...")
                                resp = await client2.post(f"/v1/approvals/{approval_id}/approve", json={"approved": True})
                                resp.raise_for_status()
                                print("[Human] Request Approved.")
                            
                            # 6. Agent retries the action
                            print("\n[Agent] Retrying destructive action after human approval...")
                            result_retry = await session.call_tool("billing_delete_invoice", arguments={"invoice_id": "acme-inv-002", "tenant_id": "acme", "approval_id": approval_id})
                            if not result_retry.is_error:
                                print(f"[Gateway] Allowed action! Output: {result_retry.content[0].text}")
                            else:
                                print(f"[Gateway] Action failed: {result_retry.content[0].text}")
                    except Exception as e:
                        print(f"Could not parse approval_id: {e}")
                else:
                    print(f"[Gateway] Action succeeded (Expected it to be blocked!): {result.content[0].text}")

if __name__ == "__main__":
    asyncio.run(main())
