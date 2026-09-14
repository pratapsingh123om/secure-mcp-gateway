import asyncio
from mcp.client.sse import sse_client
from mcp.client.session import ClientSession

async def main():
    print("Connecting to Zero-Trust MCP Gateway...")
    async with sse_client("http://127.0.0.1:8000/sse") as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            
            print("Listing tools...")
            tools = await session.list_tools()
            for t in tools.tools:
                print(f" - {t.name}: {t.description}")
            
            print("\nCalling crm_get_client (should be ALLOWED)...")
            try:
                res1 = await session.call_tool("crm_get_client", {"client_id": "999"})
                print("Result:", res1.content[0].text)
            except Exception as e:
                print("Failed:", e)
                
            print("\nCalling hr_get_salary (should be DENIED without approval)...")
            try:
                res2 = await session.call_tool("hr_get_salary", {"employee_id": "404"})
                print("Result:", res2.content[0].text)
            except Exception as e:
                print("Failed:", e)

if __name__ == "__main__":
    asyncio.run(main())
