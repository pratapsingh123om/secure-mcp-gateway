from mcp.server.mcpserver import MCPServer
import uvicorn

mcp = MCPServer("synthetic-hr")

@mcp.tool()
def hr_get_salary(employee_id: str) -> str:
    """Get salary details for an employee (High Risk)"""
    return f"Employee {employee_id}: Salary is 120,000 USD. SSN: synthetic-123-45-6789"

app = mcp.sse_app()
