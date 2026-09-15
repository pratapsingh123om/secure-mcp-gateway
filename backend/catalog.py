from backend.models import ToolDefinition


TOOL_CATALOG: dict[str, ToolDefinition] = {
    "crm_get_client": ToolDefinition(
        name="crm_get_client",
        upstream="crm",
        upstream_tool="crm_get_client",
        description="Read one tenant-scoped CRM client record.",
        risk="low",
        operation="read",
        resource_argument="client_id",
    ),
    "hr_get_salary": ToolDefinition(
        name="hr_get_salary",
        upstream="hr",
        upstream_tool="hr_get_salary",
        description="Read one tenant-scoped salary record. Human approval is required.",
        risk="high",
        operation="read_sensitive",
        resource_argument="employee_id",
    ),
    "billing_get_invoice": ToolDefinition(
        name="billing_get_invoice",
        upstream="billing",
        upstream_tool="billing_get_invoice",
        description="Read one tenant-scoped invoice.",
        risk="medium",
        operation="read",
        resource_argument="invoice_id",
    ),
    "billing_delete_invoice": ToolDefinition(
        name="billing_delete_invoice",
        upstream="billing",
        upstream_tool="billing_delete_invoice",
        description="Delete one tenant-scoped invoice. Human approval is required.",
        risk="critical",
        operation="delete",
        resource_argument="invoice_id",
    ),
}
