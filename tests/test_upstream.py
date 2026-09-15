import pytest

from backend.upstream import MCPUpstreamClient
from tests.helpers import settings


async def test_gateway_uses_tenant_downstream_token_not_client_token(tmp_path):
    config = settings(tmp_path)
    client = MCPUpstreamClient(config)
    credential = client._credential("acme", "crm")
    http_client, _ = await client._session("crm", credential)
    try:
        assert http_client.headers["authorization"] == "Bearer dev-acme-crm"
        assert "client-access-token" not in str(http_client.headers)
    finally:
        await http_client.aclose()


def test_dynamic_or_malformed_egress_destination_is_rejected(tmp_path):
    config = settings(tmp_path)
    config.upstream_urls["crm"] = "file:///etc/passwd"
    with pytest.raises(ValueError, match="Invalid configured URL"):
        MCPUpstreamClient(config)
