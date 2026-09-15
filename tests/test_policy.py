from backend.catalog import TOOL_CATALOG
from backend.models import Decision
from backend.policy import OPAPolicyEngine
import httpx
from tests.helpers import principal


class Response:
    status_code = 200

    def __init__(self, body):
        self.body = body

    def raise_for_status(self):
        return None

    def json(self):
        return self.body


class Client:
    body = {"result": {"decision": "ALLOW", "reason": "matched", "policy_version": "v1"}}

    def __init__(self, *args, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return None

    async def post(self, url, json):
        self.sent = json
        return Response(self.body)

    async def get(self, url):
        return Response({})


async def test_opa_adapter_sends_principal_agent_tool_resource_and_context(monkeypatch):
    monkeypatch.setattr("backend.policy.httpx.AsyncClient", Client)
    engine = OPAPolicyEngine("http://opa/decision", "http://opa/health")
    result = await engine.evaluate(
        principal(),
        TOOL_CATALOG["crm_get_client"],
        action="call_tool",
        resource_id="acme-100",
        resource_tenant="acme",
    )
    assert result.decision == Decision.ALLOW
    document = engine.input_document(
        principal(),
        TOOL_CATALOG["crm_get_client"],
        action="call_tool",
        resource_id="acme-100",
        resource_tenant="acme",
        human_approval=False,
    )
    assert document["principal"]["tenant"] == "acme"
    assert document["agent"]["id"] == "test-agent"
    assert document["resource"] == {"id": "acme-100", "tenant": "acme"}


async def test_invalid_opa_result_fails_closed(monkeypatch):
    class InvalidClient(Client):
        body = {"result": {"decision": "MAYBE"}}

    monkeypatch.setattr("backend.policy.httpx.AsyncClient", InvalidClient)
    engine = OPAPolicyEngine("http://opa/decision", "http://opa/health")
    result = await engine.evaluate(
        principal(),
        TOOL_CATALOG["crm_get_client"],
        action="call_tool",
        resource_id="acme-100",
        resource_tenant="acme",
    )
    assert result.decision == Decision.DENY
    assert "failed closed" in result.reason


async def test_policy_network_outage_fails_closed(monkeypatch):
    class OfflineClient(Client):
        async def post(self, url, json):
            raise httpx.ConnectError("offline")

    monkeypatch.setattr("backend.policy.httpx.AsyncClient", OfflineClient)
    result = await OPAPolicyEngine("http://opa/decision", "http://opa/health").evaluate(
        principal(),
        TOOL_CATALOG["crm_get_client"],
        action="call_tool",
        resource_id="acme-100",
        resource_tenant="acme",
    )
    assert result.decision == Decision.DENY
    assert "failed closed" in result.reason
