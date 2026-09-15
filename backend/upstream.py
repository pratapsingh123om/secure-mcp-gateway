from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

import httpx2
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamable_http_client

from backend.config import Settings


class UpstreamError(RuntimeError):
    pass


class MCPUpstreamClient:
    def __init__(self, settings: Settings):
        self.settings = settings
        for name, url in settings.upstream_urls.items():
            parsed = urlparse(url)
            if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                raise ValueError(f"Invalid configured URL for upstream {name}")

    def _credential(self, tenant_id: str, upstream: str) -> str:
        try:
            return self.settings.downstream_credentials[tenant_id][upstream]
        except KeyError as exc:
            raise UpstreamError("No tenant-bound downstream credential is configured") from exc

    async def _session(self, upstream: str, credential: str):
        url = self.settings.upstream_urls.get(upstream)
        if not url:
            raise UpstreamError(f"Unknown upstream: {upstream}")
        client = httpx2.AsyncClient(
            headers={"Authorization": f"Bearer {credential}"},
            timeout=self.settings.upstream_timeout_seconds,
        )
        return client, streamable_http_client(url, http_client=client)

    async def list_tools(self, upstream: str, *, tenant_id: str | None = None) -> list[dict[str, Any]]:
        selected_tenant = tenant_id or next(
            (tenant for tenant, credentials in self.settings.downstream_credentials.items() if upstream in credentials),
            None,
        )
        if selected_tenant is None:
            raise UpstreamError(f"No credential exists for upstream {upstream}")
        credential = self._credential(selected_tenant, upstream)
        client, transport = await self._session(upstream, credential)
        try:
            async with client:
                async with transport as (read, write):
                    async with ClientSession(read, write) as session:
                        await session.initialize()
                        result = await session.list_tools()
                        return [tool.model_dump(by_alias=True, exclude_none=True) for tool in result.tools]
        except Exception as exc:
            raise UpstreamError(f"Upstream {upstream} tool discovery failed") from exc

    async def call_tool(
        self,
        upstream: str,
        tool_name: str,
        arguments: dict[str, Any],
        *,
        tenant_id: str,
    ) -> str:
        credential = self._credential(tenant_id, upstream)
        client, transport = await self._session(upstream, credential)
        try:
            async with client:
                async with transport as (read, write):
                    async with ClientSession(read, write) as session:
                        await session.initialize()
                        result = await session.call_tool(tool_name, {**arguments, "tenant_id": tenant_id})
                        if result.is_error:
                            raise UpstreamError(f"Upstream {upstream} rejected the tool call")
                        texts = [str(item.text) for item in result.content if hasattr(item, "text")]
                        return "\n".join(texts)
        except UpstreamError:
            raise
        except Exception as exc:
            raise UpstreamError(f"Upstream {upstream} call failed") from exc
