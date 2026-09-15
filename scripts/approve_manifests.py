from __future__ import annotations

import argparse
import asyncio

from backend.config import Settings
from backend.manifest import ManifestRegistry
from backend.upstream import MCPUpstreamClient


async def approve_all(*, confirmed: bool) -> None:
    if not confirmed:
        raise SystemExit("Refusing to modify the trust baseline without --yes")
    settings = Settings.from_env()
    client = MCPUpstreamClient(settings)
    registry = ManifestRegistry(settings.manifests_path, settings.manifest_cache_seconds)
    for upstream in sorted(settings.upstream_urls):
        tools = await client.list_tools(upstream)
        status = registry.approve(upstream, tools)
        print(f"{upstream}: {status.status} {status.current_hash}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Review and approve the currently advertised upstream MCP manifests.")
    parser.add_argument("--yes", action="store_true", help="Confirm replacing each approved manifest hash.")
    arguments = parser.parse_args()
    asyncio.run(approve_all(confirmed=arguments.yes))
