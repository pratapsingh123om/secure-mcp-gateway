from __future__ import annotations

import argparse
import asyncio
import json
import statistics
import time
import uuid
from collections.abc import Awaitable, Callable
from typing import Any

import httpx
import httpx2
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamable_http_client

from backend.config import Settings
from backend.dlp import DLPEngine


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int(round((len(ordered) - 1) * fraction))))
    return ordered[index]


def summary(samples: list[float]) -> dict[str, float]:
    return {
        "p50_ms": round(percentile(samples, 0.50), 3),
        "p95_ms": round(percentile(samples, 0.95), 3),
        "p99_ms": round(percentile(samples, 0.99), 3),
        "mean_ms": round(statistics.fmean(samples), 3),
        "requests_per_second_sequential": round(1000 / statistics.fmean(samples), 3),
    }


async def measure(operation: Callable[[], Awaitable[Any]], iterations: int) -> dict[str, float]:
    for _ in range(2):
        await operation()
    samples = []
    for _ in range(iterations):
        started = time.perf_counter()
        await operation()
        samples.append((time.perf_counter() - started) * 1000)
    return summary(samples)


async def measure_concurrent(
    operation: Callable[[], Awaitable[Any]], requests: int, concurrency: int
) -> dict[str, float | int]:
    semaphore = asyncio.Semaphore(concurrency)

    async def one() -> float:
        async with semaphore:
            started = time.perf_counter()
            await operation()
            return (time.perf_counter() - started) * 1000

    started = time.perf_counter()
    samples = await asyncio.gather(*(one() for _ in range(requests)))
    elapsed = time.perf_counter() - started
    return {
        **summary(samples),
        "concurrency": concurrency,
        "requests": requests,
        "wall_time_ms": round(elapsed * 1000, 3),
        "requests_per_second_concurrent": round(requests / elapsed, 3),
    }


async def mcp_call(url: str, token: str, tool: str, arguments: dict[str, Any]) -> None:
    async with httpx2.AsyncClient(headers={"Authorization": f"Bearer {token}"}, timeout=20) as client:
        async with streamable_http_client(url, http_client=client) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                await session.call_tool(tool, arguments)


async def issue_token(base_url: str) -> str:
    async with httpx.AsyncClient(base_url=base_url, timeout=10) as client:
        response = await client.post("/dev/token", json={
            "subject": f"benchmark-{uuid.uuid4().hex}",
            "tenant_id": "acme",
            "roles": ["crm-viewer"],
            "scopes": ["mcp:tools", "control:read"],
            "agent_id": "benchmark-agent",
        })
        response.raise_for_status()
        return str(response.json()["access_token"])


async def benchmark(base_url: str, iterations: int, concurrency: int) -> dict[str, Any]:
    settings = Settings.from_env()
    gateway_token = await issue_token(base_url)
    gateway_url = f"{base_url}/mcp"
    direct_url = settings.upstream_urls["crm"]
    direct_token = settings.downstream_credentials["acme"]["crm"]

    direct = await measure(
        lambda: mcp_call(
            direct_url,
            direct_token,
            "crm_get_client",
            {"client_id": "acme-100", "tenant_id": "acme"},
        ),
        iterations,
    )
    gateway = await measure(
        lambda: mcp_call(gateway_url, gateway_token, "crm_get_client", {"client_id": "acme-100"}),
        iterations,
    )
    denied = await measure(
        lambda: mcp_call(
            gateway_url,
            gateway_token,
            "billing_delete_invoice",
            {"invoice_id": "acme-inv-001"},
        ),
        iterations,
    )
    concurrent = await measure_concurrent(
        lambda: mcp_call(gateway_url, gateway_token, "crm_get_client", {"client_id": "acme-100"}),
        max(iterations, concurrency * 2),
        concurrency,
    )

    policy_payload = {
        "input": {
            "principal": {"id": "benchmark-user", "tenant": "acme", "roles": ["crm-viewer"]},
            "agent": {"id": "benchmark-agent"},
            "action": "call_tool",
            "tool": {"server": "crm", "name": "crm_get_client", "risk": "low", "operation": "read"},
            "resource": {"id": "acme-100", "tenant": "acme"},
            "context": {"human_approval": False},
        }
    }
    async with httpx.AsyncClient(timeout=10) as client:
        policy = await measure(lambda: client.post(settings.opa_url, json=policy_payload), iterations)

    dlp = DLPEngine()
    dlp_samples = []
    text = "Contact person@example.com with SSN 111-22-3333 and sk-live-ABCDEFGHIJKLMNOP"
    for _ in range(max(100, iterations * 10)):
        started = time.perf_counter()
        dlp.inspect(text, direction="inbound")
        dlp_samples.append((time.perf_counter() - started) * 1000)

    return {
        "iterations": iterations,
        "direct_mcp": direct,
        "gateway_full": gateway,
        "gateway_denied": denied,
        "gateway_concurrent": concurrent,
        "opa_policy": policy,
        "dlp_scan": summary(dlp_samples),
        "gateway_overhead_p50_ms": round(gateway["p50_ms"] - direct["p50_ms"], 3),
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Measure direct MCP and zero-trust gateway latency.")
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--iterations", type=int, default=20)
    parser.add_argument("--concurrency", type=int, default=5)
    args = parser.parse_args()
    if args.iterations < 5:
        parser.error("--iterations must be at least 5")
    if args.concurrency < 1:
        parser.error("--concurrency must be at least 1")
    print(json.dumps(
        asyncio.run(benchmark(args.base_url.rstrip("/"), args.iterations, args.concurrency)),
        indent=2,
        sort_keys=True,
    ))
