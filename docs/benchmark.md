# Benchmark report

Measured on September 14, 2026 against the Docker Compose stack on a Windows Docker Desktop development machine. This is one local run, not a capacity claim or cross-machine comparison.

## Method

- 20 measured operations per sequential scenario after two warmups
- one CRM read per direct and full-path operation
- a new MCP Streamable HTTP session for every operation
- five concurrent clients, 20 total operations for the concurrency scenario
- OPA measured through its HTTP data API
- DLP measured in-process over a string containing email, SSN, and an API-key-shaped value

Because each MCP operation includes a fresh connection, initialization, discovery path, manifest fetch, policy call, audit writes, upstream session, and teardown, these results emphasize end-to-end security-path cost rather than steady-state connection reuse.

## Results

| Scenario | p50 | p95 | p99 | Mean | Sequential ops/s |
|---|---:|---:|---:|---:|---:|
| Direct CRM MCP | 55.299 ms | 90.857 ms | 101.331 ms | 58.632 ms | 17.056 |
| Gateway full security path | 302.277 ms | 399.025 ms | 533.106 ms | 323.076 ms | 3.095 |
| Gateway policy denial | 85.872 ms | 113.399 ms | 153.492 ms | 84.605 ms | 11.820 |
| OPA policy HTTP evaluation | 4.361 ms | 5.185 ms | 5.191 ms | 4.449 ms | 224.755 |
| DLP scan | 0.047 ms | 0.122 ms | 0.225 ms | 0.063 ms | 15,849.144 |

Measured full-path median overhead over direct MCP was **246.978 ms**.

The five-client scenario completed 20 full-path requests in 8,330.434 ms, or **2.401 requests/second**. Per-request latency was p50 2,289.393 ms, p95 2,433.689 ms, and p99 2,473.063 ms. This shows that connection/session setup and serialized service work dominate this small development stack; it is a useful optimization baseline, not a production throughput result.

## Post-test resource snapshot

Captured after the benchmark with `docker stats --no-stream`:

| Container | CPU | Memory |
|---|---:|---:|
| Gateway | 0.30% | 66.74 MiB / 384 MiB |
| OPA | 10.07% | 10.64 MiB / 128 MiB |
| CRM | 0.32% | 50.07 MiB / 192 MiB |
| HR | 0.35% | 49.23 MiB / 192 MiB |
| Billing | 0.36% | 49.98 MiB / 192 MiB |
| Dashboard | 0.00% | 7.15 MiB / 64 MiB |

This is a point-in-time sample captured shortly after the live test, not peak profiling.

## Reproduce

```powershell
.\run-servers.ps1
docker compose exec -T gateway python -m scripts.benchmark --base-url http://gateway:8000 --iterations 20 --concurrency 5
```

The benchmark runs inside the gateway container so it can reach both the internal direct-CRM baseline and the gateway endpoint using the same Docker network environment.

## Next optimization targets

1. Reuse initialized MCP sessions and HTTP connection pools.
2. Cache trusted manifests for the configured cache interval without weakening drift revalidation.
3. Batch or asynchronously export completion audit events after a durable local intent write.
4. Repeat with sustained duration, controlled hardware, mixed tools, and multiple concurrency levels.
