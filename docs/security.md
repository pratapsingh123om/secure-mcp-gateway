# Security and deployment guide

## Development versus production

Docker Compose intentionally runs a local-only development issuer and synthetic credentials. Host ports are bound to `127.0.0.1`, upstream MCP servers are not published, and the backplane is an internal Docker network.

Production mode enforces external asymmetric OIDC and HTTPS configuration at startup. Start from `.env.example` and inject populated values using the deployment platform, not a committed file.

Required production changes:

- configure a trusted OIDC issuer, gateway-specific audience, HTTPS JWKS URL, and asymmetric algorithm such as RS256;
- source distinct tenant/upstream credentials from a secret manager and rotate them independently;
- terminate TLS at a trusted ingress and use TLS or mTLS from the gateway to sensitive upstreams;
- restrict `/v1/*`, `/metrics`, readiness details, and the dashboard to authorized operator networks;
- replace SQLite and JSONL local state for multi-replica operation;
- export OpenTelemetry to an authenticated collector and audit records to durable append-only storage;
- enforce infrastructure egress rules matching the configured upstream allowlist;
- set conservative resource, request-size, timeout, and rate limits for the deployment;
- run images as pinned digests and scan/sign the release artifacts.

## Identity claims

An accepted access token needs `iss`, `aud`, `sub`, `exp`, `iat`, `tenant_id`, `roles`, `scope`, and an agent identifier (`agent_id` or authorized client identifier). The default MCP scope is `mcp:tools`. Control-plane operations additionally require their endpoint scope and role.

The development `/dev/token` route exists only when `DEV_AUTH_ENABLED=true`. Production validation rejects that setting.

## Credential boundary

The upstream client accepts only a logical upstream name from the fixed catalog. It resolves that name through the configured URL map, validates the destination, and attaches a tenant/upstream-specific credential. Its API deliberately has no parameter for the inbound access token.

## Manifest change procedure

1. Observe that `/ready` reports the upstream as quarantined.
2. Review the actual upstream code, tool names, descriptions, and JSON schemas.
3. In a controlled environment, generate the candidate hashes:

   ```powershell
   .\.venv\Scripts\python.exe -m scripts.approve_manifests --yes
   ```

4. Review and commit the changed `manifests/approved.json`.
5. Deploy the reviewed baseline. Do not auto-approve drift during startup.

The control-plane manifest approval endpoint requires an administrator and `manifest:write`; using it is an explicit override and should be limited to the release workflow.

## Audit handling

Audit events contain timestamps, identities, tenant, tool/upstream names, policy and manifest versions, decisions, result categories, latency, redaction counts, and SHA-256 argument/record hashes. They must not contain raw arguments, tool results, JWTs, or downstream credentials.

Readiness verifies the full chain. Tool execution verifies it again and persists an execution-intent event before making an upstream call. Back up or export the log before planned rotation, and treat any verification failure as a security incident rather than silently rebuilding the chain.
