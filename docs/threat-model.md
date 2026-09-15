# Threat model

## Assets

- tenant-scoped CRM, HR, and Billing records;
- gateway and per-tenant downstream credentials;
- authorization and approval decisions;
- tool schemas and descriptions;
- audit integrity and operational telemetry.

## Adversaries and controls

| Threat | Control | Verification |
|---|---|---|
| Forged, expired, wrong-issuer, or wrong-audience token | signature, issuer, audience, expiry, issued-at, scope, tenant, and role validation | auth tests |
| Client chooses another tenant | tenant comes only from verified claims; gateway injects it upstream | cross-tenant component and live tests |
| Guessing another tenant's resource ID | tenant-bound downstream token and tenant-partitioned server lookup | live test |
| Excessive tool capability disclosure | per-tool OPA evaluation on `tools/list` | discovery tests |
| Unauthorized or unknown tool call | deny-by-default OPA policy and fixed catalog | policy/service tests |
| Gateway token replayed against a downstream | distinct resource-specific downstream token selected internally | upstream credential test |
| Prompt or arguments contain a secret | outbound DLP blocks before upstream execution | DLP/service tests |
| Tool result exfiltrates PII or credentials | recursive inbound DLP redaction | DLP and live tests |
| Tool schema or description changes after review | canonical hash comparison, quarantine, suspicious-text check, explicit override | manifest tests/readiness |
| Destructive or highly sensitive call | exact-request, tenant-bound, expiring, single-use approval and OPA re-evaluation | approval and live tests |
| Approval replay or substitution | arguments/resource/tool/principal hashes and atomic consumption | approval tests |
| Policy engine fails open | adapter converts network and invalid-response failures to `DENY` | policy outage tests |
| Audit deletion/modification | chained record hashes and readiness verification | audit tamper test |
| Audit or telemetry leaks content | hashes, counts, and identifiers only; export scanned in live test | audit tests |
| SSRF or dynamic egress | immutable configured upstream map plus URL/host validation; internal network | upstream egress test and Compose config |
| Resource exhaustion | per-identity/tool sliding-window limits and container resource limits | rate-limit test |

## Residual risks

- Regex DLP catches known formats and sensitive field names; it is not a semantic classifier and can miss novel encodings.
- The development issuer can mint arbitrary synthetic identities and must never be enabled outside loopback development.
- Local bearer credentials on the internal Docker network are demonstration credentials. Production needs secret-manager rotation and TLS or mTLS between workloads.
- A privileged Docker host administrator can change containers or the persisted volume. Export audit events to an independently controlled durable sink for stronger non-repudiation.
- SQLite and JSONL are single-node stores. Multi-replica production requires a shared transactional store with atomic approval consumption.
- The manifest scanner detects drift and a targeted suspicious-language set; it does not prove that reviewed tool code is benign.
- The dashboard is an operator aid, not the policy authority. API authorization remains authoritative.

## Security invariants

1. A request is never authorized from a user-supplied tenant value.
2. An inbound bearer token is never forwarded to an upstream service.
3. No upstream call occurs after a deny decision, DLP block, untrusted manifest, invalid audit chain, or failed intent write.
4. High-risk authorization is bound to one exact request and is consumed once.
5. Raw arguments, results, and credentials are absent from audit records and security telemetry.
