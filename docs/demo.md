# Reproducible security demo

## 1. Start and verify

```powershell
.\run-servers.ps1
Invoke-RestMethod http://127.0.0.1:8000/ready | ConvertTo-Json -Depth 6
```

Expected readiness is `ready`, a valid audit chain, and `TRUSTED` manifests for CRM, HR, and Billing.

## 2. Run the end-to-end proof

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe test_client.py
```

The script uses real MCP Streamable HTTP sessions and fails non-zero if any invariant is violated. Its checks are:

1. A CRM viewer discovers only `crm_get_client`.
2. An Acme CRM call succeeds while email, phone, and API key are redacted.
3. The same identity cannot retrieve a guessed Globex resource.
4. A finance viewer sees invoice read but cannot discover or invoke invoice deletion.
5. An HR salary call returns `REQUIRE_APPROVAL`.
6. A separate approver authorizes that exact request.
7. The approved call succeeds with SSN redaction.
8. Reusing the approval is denied.
9. Tenant audit export contains none of the synthetic sensitive values.

## 3. Inspect the operator view

Open `http://127.0.0.1:5173`. Choose a synthetic tenant/profile and connect. The dashboard reads live readiness, visible tools, manifest status, pending approvals, and tenant audit events. It does not emulate these values in the browser.

## 4. Run automated gates

```powershell
.\.venv\Scripts\python.exe -m pytest -m "not integration"
$env:GATEWAY_TEST_BASE_URL = "http://127.0.0.1:8000"
.\.venv\Scripts\python.exe -m pytest -m integration
```

## 5. Stop

```powershell
.\stop-servers.ps1
```

The named Docker volume is preserved so the approval database and audit chain survive restarts. Delete that volume only when intentionally resetting demonstration state.
