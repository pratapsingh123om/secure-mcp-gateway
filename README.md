# Zero-Trust MCP Security Gateway

An enterprise-grade, protocol-aware reverse proxy for the **Model Context Protocol (MCP)**. This project enables AI Agents to securely connect to external tools (like databases and APIs) without compromising sensitive data or violating access controls.

## 🚀 Features

- **Model Context Protocol Proxy**: intercepts, inspects, and forwards MCP traffic (JSON-RPC over SSE).
- **Policy-as-Code (OPA)**: Integrated with Open Policy Agent. Define declarative Rego policies to enforce Tenant Isolation, RBAC/ABAC, and Human-in-the-loop approvals before an AI agent can execute a tool.
- **Data Loss Prevention (DLP)**: Real-time scrubbing of LLM inputs and outputs. Redacts PII, SSNs, and API keys before they ever cross trust boundaries.
- **Synthetic Servers**: Includes mocked high-risk (HR) and low-risk (CRM) upstream MCP servers to test policies.
- **React Dashboard**: A Vite + Tailwind SPA to visualize gateway status, view registered upstream tools, and mock database connections.

## 🏗️ Architecture

1. **AI Agent / Client** -> Connects to Gateway over SSE (`http://localhost:8000/sse`)
2. **Gateway (`backend/main.py`)** -> Intercepts `call_tool` requests.
3. **OPA (`http://localhost:8181`)** -> Gateway asks OPA if the tenant/action is permitted.
4. **Upstream Servers** -> If allowed, Gateway proxies request to `synthetic-servers/crm.py` or `hr.py`.
5. **DLP Engine** -> Gateway intercepts upstream response, scrubs PII/Secrets, and streams back to the AI Agent.

## 🛠️ Tech Stack

- **Backend**: Python, FastAPI, MCP Python SDK (`mcp`)
- **Policy Engine**: Open Policy Agent (OPA), Rego
- **Database**: PostgreSQL (Dockerized)
- **Frontend**: React, Vite, Tailwind CSS, Lucide Icons

## ⚙️ Getting Started

### Prerequisites
- Python 3.11+
- Node.js & npm
- Docker & Docker Compose

### 1. Start Infrastructure (Docker)
Boot up Open Policy Agent and PostgreSQL:
```bash
docker-compose up -d
```

### 2. Start Backend & Synthetic Servers
Create a virtual environment, install dependencies, and start the proxy and upstream servers:
```bash
# Create and activate virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1  # Windows

# Install dependencies
pip install -r backend/requirements.txt
pip install -r synthetic-servers/requirements.txt

# Start all FastAPI servers (Gateway, CRM, HR)
.\run-servers.ps1
```

### 3. Start the Frontend Dashboard
```bash
cd frontend
npm install
npm run dev
```
Navigate to `http://localhost:5173` to see the live dashboard.

### 4. Test the Gateway
You can test the Data-Plane manually using the provided async python script. It will successfully execute the CRM tool (and redact the API key) but will get a strict policy denial when attempting to access HR salaries without approval:
```bash
python test_client.py
```

## 📜 Policies
Authentication and Authorization logic is strictly separated from the application code. See `policy/authz.rego` to view or modify the enforcement rules.

---
Built for secure, enterprise Agentic AI.
