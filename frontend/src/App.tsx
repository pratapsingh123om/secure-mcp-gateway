import { useCallback, useMemo, useState } from 'react';
import type { FormEvent, ReactNode } from 'react';
import {
  Activity,
  BadgeCheck,
  Check,
  CircleAlert,
  Clock3,
  FileClock,
  Fingerprint,
  KeyRound,
  LockKeyhole,
  RefreshCw,
  ShieldCheck,
  Siren,
  Waypoints,
} from 'lucide-react';

const API_BASE = (import.meta.env.VITE_API_URL || '/api').replace(/\/$/, '');

type ProfileKey = 'crm' | 'hr' | 'finance' | 'admin';
type Profile = { label: string; subject: string; roles: string[]; scopes: string[] };
type Ready = {
  status: string;
  checks: { policy_engine: boolean; audit_chain: { valid: boolean; detail: string }; manifests: Record<string, string> };
};
type Tool = { name: string; description: string; upstream: string; risk: string; operation: string };
type Manifest = { upstream: string; status: string; current_hash?: string; suspicious_descriptions?: string[] };
type Approval = { id: string; tool_name: string; resource_id: string; status: string; requested_at: number; expires_at: number };
type AuditEvent = {
  event_id: string;
  timestamp: string;
  tool: string;
  decision: string;
  result: string;
  principal_id: string;
  event_hash: string;
};

const profiles: Record<ProfileKey, Profile> = {
  crm: { label: 'CRM viewer', subject: 'alice', roles: ['crm-viewer'], scopes: ['mcp:tools', 'control:read'] },
  hr: { label: 'HR viewer', subject: 'carol', roles: ['hr-viewer'], scopes: ['mcp:tools', 'control:read'] },
  finance: {
    label: 'Finance admin',
    subject: 'finley',
    roles: ['finance-admin'],
    scopes: ['mcp:tools', 'control:read'],
  },
  admin: {
    label: 'Security admin',
    subject: 'security-admin',
    roles: ['admin', 'approver', 'auditor'],
    scopes: ['mcp:tools', 'control:read', 'approval:write', 'manifest:write', 'audit:read'],
  },
};

async function api<T>(path: string, token?: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...init?.headers,
    },
  });
  if (!response.ok) {
    const body = await response.text();
    throw new Error(`${response.status}: ${body}`);
  }
  return response.json() as Promise<T>;
}

function App() {
  const [tenant, setTenant] = useState('acme');
  const [profileKey, setProfileKey] = useState<ProfileKey>('admin');
  const [token, setToken] = useState('');
  const [ready, setReady] = useState<Ready | null>(null);
  const [tools, setTools] = useState<Tool[]>([]);
  const [manifests, setManifests] = useState<Manifest[]>([]);
  const [approvals, setApprovals] = useState<Approval[]>([]);
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const profile = profiles[profileKey];
  const canApprove = profile.scopes.includes('approval:write');
  const canAudit = profile.scopes.includes('audit:read');

  const refresh = useCallback(async (activeToken: string) => {
    setLoading(true);
    setError('');
    try {
      const [nextReady, nextTools, nextManifests] = await Promise.all([
        api<Ready>('/ready').catch((reason: Error) => {
          const detail = reason.message.match(/\{.*\}$/)?.[0];
          return detail ? (JSON.parse(detail) as Ready) : Promise.reject(reason);
        }),
        api<Tool[]>('/v1/tools', activeToken),
        api<Manifest[]>('/v1/tool-manifests', activeToken),
      ]);
      setReady(nextReady);
      setTools(nextTools);
      setManifests(nextManifests);

      if (canApprove) {
        setApprovals(await api<Approval[]>('/v1/approvals', activeToken));
      } else {
        setApprovals([]);
      }
      if (canAudit) {
        setEvents(await api<AuditEvent[]>('/v1/audit/events?limit=25', activeToken));
      } else {
        setEvents([]);
      }
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'Unable to load the gateway control plane');
    } finally {
      setLoading(false);
    }
  }, [canApprove, canAudit]);

  const signIn = async (event: FormEvent) => {
    event.preventDefault();
    setLoading(true);
    setError('');
    try {
      const response = await api<{ access_token: string }>('/dev/token', undefined, {
        method: 'POST',
        body: JSON.stringify({
          subject: profile.subject,
          tenant_id: tenant,
          roles: profile.roles,
          scopes: profile.scopes,
          agent_id: `${profileKey}-dashboard`,
        }),
      });
      setToken(response.access_token);
      await refresh(response.access_token);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'Development sign-in failed');
      setLoading(false);
    }
  };

  const approve = async (approvalId: string) => {
    if (!token) return;
    setError('');
    try {
      await api(`/v1/approvals/${approvalId}/approve`, token, { method: 'POST' });
      await refresh(token);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'Approval failed');
    }
  };

  const summary = useMemo(() => {
    const trusted = manifests.filter((manifest) => manifest.status.startsWith('TRUSTED')).length;
    return { trusted, pending: approvals.filter((approval) => approval.status === 'PENDING').length };
  }, [approvals, manifests]);

  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="brand"><ShieldCheck size={28} /><span>Zero-Trust MCP</span></div>
        <div className="endpoint"><span className="pulse" />{API_BASE}/mcp</div>
      </header>

      <main>
        <section className="hero-panel">
          <div>
            <p className="eyebrow">Agent control plane</p>
            <h1>Every tool call earns its way through.</h1>
            <p className="hero-copy">Verified identity, tenant-scoped credentials, OPA policy, DLP, approvals, manifest integrity, and tamper-evident audit—before data reaches an agent.</p>
          </div>
          <form className="identity-card" onSubmit={signIn}>
            <div className="identity-title"><Fingerprint size={19} /> Development identity</div>
            <label>Tenant<select value={tenant} onChange={(event) => setTenant(event.target.value)}><option value="acme">Acme</option><option value="globex">Globex</option></select></label>
            <label>Role profile<select value={profileKey} onChange={(event) => setProfileKey(event.target.value as ProfileKey)}>{Object.entries(profiles).map(([key, value]) => <option key={key} value={key}>{value.label}</option>)}</select></label>
            <button disabled={loading} type="submit"><KeyRound size={17} /> {token ? 'Switch identity' : 'Issue audience-bound token'}</button>
            <small>Development only. Production mode requires an external OIDC issuer and disables this endpoint.</small>
          </form>
        </section>

        {error && <div className="error-banner"><CircleAlert size={18} />{error}</div>}

        {!token ? (
          <section className="empty-state"><LockKeyhole size={34} /><h2>Authenticate to inspect the tenant control plane</h2><p>Tokens remain in memory and are never written to browser storage.</p></section>
        ) : (
          <>
            <section className="summary-grid">
              <Stat icon={<Activity />} label="Gateway" value={ready?.status || 'checking'} tone={ready?.status === 'ready' ? 'good' : 'warn'} />
              <Stat icon={<ShieldCheck />} label="OPA policy" value={ready?.checks.policy_engine ? 'healthy' : 'unavailable'} tone={ready?.checks.policy_engine ? 'good' : 'bad'} />
              <Stat icon={<BadgeCheck />} label="Trusted manifests" value={`${summary.trusted}/${manifests.length}`} tone={summary.trusted === manifests.length ? 'good' : 'bad'} />
              <Stat icon={<Clock3 />} label="Pending approvals" value={String(summary.pending)} tone={summary.pending ? 'warn' : 'neutral'} />
            </section>

            <div className="section-heading"><div><p className="eyebrow">Least privilege</p><h2>Visible tools for {profile.label}</h2></div><button className="secondary" onClick={() => void refresh(token)} disabled={loading}><RefreshCw className={loading ? 'spin' : ''} size={16} /> Refresh</button></div>
            <section className="tool-grid">
              {tools.map((tool) => <article className="tool-card" key={tool.name}><div className="tool-top"><Waypoints size={19} /><span className={`risk ${tool.risk}`}>{tool.risk}</span></div><h3>{tool.name}</h3><p>{tool.description}</p><footer><span>{tool.upstream}</span><span>{tool.operation}</span></footer></article>)}
              {!tools.length && <div className="inline-empty">No tools are authorized for this identity.</div>}
            </section>

            <section className="two-column">
              <Panel title="Upstream integrity" icon={<Siren size={19} />}>
                {manifests.map((manifest) => <div className="row" key={manifest.upstream}><div><strong>{manifest.upstream}</strong><small>{manifest.current_hash?.slice(0, 16) || 'unavailable'}</small></div><Status value={manifest.status} /></div>)}
              </Panel>
              <Panel title="Human approvals" icon={<Check size={19} />}>
                {!canApprove && <p className="muted">Switch to Security admin to inspect and approve tenant requests.</p>}
                {canApprove && !approvals.length && <p className="muted">No approval requests for this tenant.</p>}
                {approvals.slice(0, 8).map((approval) => <div className="row" key={approval.id}><div><strong>{approval.tool_name}</strong><small>{approval.resource_id} · {approval.status}</small></div>{approval.status === 'PENDING' ? <button className="compact" onClick={() => void approve(approval.id)}>Approve</button> : <Status value={approval.status} />}</div>)}
              </Panel>
            </section>

            <Panel title="Tamper-evident audit" icon={<FileClock size={19} />}>
              {!canAudit && <p className="muted">Audit events require the auditor role and audit:read scope.</p>}
              {canAudit && !events.length && <p className="muted">No events recorded for this tenant yet.</p>}
              {events.slice().reverse().map((event) => <div className="audit-row" key={event.event_id}><time>{new Date(event.timestamp).toLocaleTimeString()}</time><strong>{event.tool}</strong><Status value={event.decision} /><span>{event.result}</span><code>{event.event_hash.slice(0, 12)}</code></div>)}
            </Panel>
          </>
        )}
      </main>
    </div>
  );
}

function Stat({ icon, label, value, tone }: { icon: ReactNode; label: string; value: string; tone: string }) {
  return <article className={`stat ${tone}`}><div>{icon}</div><span>{label}</span><strong>{value}</strong></article>;
}

function Panel({ title, icon, children }: { title: string; icon: ReactNode; children: ReactNode }) {
  return <section className="panel"><header>{icon}<h2>{title}</h2></header><div>{children}</div></section>;
}

function Status({ value }: { value: string }) {
  const good = value === 'ALLOW' || value === 'APPROVED' || value === 'CONSUMED' || value.startsWith('TRUSTED');
  const warning = value === 'PENDING' || value === 'REQUIRE_APPROVAL';
  return <span className={`status ${good ? 'good' : warning ? 'warn' : 'bad'}`}>{value}</span>;
}

export default App;
