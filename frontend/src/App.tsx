import { useState, FormEvent } from 'react';
import { ShieldCheck, Database, Lock, EyeOff, Activity, Code, Server, ArrowRight } from 'lucide-react';

function App() {
  const [dbConfig, setDbConfig] = useState({
    host: '',
    port: '5432',
    user: '',
    password: '',
    dbname: ''
  });
  
  const [connStatus, setConnStatus] = useState<'idle' | 'connecting' | 'success' | 'error'>('idle');

  const handleConnect = async (e: FormEvent) => {
    e.preventDefault();
    setConnStatus('connecting');
    // Simulate connection delay
    setTimeout(() => {
      if (dbConfig.host && dbConfig.user && dbConfig.password) {
        setConnStatus('success');
      } else {
        setConnStatus('error');
      }
    }, 1500);
  };

  return (
    <div className="min-h-screen bg-gray-50 font-sans text-gray-800">
      
      {/* Navigation */}
      <nav className="bg-white shadow-sm border-b border-gray-200">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between h-16 items-center">
            <div className="flex items-center space-x-2">
              <ShieldCheck className="h-8 w-8 text-indigo-600" />
              <span className="font-bold text-xl tracking-tight text-gray-900">Zero-Trust MCP</span>
            </div>
            <div className="flex space-x-4">
              <a href="#features" className="text-gray-600 hover:text-indigo-600 px-3 py-2 text-sm font-medium transition-colors">Features</a>
              <a href="#connect" className="text-gray-600 hover:text-indigo-600 px-3 py-2 text-sm font-medium transition-colors">Connect DB</a>
            </div>
          </div>
        </div>
      </nav>

      {/* Hero Section */}
      <div className="bg-indigo-900 text-white py-20">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col items-center text-center">
          <h1 className="text-5xl font-extrabold tracking-tight mb-6 leading-tight">
            Enterprise Security for AI Agents
          </h1>
          <p className="text-xl max-w-3xl text-indigo-200 mb-10 leading-relaxed">
            A protocol-aware reverse proxy that mediates tool discovery and execution. We enforce identity, tenant isolation, Open Policy Agent (OPA) rules, and Data Loss Prevention (DLP) natively—so your LLMs can't leak data.
          </p>
          <div className="flex space-x-4">
            <a href="#connect" className="bg-white text-indigo-900 px-8 py-3 rounded-lg font-bold shadow hover:bg-gray-100 transition flex items-center space-x-2">
              <span>Connect Database</span>
              <ArrowRight className="h-5 w-5" />
            </a>
            <a href="#features" className="border border-indigo-400 text-indigo-100 px-8 py-3 rounded-lg font-bold hover:bg-indigo-800 transition">
              Explore Architecture
            </a>
          </div>
        </div>
      </div>

      {/* Features Section */}
      <div id="features" className="py-20 bg-white">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center mb-16">
            <h2 className="text-3xl font-bold text-gray-900">Why a Gateway?</h2>
            <p className="mt-4 text-lg text-gray-600 max-w-2xl mx-auto">
              Connecting agents directly to databases is a security nightmare. Our gateway sits between the agent and your data, ensuring determinism.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-10">
            <FeatureCard 
              icon={<Lock className="h-10 w-10 text-indigo-600" />}
              title="Policy-as-Code (OPA)"
              description="Authorization is independent of the LLM. Rego policies enforce RBAC, ABAC, and human-in-the-loop approvals."
            />
            <FeatureCard 
              icon={<EyeOff className="h-10 w-10 text-indigo-600" />}
              title="Data Loss Prevention"
              description="Redact PII, API Keys, and SSNs before they cross trust boundaries using advanced regex and semantic scanners."
            />
            <FeatureCard 
              icon={<Server className="h-10 w-10 text-indigo-600" />}
              title="Tenant Isolation"
              description="Every principal resolves to exactly one tenant. Resources, quotas, and cache keys are strictly partitioned."
            />
          </div>
        </div>
      </div>

      {/* Database Connection Section */}
      <div id="connect" className="py-20 bg-gray-50">
        <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col md:flex-row bg-white rounded-2xl shadow-xl overflow-hidden border border-gray-100">
          
          <div className="md:w-1/2 bg-indigo-600 p-10 text-white flex flex-col justify-center">
            <Database className="h-16 w-16 mb-6 text-indigo-200" />
            <h3 className="text-3xl font-bold mb-4">Connect Your Database</h3>
            <p className="text-indigo-100 mb-6">
              Link your PostgreSQL database to automatically generate secure MCP tools. We'll deploy an isolated synthetic server mapped to your schema.
            </p>
            <ul className="space-y-3">
              <li className="flex items-center space-x-3"><Activity className="h-5 w-5 text-indigo-300"/> <span>Real-time OPA enforcement</span></li>
              <li className="flex items-center space-x-3"><Code className="h-5 w-5 text-indigo-300"/> <span>Auto-generated JSON-RPC schemas</span></li>
              <li className="flex items-center space-x-3"><ShieldCheck className="h-5 w-5 text-indigo-300"/> <span>Built-in secret scrubbing</span></li>
            </ul>
          </div>

          <div className="md:w-1/2 p-10">
            <form onSubmit={handleConnect} className="space-y-5">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Host</label>
                <input required type="text" className="w-full px-4 py-2 border border-gray-300 rounded-md focus:ring-indigo-500 focus:border-indigo-500 bg-white text-gray-900" placeholder="db.example.com" value={dbConfig.host} onChange={e => setDbConfig({...dbConfig, host: e.target.value})} />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Port</label>
                <input required type="text" className="w-full px-4 py-2 border border-gray-300 rounded-md focus:ring-indigo-500 focus:border-indigo-500 bg-white text-gray-900" placeholder="5432" value={dbConfig.port} onChange={e => setDbConfig({...dbConfig, port: e.target.value})} />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Database Name</label>
                <input required type="text" className="w-full px-4 py-2 border border-gray-300 rounded-md focus:ring-indigo-500 focus:border-indigo-500 bg-white text-gray-900" placeholder="postgres" value={dbConfig.dbname} onChange={e => setDbConfig({...dbConfig, dbname: e.target.value})} />
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">User</label>
                  <input required type="text" className="w-full px-4 py-2 border border-gray-300 rounded-md focus:ring-indigo-500 focus:border-indigo-500 bg-white text-gray-900" placeholder="admin" value={dbConfig.user} onChange={e => setDbConfig({...dbConfig, user: e.target.value})} />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Password</label>
                  <input required type="password" className="w-full px-4 py-2 border border-gray-300 rounded-md focus:ring-indigo-500 focus:border-indigo-500 bg-white text-gray-900" placeholder="••••••••" value={dbConfig.password} onChange={e => setDbConfig({...dbConfig, password: e.target.value})} />
                </div>
              </div>
              
              <button 
                type="submit" 
                disabled={connStatus === 'connecting'}
                className="w-full mt-6 bg-indigo-600 text-white font-bold py-3 px-4 rounded-md hover:bg-indigo-700 transition disabled:opacity-70 flex justify-center items-center"
              >
                {connStatus === 'connecting' ? 'Connecting...' : 'Securely Connect Database'}
              </button>

              {connStatus === 'success' && (
                <div className="mt-4 p-4 bg-green-50 text-green-800 rounded-md text-sm border border-green-200">
                  <span className="font-bold">Success!</span> Database connected. Your MCP endpoints have been provisioned under tenant isolation.
                </div>
              )}
              {connStatus === 'error' && (
                <div className="mt-4 p-4 bg-red-50 text-red-800 rounded-md text-sm border border-red-200">
                  <span className="font-bold">Connection Failed.</span> Please check your credentials or network configuration.
                </div>
              )}
            </form>
          </div>
        </div>
      </div>

      {/* Footer */}
      <footer className="bg-gray-900 text-gray-400 py-10 text-center">
        <p>© 2026 Zero-Trust MCP Gateway. Built for Enterprise Agentic AI.</p>
      </footer>
    </div>
  );
}

function FeatureCard({ icon, title, description }: { icon: React.ReactNode, title: string, description: string }) {
  return (
    <div className="p-8 rounded-xl bg-gray-50 border border-gray-100 hover:shadow-lg transition-shadow">
      <div className="mb-5 inline-block p-3 bg-white rounded-lg shadow-sm border border-gray-100">{icon}</div>
      <h3 className="text-xl font-bold text-gray-900 mb-3">{title}</h3>
      <p className="text-gray-600 leading-relaxed">{description}</p>
    </div>
  );
}

export default App;
