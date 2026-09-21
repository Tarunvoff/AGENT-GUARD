'use client';

import { useState, useMemo } from 'react';
import { Code, Copy, CheckCircle2, Globe, ChevronRight, ChevronDown, Search, X } from 'lucide-react';
import { PageHeader } from '@/components/ui/PageHeader';

/* ──────────────────────────────────────────────────────────────────────────
   DATA
────────────────────────────────────────────────────────────────────────── */

const SDK_SECTIONS = [
  {
    id: 'quickstart',
    label: 'Quick Start',
    content: [
      {
        title: 'Installation',
        body: `AgentGuard is designed to be lightweight. The core package has zero runtime dependencies beyond Python 3.11+. Install only what you need.`,
        code: [
          { lang: 'bash', label: 'Core (zero deps)', snippet: `pip install agentguard` },
          { lang: 'bash', label: 'With dashboard server', snippet: `pip install agentguard[server]` },
          { lang: 'bash', label: 'With LLM providers', snippet: `pip install agentguard[openai,gemini,anthropic]` },
          { lang: 'bash', label: 'All extras', snippet: `pip install agentguard[all]` },
        ],
      },
      {
        title: 'Initialize the Control Plane',
        body: 'Create a single `AgentGuard` instance and use `@guard.protect()` to wrap any agent entrypoint. The decorator intercepts every outbound tool call and context exchange.',
        code: [{ lang: 'python', label: 'main.py', snippet:
`from agentguard import AgentGuard

guard = AgentGuard(mode="strict")

@guard.protect(agent_id="orchestrator_v1", trust_level="HIGH")
def run_agent(task: str) -> str:
    # Your agent logic here
    return agent.run(task)` }],
      },
      {
        title: 'Enforcement Modes',
        body: 'Three built-in enforcement modes control how strictly the policy engine acts. All modes produce full evidence records.',
        code: [{ lang: 'python', label: 'modes.py', snippet:
`# STRICT  — Block all policy violations. Zero AI override.
guard = AgentGuard(mode="strict")

# MONITOR — Log and alert but do not block. Safe for staging.
guard = AgentGuard(mode="monitor")

# AUDIT   — Read-only. Record decisions without enforcement.
guard = AgentGuard(mode="audit")` }],
      },
    ],
  },
  {
    id: 'sdk-core',
    label: 'SDK Reference',
    content: [
      {
        title: 'AgentGuard Class',
        body: 'The primary entry point for all SDK operations. Thread-safe and designed for singleton usage per process.',
        code: [{ lang: 'python', label: 'class signature', snippet:
`class AgentGuard:
    def __init__(
        self,
        mode: Literal["strict", "monitor", "audit"] = "strict",
        config: ActShieldConfig | None = None,
        agent_id: str | None = None,
    ) -> None: ...

    def protect(
        self,
        agent_id: str,
        trust_level: Literal["HIGH", "MEDIUM", "LOW"] = "MEDIUM",
        capabilities: list[str] | None = None,
    ) -> Callable: ...

    def evaluate(self, action: Action) -> PolicyDecision: ...

    def record_incident(self, event_id: str, severity: str) -> Incident: ...` }],
      },
      {
        title: 'AgentGuardConfig',
        body: 'Configuration can be provided programmatically or via environment variables prefixed with `AGENTGUARD_`.',
        code: [{ lang: 'python', label: 'config.py', snippet:
`from agentguard import AgentGuardConfig

config = AgentGuardConfig(
    mode="strict",
    fail_safe_mode="BLOCK",          # Default on engine error
    max_delegation_depth=3,           # Max authority chain depth
    enable_forensics=True,            # Causal evidence records
    enable_drift_detection=True,      # Behavioral baseline checks
    log_redaction=True,               # Strip secrets from logs
    cors_origins=["http://localhost:3000"],
)

guard = AgentGuard(config=config)` }],
      },
      {
        title: 'Delegation & Authority',
        body: 'Control authority propagation between agents. AgentGuard tracks the full delegation lineage and enforces scope containment.',
        code: [{ lang: 'python', label: 'delegation.py', snippet:
`# Create a delegation token
token = guard.create_delegation(
    from_agent="orchestrator",
    to_agent="sub_agent",
    scope=["read_db", "query_customers"],   # Scope cannot exceed parent
    max_depth=2,                             # Further sub-delegation limit
    ttl_seconds=300,                         # Auto-expire after 5 minutes
)

# Verify a delegation chain
result = guard.verify_delegation(token, required_scope="read_db")
# result.valid, result.chain, result.violations` }],
      },
      {
        title: 'Context Provenance',
        body: 'Tag every piece of context with a trust level and track taint propagation through the agent execution graph.',
        code: [{ lang: 'python', label: 'context.py', snippet:
`from agentguard.context import ContextEntry, TrustLevel

# Attach provenance to a context entry
entry = ContextEntry(
    content=user_input,
    source="user_prompt",
    trust_level=TrustLevel.UNTRUSTED,     # Mark as external input
    tainted=True,                          # Propagate taint downstream
)

# Check if context is safe to act on
safe = guard.is_safe_context(entry, required_trust=TrustLevel.VERIFIED)` }],
      },
      {
        title: 'Threat Modeling',
        body: 'Build a structured threat model against your agent system. Identify critical assets, trust boundaries, and attack paths.',
        code: [{ lang: 'python', label: 'threat_model.py', snippet:
`from agentguard.threatmodel import ThreatModelAnalyzer

analyzer = ThreatModelAnalyzer(guard)

# Define an asset
analyzer.add_asset("customer_db", sensitivity="CRITICAL")

# Define a trust boundary
analyzer.add_boundary("external_user → orchestrator")

# Run automated threat analysis
report = analyzer.analyze()
print(report.critical_threats)   # List[Threat]
print(report.risk_score)          # 0.0–100.0` }],
      },
    ],
  },
  {
    id: 'api',
    label: 'REST API',
    content: [],  // rendered separately from API_ENDPOINTS
  },
  {
    id: 'cli',
    label: 'CLI Reference',
    content: [
      {
        title: 'CLI Entry Point',
        body: 'The `agentguard` CLI provides access to offensive validation, threat modeling, and server management.',
        code: [{ lang: 'bash', label: 'commands', snippet:
`agentguard --help

# Server
agentguard serve              # Start dashboard + API server

# Threat modeling
agentguard threat model       # Interactive threat model builder
agentguard threat analyze     # Run automated threat analysis
agentguard threat report      # Generate HTML/JSON report

# Offensive validation
agentguard attack run         # Launch adaptive attack campaign
agentguard attack list        # List all campaigns

# Health
agentguard doctor             # Verify SDK and server health` }],
      },
      {
        title: 'Threat Model Commands',
        body: 'Build and analyze threat models from the command line.',
        code: [{ lang: 'bash', label: 'threat commands', snippet:
`# Build a threat model interactively
agentguard threat model --output threat_model.json

# List all identified threats
agentguard threat list --severity critical

# Inspect a specific threat
agentguard threat inspect threat_001

# Export as STRIDE matrix
agentguard threat export --format stride --output stride.csv` }],
      },
      {
        title: 'Offensive Validation Commands',
        body: 'Run adversarial attacks against your own security boundary in a local sandbox.',
        code: [{ lang: 'bash', label: 'attack commands', snippet:
`# Run a full attack campaign
agentguard attack run --strategy all --target http://localhost:8000

# Run a specific attack type
agentguard attack run --strategy prompt_injection

# List campaigns and their bypass rates
agentguard attack list --format table

# View a campaign result
agentguard attack inspect campaign_001` }],
      },
    ],
  },
  {
    id: 'concepts',
    label: 'Concepts',
    content: [
      {
        title: 'Deterministic Policy Engine',
        body: `The core invariant of AgentGuard: no AI model can override policy decisions. AI advisory systems (AI Secura, APIRIS) produce risk signals only. The deterministic policy engine has final authority.

Every decision is reproducible given the same inputs. The engine applies mathematical invariants, not probabilistic heuristics. A BLOCK verdict produced today will produce the same result when replayed against the same evidence record tomorrow.`,
        code: [],
      },
      {
        title: '4-Point Execution Truth',
        body: `AgentGuard tracks the difference between what an agent intended, what it requested, what was allowed, and what actually executed. Divergence between these four states is a forensic finding.

• INTENDED — What the agent's prompt implied it would do
• REQUESTED — What the agent actually requested (tool call, API payload)
• ALLOWED — What the policy engine permitted
• EXECUTED — What the downstream system confirmed ran`,
        code: [],
      },
      {
        title: 'Taint Propagation',
        body: `Context entering the system from untrusted sources (user prompts, external APIs, web search results) is tagged as TAINTED. Taint propagates through the agent execution graph. Any action derived from tainted context is subject to higher scrutiny.

AgentGuard never implicitly trusts context because it came from the model — only verified, scoped, and provenance-tracked context receives elevated trust.`,
        code: [],
      },
      {
        title: 'Fail-Safe Design',
        body: `AgentGuard is designed to fail safely. If the policy engine encounters an error, the configured fail-safe mode determines the default decision:

• BLOCK (default) — Safest. Rejects the action on engine error.
• MONITOR — Allows the action but logs an anomaly.
• PASS — Allows the action. Not recommended for production.`,
        code: [{ lang: 'python', label: 'fail_safe.py', snippet:
`config = AgentGuardConfig(
    fail_safe_mode="BLOCK",   # On engine error, default to BLOCK
)` }],
      },
    ],
  },
];

const API_ENDPOINTS = [
  { method:'GET',  path:'/api/v1/agents',            category:'Agents',    desc:'List all registered agents with identity, trust level, and capability set.', params:[{name:'limit',type:'int',desc:'Max results (default 50)'},{name:'offset',type:'int',desc:'Pagination offset'}], response:`{"agents":[{"agent_id":"orchestrator_v2","trust_level":"HIGH","capabilities":["read_db","delegate"],"status":"ACTIVE"}],"total":5}` },
  { method:'GET',  path:'/api/v1/agents/{agent_id}', category:'Agents',    desc:'Get agent profile, current capabilities, delegation chain, and trust score.', params:[{name:'agent_id',type:'string',desc:'Agent identifier (path)'}], response:`{"agent_id":"orchestrator_v2","trust_level":"HIGH","delegation_depth":1,"taint_flags":[],"capabilities":["read_db","delegate"]}` },
  { method:'GET',  path:'/api/v1/events',            category:'Events',    desc:'Stream security decision events with filtering by decision, agent, and time range.', params:[{name:'decision',type:'string',desc:'Filter by ALLOW|BLOCK|HITL|MONITOR'},{name:'agent_id',type:'string',desc:'Filter by agent'},{name:'since',type:'ISO8601',desc:'Start timestamp'}], response:`{"events":[{"event_id":"evt_001","decision":"BLOCK","tool":"upload_s3","agent_id":"rogue_agent","timestamp":"2026-09-19T10:30:00Z"}],"total":47}` },
  { method:'POST', path:'/api/v1/policy/evaluate',   category:'Policy',    desc:'Evaluate a proposed action against the deterministic policy engine without executing.', params:[{name:'agent_id',type:'string',desc:'Acting agent'},{name:'action',type:'Action',desc:'Proposed action object'},{name:'context',type:'Context',desc:'Attached context object'}], response:`{"decision":"BLOCK","reason":"Scope violation: upload_s3 not in agent capability set","risk_score":0.94,"invariants_checked":7}` },
  { method:'GET',  path:'/api/v1/forensics/{event_id}',category:'Forensics',desc:'Full forensic evidence record and causal explanation for a specific event.', params:[{name:'event_id',type:'string',desc:'Event ID (path)'}], response:`{"event_id":"evt_001","causal_chain":["user_prompt→tainted_context→tool_call"],"execution_truth":{"intended":"summarize","requested":"upload_s3","allowed":"NONE","executed":"NONE"},"blast_radius":["customer_db","s3_bucket"]}` },
  { method:'GET',  path:'/api/v1/traces/{trace_id}', category:'Traces',    desc:'Causal execution trace with span-level decision evidence and latency breakdown.', params:[{name:'trace_id',type:'string',desc:'Trace ID (path)'}], response:`{"trace_id":"trc_001","spans":[{"span_id":"sp_001","operation":"tool_call","decision":"BLOCK","latency_ms":1.4}]}` },
  { method:'GET',  path:'/api/v1/campaigns',         category:'Offensive', desc:'List all offensive validation campaigns with empirical bypass prevention metrics.', params:[{name:'status',type:'string',desc:'Filter by RUNNING|COMPLETE|FAILED'}], response:`{"campaigns":[{"id":"cmp_001","strategy":"prompt_injection","variants_tested":47,"bypasses_found":0,"prevention_rate":1.0}]}` },
  { method:'POST', path:'/api/v1/attack/run',        category:'Offensive', desc:'Trigger a new adaptive attack campaign against a local sandbox target only.', params:[{name:'strategy',type:'string',desc:'Attack strategy type'},{name:'target',type:'url',desc:'Local target URL (localhost only)'}], response:`{"campaign_id":"cmp_002","status":"RUNNING","estimated_duration_s":120}` },
  { method:'GET',  path:'/api/v1/posture',           category:'Posture',   desc:'6-dimension security posture scorecard JSON for external monitoring integrations.', params:[], response:`{"score":98,"grade":"A+","dimensions":{"identity":100,"context":98,"policy":100,"forensics":95,"validation":96,"drift":99}}` },
  { method:'GET',  path:'/api/v1/incidents',         category:'Incidents', desc:'List all security incidents with lifecycle state, severity, and containment status.', params:[{name:'state',type:'string',desc:'Filter by OPEN|CONTAINED|RESOLVED'},{name:'severity',type:'string',desc:'CRITICAL|HIGH|MEDIUM|LOW'}], response:`{"incidents":[{"id":"inc_001","severity":"HIGH","state":"CONTAINED","agent_id":"rogue_agent","actions_taken":["QUARANTINE","REVOKE"]}]}` },
  { method:'GET',  path:'/api/v1/posture/drift',     category:'Posture',   desc:'Behavioral drift anomaly detection results versus verified baseline profiles.', params:[{name:'agent_id',type:'string',desc:'Specific agent (optional)'}], response:`{"agent_id":"orchestrator_v2","drift_score":0.03,"status":"NOMINAL","anomalies":[]}` },
];

const METHOD_COLORS: Record<string, string> = {
  GET:    'bg-emerald-50 text-emerald-700 border-emerald-200',
  POST:   'bg-blue-50 text-blue-700 border-blue-200',
  PUT:    'bg-amber-50 text-amber-700 border-amber-200',
  DELETE: 'bg-red-50 text-red-700 border-red-200',
};

/* ──────────────────────────────────────────────────────────────────────────
   COMPONENT
────────────────────────────────────────────────────────────────────────── */
export default function ApiPage() {
  const [activeSection, setActiveSection] = useState('quickstart');
  const [selectedEndpoint, setSelectedEndpoint] = useState(API_ENDPOINTS[0]);
  const [copied, setCopied] = useState<string | null>(null);
  const [apiSearch, setApiSearch] = useState('');
  const [apiCategory, setApiCategory] = useState('All');
  const [expandedConcept, setExpandedConcept] = useState<string | null>('Deterministic Policy Engine');

  const copy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopied(key);
    setTimeout(() => setCopied(null), 2000);
  };

  const filteredEndpoints = useMemo(() =>
    API_ENDPOINTS.filter(e =>
      (apiCategory === 'All' || e.category === apiCategory) &&
      (e.path.toLowerCase().includes(apiSearch.toLowerCase()) ||
       e.desc.toLowerCase().includes(apiSearch.toLowerCase()))
    ), [apiSearch, apiCategory]);

  const categories = ['All', ...Array.from(new Set(API_ENDPOINTS.map(e => e.category)))];
  const section = SDK_SECTIONS.find(s => s.id === activeSection);

  return (
    <div className="min-h-screen bg-slate-50" style={{ fontFamily:'Inter, system-ui, sans-serif' }}>
      <PageHeader
        title="Documentation"
        subtitle="SDK reference, REST API specification, CLI guide, and architectural concepts for AgentGuard."
        badge="v1.0.0"
        actions={
          <div className="flex items-center gap-2 text-xs font-mono text-slate-500 bg-white border border-slate-200 px-3 py-1.5 rounded">
            <Globe size={12} />
            <span>Base URL: http://127.0.0.1:8000</span>
          </div>
        }
      />

      <div className="max-w-screen-xl mx-auto px-6 py-8">
        <div className="grid grid-cols-1 lg:grid-cols-[220px_1fr] gap-8">

          {/* ── Sidebar ── */}
          <aside className="space-y-1">
            {SDK_SECTIONS.map(s => (
              <button key={s.id} onClick={() => setActiveSection(s.id)}
                className={`w-full text-left px-3 py-2 rounded text-[13px] font-medium transition-colors ${
                  activeSection === s.id
                    ? 'bg-blue-600 text-white'
                    : 'text-slate-700 hover:bg-slate-200 hover:text-slate-900'
                }`}>
                {s.label}
              </button>
            ))}

            {/* SDK extras info box */}
            <div className="mt-6 p-3 bg-white border border-slate-200 rounded-lg">
              <p className="text-[10px] font-bold uppercase tracking-widest text-slate-500 mb-2">Install Extras</p>
              {[
                { extra:'[cli]',       hint:'CLI tools (Rich/Typer)' },
                { extra:'[server]',    hint:'FastAPI + Uvicorn' },
                { extra:'[openai]',    hint:'OpenAI provider' },
                { extra:'[gemini]',    hint:'Gemini provider' },
                { extra:'[anthropic]', hint:'Claude provider' },
                { extra:'[all]',       hint:'Everything' },
              ].map(e => (
                <div key={e.extra} className="flex items-center justify-between py-1">
                  <code className="text-[10px] font-mono font-semibold text-blue-700">{e.extra}</code>
                  <span className="text-[10px] text-slate-400">{e.hint}</span>
                </div>
              ))}
            </div>
          </aside>

          {/* ── Main Content ── */}
          <main className="space-y-8 min-w-0">

            {/* ─── Non-Concepts / Non-API Sections ─── */}
            {activeSection !== 'api' && activeSection !== 'concepts' && section && (
              <div className="space-y-8">
                {section.content.map(item => (
                  <div key={item.title} className="bg-white border border-slate-200 rounded-lg overflow-hidden">
                    {/* Header */}
                    <div className="px-6 py-4 border-b border-slate-100">
                      <h3 className="text-base font-bold text-slate-900">{item.title}</h3>
                    </div>
                    {/* Body */}
                    <div className="px-6 pt-4 pb-2">
                      <p className="text-sm text-slate-600 leading-relaxed whitespace-pre-line">{item.body}</p>
                    </div>
                    {/* Code blocks */}
                    {item.code.map((block, ci) => (
                      <div key={ci} className="mx-6 mb-4 rounded-lg border border-slate-800 bg-slate-950 overflow-hidden">
                        <div className="flex items-center justify-between px-4 py-2 border-b border-slate-800">
                          <span className="text-[11px] font-mono text-slate-400">{block.label}</span>
                          <button onClick={() => copy(block.snippet, `${item.title}-${ci}`)}
                            className="flex items-center gap-1 text-[11px] font-mono text-slate-500 hover:text-white transition-colors">
                            {copied === `${item.title}-${ci}`
                              ? <><CheckCircle2 size={11} className="text-emerald-400" /> Copied</>
                              : <><Copy size={11} /> Copy</>}
                          </button>
                        </div>
                        <pre className="px-4 py-3 text-xs font-mono text-slate-200 leading-relaxed overflow-x-auto">
                          {block.snippet}
                        </pre>
                      </div>
                    ))}
                  </div>
                ))}
              </div>
            )}

            {/* ─── Concepts Accordion Section ─── */}
            {activeSection === 'concepts' && section && (
              <div className="space-y-4">
                {section.content.map(item => (
                  <div key={item.title} className="bg-white border border-slate-200 rounded-lg overflow-hidden">
                    <button
                      onClick={() => setExpandedConcept(expandedConcept === item.title ? null : item.title)}
                      className="w-full flex items-center justify-between px-6 py-4 text-left hover:bg-slate-50 transition-colors"
                    >
                      <h3 className="text-sm font-bold text-slate-900">{item.title}</h3>
                      {expandedConcept === item.title
                        ? <ChevronDown size={15} className="text-slate-500" />
                        : <ChevronRight size={15} className="text-slate-500" />}
                    </button>
                    {expandedConcept === item.title && (
                      <div className="px-6 pb-5 border-t border-slate-100 pt-4 space-y-4">
                        <p className="text-sm text-slate-600 leading-relaxed whitespace-pre-line">{item.body}</p>
                        {item.code.map((block, ci) => (
                          <div key={ci} className="rounded-lg border border-slate-800 bg-slate-950 overflow-hidden">
                            <div className="flex items-center justify-between px-4 py-2 border-b border-slate-800">
                              <span className="text-[11px] font-mono text-slate-400">{block.label}</span>
                              <button onClick={() => copy(block.snippet, `concept-${ci}`)}
                                className="flex items-center gap-1 text-[11px] font-mono text-slate-500 hover:text-white transition-colors">
                                {copied === `concept-${ci}`
                                  ? <><CheckCircle2 size={11} className="text-emerald-400" />Copied</>
                                  : <><Copy size={11} />Copy</>}
                              </button>
                            </div>
                            <pre className="px-4 py-3 text-xs font-mono text-slate-200 leading-relaxed overflow-x-auto">{block.snippet}</pre>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}

            {/* ─── REST API Section ─── */}
            {activeSection === 'api' && (
              <div className="grid grid-cols-1 xl:grid-cols-[1fr_440px] gap-6">
                {/* Left: Endpoint list */}
                <div className="bg-white border border-slate-200 rounded-lg overflow-hidden">
                  {/* Filters */}
                  <div className="px-4 py-3 border-b border-slate-200 space-y-3">
                    <div className="flex items-center gap-2 px-3 py-2 rounded border border-slate-200 bg-slate-50">
                      <Search size={12} className="text-slate-400 shrink-0" />
                      <input
                        value={apiSearch}
                        onChange={e => setApiSearch(e.target.value)}
                        placeholder="Search endpoints…"
                        className="flex-1 text-[13px] bg-transparent outline-none text-slate-700 placeholder:text-slate-400"
                      />
                      {apiSearch && (
                        <button onClick={() => setApiSearch('')}><X size={12} className="text-slate-400" /></button>
                      )}
                    </div>
                    <div className="flex flex-wrap gap-1.5">
                      {categories.map(c => (
                        <button key={c} onClick={() => setApiCategory(c)}
                          className={`text-[11px] font-medium px-2.5 py-1 rounded border transition-colors ${
                            apiCategory === c
                              ? 'bg-blue-600 text-white border-blue-600'
                              : 'bg-white text-slate-600 border-slate-200 hover:border-slate-300'
                          }`}>{c}</button>
                      ))}
                    </div>
                  </div>
                  {/* Endpoint list */}
                  <div className="divide-y divide-slate-100 max-h-[600px] overflow-y-auto">
                    {filteredEndpoints.length === 0 && (
                      <div className="px-4 py-8 text-center text-sm text-slate-400">No endpoints match your search.</div>
                    )}
                    {filteredEndpoints.map(ep => (
                      <button key={ep.path} onClick={() => setSelectedEndpoint(ep)}
                        className={`w-full text-left px-4 py-3 transition-colors ${
                          selectedEndpoint.path === ep.path ? 'bg-blue-50 border-l-2 border-blue-600' : 'hover:bg-slate-50 border-l-2 border-transparent'
                        }`}>
                        <div className="flex items-center gap-2 mb-1">
                          <span className={`text-[10px] font-mono font-bold px-1.5 py-0.5 rounded border ${METHOD_COLORS[ep.method]}`}>{ep.method}</span>
                          <code className="text-[12px] font-mono font-semibold text-slate-800 truncate">{ep.path}</code>
                        </div>
                        <p className="text-[11px] text-slate-500 leading-snug">{ep.desc}</p>
                      </button>
                    ))}
                  </div>
                </div>

                {/* Right: Endpoint detail */}
                <div className="bg-white border border-slate-200 rounded-lg overflow-hidden flex flex-col">
                  <div className="px-5 py-4 border-b border-slate-200">
                    <div className="flex items-center gap-2 mb-1">
                      <span className={`text-[10px] font-mono font-bold px-1.5 py-0.5 rounded border ${METHOD_COLORS[selectedEndpoint.method]}`}>{selectedEndpoint.method}</span>
                      <code className="text-sm font-mono font-bold text-slate-900">{selectedEndpoint.path}</code>
                    </div>
                    <p className="text-[13px] text-slate-600 mt-1">{selectedEndpoint.desc}</p>
                  </div>

                  {/* Parameters */}
                  {selectedEndpoint.params.length > 0 && (
                    <div className="px-5 py-4 border-b border-slate-200">
                      <p className="text-[10px] font-bold uppercase tracking-widest text-slate-500 mb-3">Parameters</p>
                      <div className="space-y-2">
                        {selectedEndpoint.params.map(p => (
                          <div key={p.name} className="flex items-start gap-3">
                            <code className="text-[11px] font-mono font-semibold text-slate-800 bg-slate-100 border border-slate-200 px-1.5 py-0.5 rounded shrink-0">{p.name}</code>
                            <span className="text-[11px] font-mono text-blue-600 shrink-0">{p.type}</span>
                            <span className="text-[11px] text-slate-500">{p.desc}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Response */}
                  <div className="flex-1 flex flex-col">
                    <div className="flex items-center justify-between px-5 py-3 border-b border-slate-100">
                      <p className="text-[10px] font-bold uppercase tracking-widest text-slate-500">Example Response</p>
                      <button onClick={() => copy(selectedEndpoint.response, 'response')}
                        className="flex items-center gap-1 text-[11px] font-mono text-slate-500 hover:text-slate-800 transition-colors">
                        {copied === 'response' ? <><CheckCircle2 size={11} className="text-emerald-500" />Copied</> : <><Copy size={11} />Copy JSON</>}
                      </button>
                    </div>
                    <div className="flex-1 bg-slate-950 p-4 font-mono overflow-auto">
                      <pre className="text-[11px] text-slate-200 leading-relaxed">
                        {JSON.stringify(JSON.parse(selectedEndpoint.response), null, 2)}
                      </pre>
                    </div>
                  </div>
                </div>
              </div>
            )}
          </main>
        </div>
      </div>
    </div>
  );
}
