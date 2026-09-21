(globalThis.TURBOPACK||(globalThis.TURBOPACK=[])).push(["object"==typeof document?document.currentScript:void 0,51757,e=>{"use strict";var t=e.i(56420);let a={name:"circle-check",size:24,node:[["circle",{cx:"12",cy:"12",r:"10",key:"1mglay"}],["path",{d:"m16 9-5.5 5.5L8 12",key:"xofnsj"}]],aliases:["check-circle-2"]};a.node;let s=(0,t.default)(a);e.s(["CheckCircle2",0,s],51757)},8734,e=>{"use strict";var t=e.i(56420);let a={name:"copy",size:24,node:[["rect",{width:"14",height:"14",x:"8",y:"8",rx:"2",ry:"2",key:"17jyea"}],["path",{d:"M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2",key:"zix9uf"}]]};a.node;let s=(0,t.default)(a);e.s(["Copy",0,s],8734)},91511,e=>{"use strict";var t=e.i(56420);let a={name:"globe",size:24,node:[["circle",{cx:"12",cy:"12",r:"10",key:"1mglay"}],["path",{d:"M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20",key:"13o1zl"}],["path",{d:"M2 12h20",key:"9i4pu4"}]]};a.node;let s=(0,t.default)(a);e.s(["Globe",0,s],91511)},63676,e=>{"use strict";var t=e.i(56420);let a={name:"x",size:24,node:[["path",{d:"M18 6 6 18",key:"1bl5f8"}],["path",{d:"m6 6 12 12",key:"d8bk6v"}]]};a.node;let s=(0,t.default)(a);e.s(["X",0,s],63676)},14748,e=>{"use strict";var t=e.i(43476),a=e.i(71645),s=e.i(8734),n=e.i(51757),r=e.i(91511),i=e.i(67927),o=e.i(16327),l=e.i(66595),d=e.i(63676),c=e.i(37757);let p=[{id:"quickstart",label:"Quick Start",content:[{title:"Installation",body:"AgentGuard is designed to be lightweight. The core package has zero runtime dependencies beyond Python 3.11+. Install only what you need.",code:[{lang:"bash",label:"Core (zero deps)",snippet:"pip install agentguard"},{lang:"bash",label:"With dashboard server",snippet:"pip install agentguard[server]"},{lang:"bash",label:"With LLM providers",snippet:"pip install agentguard[openai,gemini,anthropic]"},{lang:"bash",label:"All extras",snippet:"pip install agentguard[all]"}]},{title:"Initialize the Control Plane",body:"Create a single `AgentGuard` instance and use `@guard.protect()` to wrap any agent entrypoint. The decorator intercepts every outbound tool call and context exchange.",code:[{lang:"python",label:"main.py",snippet:`from agentguard import AgentGuard

guard = AgentGuard(mode="strict")

@guard.protect(agent_id="orchestrator_v1", trust_level="HIGH")
def run_agent(task: str) -> str:
    # Your agent logic here
    return agent.run(task)`}]},{title:"Enforcement Modes",body:"Three built-in enforcement modes control how strictly the policy engine acts. All modes produce full evidence records.",code:[{lang:"python",label:"modes.py",snippet:`# STRICT  — Block all policy violations. Zero AI override.
guard = AgentGuard(mode="strict")

# MONITOR — Log and alert but do not block. Safe for staging.
guard = AgentGuard(mode="monitor")

# AUDIT   — Read-only. Record decisions without enforcement.
guard = AgentGuard(mode="audit")`}]}]},{id:"sdk-core",label:"SDK Reference",content:[{title:"AgentGuard Class",body:"The primary entry point for all SDK operations. Thread-safe and designed for singleton usage per process.",code:[{lang:"python",label:"class signature",snippet:`class AgentGuard:
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

    def record_incident(self, event_id: str, severity: str) -> Incident: ...`}]},{title:"AgentGuardConfig",body:"Configuration can be provided programmatically or via environment variables prefixed with `AGENTGUARD_`.",code:[{lang:"python",label:"config.py",snippet:`from agentguard import AgentGuardConfig

config = AgentGuardConfig(
    mode="strict",
    fail_safe_mode="BLOCK",          # Default on engine error
    max_delegation_depth=3,           # Max authority chain depth
    enable_forensics=True,            # Causal evidence records
    enable_drift_detection=True,      # Behavioral baseline checks
    log_redaction=True,               # Strip secrets from logs
    cors_origins=["http://localhost:3000"],
)

guard = AgentGuard(config=config)`}]},{title:"Delegation & Authority",body:"Control authority propagation between agents. AgentGuard tracks the full delegation lineage and enforces scope containment.",code:[{lang:"python",label:"delegation.py",snippet:`# Create a delegation token
token = guard.create_delegation(
    from_agent="orchestrator",
    to_agent="sub_agent",
    scope=["read_db", "query_customers"],   # Scope cannot exceed parent
    max_depth=2,                             # Further sub-delegation limit
    ttl_seconds=300,                         # Auto-expire after 5 minutes
)

# Verify a delegation chain
result = guard.verify_delegation(token, required_scope="read_db")
# result.valid, result.chain, result.violations`}]},{title:"Context Provenance",body:"Tag every piece of context with a trust level and track taint propagation through the agent execution graph.",code:[{lang:"python",label:"context.py",snippet:`from agentguard.context import ContextEntry, TrustLevel

# Attach provenance to a context entry
entry = ContextEntry(
    content=user_input,
    source="user_prompt",
    trust_level=TrustLevel.UNTRUSTED,     # Mark as external input
    tainted=True,                          # Propagate taint downstream
)

# Check if context is safe to act on
safe = guard.is_safe_context(entry, required_trust=TrustLevel.VERIFIED)`}]},{title:"Threat Modeling",body:"Build a structured threat model against your agent system. Identify critical assets, trust boundaries, and attack paths.",code:[{lang:"python",label:"threat_model.py",snippet:`from agentguard.threatmodel import ThreatModelAnalyzer

analyzer = ThreatModelAnalyzer(guard)

# Define an asset
analyzer.add_asset("customer_db", sensitivity="CRITICAL")

# Define a trust boundary
analyzer.add_boundary("external_user → orchestrator")

# Run automated threat analysis
report = analyzer.analyze()
print(report.critical_threats)   # List[Threat]
print(report.risk_score)          # 0.0–100.0`}]}]},{id:"api",label:"REST API",content:[]},{id:"cli",label:"CLI Reference",content:[{title:"CLI Entry Point",body:"The `agentguard` CLI provides access to offensive validation, threat modeling, and server management.",code:[{lang:"bash",label:"commands",snippet:`agentguard --help

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
agentguard doctor             # Verify SDK and server health`}]},{title:"Threat Model Commands",body:"Build and analyze threat models from the command line.",code:[{lang:"bash",label:"threat commands",snippet:`# Build a threat model interactively
agentguard threat model --output threat_model.json

# List all identified threats
agentguard threat list --severity critical

# Inspect a specific threat
agentguard threat inspect threat_001

# Export as STRIDE matrix
agentguard threat export --format stride --output stride.csv`}]},{title:"Offensive Validation Commands",body:"Run adversarial attacks against your own security boundary in a local sandbox.",code:[{lang:"bash",label:"attack commands",snippet:`# Run a full attack campaign
agentguard attack run --strategy all --target http://localhost:8000

# Run a specific attack type
agentguard attack run --strategy prompt_injection

# List campaigns and their bypass rates
agentguard attack list --format table

# View a campaign result
agentguard attack inspect campaign_001`}]}]},{id:"concepts",label:"Concepts",content:[{title:"Deterministic Policy Engine",body:`The core invariant of AgentGuard: no AI model can override policy decisions. AI advisory systems (AI Secura, APIRIS) produce risk signals only. The deterministic policy engine has final authority.

Every decision is reproducible given the same inputs. The engine applies mathematical invariants, not probabilistic heuristics. A BLOCK verdict produced today will produce the same result when replayed against the same evidence record tomorrow.`,code:[]},{title:"4-Point Execution Truth",body:`AgentGuard tracks the difference between what an agent intended, what it requested, what was allowed, and what actually executed. Divergence between these four states is a forensic finding.

• INTENDED — What the agent's prompt implied it would do
• REQUESTED — What the agent actually requested (tool call, API payload)
• ALLOWED — What the policy engine permitted
• EXECUTED — What the downstream system confirmed ran`,code:[]},{title:"Taint Propagation",body:`Context entering the system from untrusted sources (user prompts, external APIs, web search results) is tagged as TAINTED. Taint propagates through the agent execution graph. Any action derived from tainted context is subject to higher scrutiny.

AgentGuard never implicitly trusts context because it came from the model — only verified, scoped, and provenance-tracked context receives elevated trust.`,code:[]},{title:"Fail-Safe Design",body:`AgentGuard is designed to fail safely. If the policy engine encounters an error, the configured fail-safe mode determines the default decision:

• BLOCK (default) — Safest. Rejects the action on engine error.
• MONITOR — Allows the action but logs an anomaly.
• PASS — Allows the action. Not recommended for production.`,code:[{lang:"python",label:"fail_safe.py",snippet:`config = AgentGuardConfig(
    fail_safe_mode="BLOCK",   # On engine error, default to BLOCK
)`}]}]}],m=[{method:"GET",path:"/api/v1/agents",category:"Agents",desc:"List all registered agents with identity, trust level, and capability set.",params:[{name:"limit",type:"int",desc:"Max results (default 50)"},{name:"offset",type:"int",desc:"Pagination offset"}],response:'{"agents":[{"agent_id":"orchestrator_v2","trust_level":"HIGH","capabilities":["read_db","delegate"],"status":"ACTIVE"}],"total":5}'},{method:"GET",path:"/api/v1/agents/{agent_id}",category:"Agents",desc:"Get agent profile, current capabilities, delegation chain, and trust score.",params:[{name:"agent_id",type:"string",desc:"Agent identifier (path)"}],response:'{"agent_id":"orchestrator_v2","trust_level":"HIGH","delegation_depth":1,"taint_flags":[],"capabilities":["read_db","delegate"]}'},{method:"GET",path:"/api/v1/events",category:"Events",desc:"Stream security decision events with filtering by decision, agent, and time range.",params:[{name:"decision",type:"string",desc:"Filter by ALLOW|BLOCK|HITL|MONITOR"},{name:"agent_id",type:"string",desc:"Filter by agent"},{name:"since",type:"ISO8601",desc:"Start timestamp"}],response:'{"events":[{"event_id":"evt_001","decision":"BLOCK","tool":"upload_s3","agent_id":"rogue_agent","timestamp":"2026-09-19T10:30:00Z"}],"total":47}'},{method:"POST",path:"/api/v1/policy/evaluate",category:"Policy",desc:"Evaluate a proposed action against the deterministic policy engine without executing.",params:[{name:"agent_id",type:"string",desc:"Acting agent"},{name:"action",type:"Action",desc:"Proposed action object"},{name:"context",type:"Context",desc:"Attached context object"}],response:'{"decision":"BLOCK","reason":"Scope violation: upload_s3 not in agent capability set","risk_score":0.94,"invariants_checked":7}'},{method:"GET",path:"/api/v1/forensics/{event_id}",category:"Forensics",desc:"Full forensic evidence record and causal explanation for a specific event.",params:[{name:"event_id",type:"string",desc:"Event ID (path)"}],response:'{"event_id":"evt_001","causal_chain":["user_prompt→tainted_context→tool_call"],"execution_truth":{"intended":"summarize","requested":"upload_s3","allowed":"NONE","executed":"NONE"},"blast_radius":["customer_db","s3_bucket"]}'},{method:"GET",path:"/api/v1/traces/{trace_id}",category:"Traces",desc:"Causal execution trace with span-level decision evidence and latency breakdown.",params:[{name:"trace_id",type:"string",desc:"Trace ID (path)"}],response:'{"trace_id":"trc_001","spans":[{"span_id":"sp_001","operation":"tool_call","decision":"BLOCK","latency_ms":1.4}]}'},{method:"GET",path:"/api/v1/campaigns",category:"Offensive",desc:"List all offensive validation campaigns with empirical bypass prevention metrics.",params:[{name:"status",type:"string",desc:"Filter by RUNNING|COMPLETE|FAILED"}],response:'{"campaigns":[{"id":"cmp_001","strategy":"prompt_injection","variants_tested":47,"bypasses_found":0,"prevention_rate":1.0}]}'},{method:"POST",path:"/api/v1/attack/run",category:"Offensive",desc:"Trigger a new adaptive attack campaign against a local sandbox target only.",params:[{name:"strategy",type:"string",desc:"Attack strategy type"},{name:"target",type:"url",desc:"Local target URL (localhost only)"}],response:'{"campaign_id":"cmp_002","status":"RUNNING","estimated_duration_s":120}'},{method:"GET",path:"/api/v1/posture",category:"Posture",desc:"6-dimension security posture scorecard JSON for external monitoring integrations.",params:[],response:'{"score":98,"grade":"A+","dimensions":{"identity":100,"context":98,"policy":100,"forensics":95,"validation":96,"drift":99}}'},{method:"GET",path:"/api/v1/incidents",category:"Incidents",desc:"List all security incidents with lifecycle state, severity, and containment status.",params:[{name:"state",type:"string",desc:"Filter by OPEN|CONTAINED|RESOLVED"},{name:"severity",type:"string",desc:"CRITICAL|HIGH|MEDIUM|LOW"}],response:'{"incidents":[{"id":"inc_001","severity":"HIGH","state":"CONTAINED","agent_id":"rogue_agent","actions_taken":["QUARANTINE","REVOKE"]}]}'},{method:"GET",path:"/api/v1/posture/drift",category:"Posture",desc:"Behavioral drift anomaly detection results versus verified baseline profiles.",params:[{name:"agent_id",type:"string",desc:"Specific agent (optional)"}],response:'{"agent_id":"orchestrator_v2","drift_score":0.03,"status":"NOMINAL","anomalies":[]}'}],g={GET:"bg-emerald-50 text-emerald-700 border-emerald-200",POST:"bg-blue-50 text-blue-700 border-blue-200",PUT:"bg-amber-50 text-amber-700 border-amber-200",DELETE:"bg-red-50 text-red-700 border-red-200"};e.s(["default",0,function(){let[e,h]=(0,a.useState)("quickstart"),[x,u]=(0,a.useState)(m[0]),[b,y]=(0,a.useState)(null),[f,v]=(0,a.useState)(""),[N,j]=(0,a.useState)("All"),[_,C]=(0,a.useState)("Deterministic Policy Engine"),w=(e,t)=>{navigator.clipboard.writeText(e),y(t),setTimeout(()=>y(null),2e3)},T=(0,a.useMemo)(()=>m.filter(e=>("All"===N||e.category===N)&&(e.path.toLowerCase().includes(f.toLowerCase())||e.desc.toLowerCase().includes(f.toLowerCase()))),[f,N]),A=["All",...Array.from(new Set(m.map(e=>e.category)))],k=p.find(t=>t.id===e);return(0,t.jsxs)("div",{className:"min-h-screen bg-slate-50",style:{fontFamily:"Inter, system-ui, sans-serif"},children:[(0,t.jsx)(c.PageHeader,{title:"Documentation",subtitle:"SDK reference, REST API specification, CLI guide, and architectural concepts for AgentGuard.",badge:"v1.0.0",actions:(0,t.jsxs)("div",{className:"flex items-center gap-2 text-xs font-mono text-slate-500 bg-white border border-slate-200 px-3 py-1.5 rounded",children:[(0,t.jsx)(r.Globe,{size:12}),(0,t.jsx)("span",{children:"Base URL: http://127.0.0.1:8000"})]})}),(0,t.jsx)("div",{className:"max-w-screen-xl mx-auto px-6 py-8",children:(0,t.jsxs)("div",{className:"grid grid-cols-1 lg:grid-cols-[220px_1fr] gap-8",children:[(0,t.jsxs)("aside",{className:"space-y-1",children:[p.map(a=>(0,t.jsx)("button",{onClick:()=>h(a.id),className:`w-full text-left px-3 py-2 rounded text-[13px] font-medium transition-colors ${e===a.id?"bg-blue-600 text-white":"text-slate-700 hover:bg-slate-200 hover:text-slate-900"}`,children:a.label},a.id)),(0,t.jsxs)("div",{className:"mt-6 p-3 bg-white border border-slate-200 rounded-lg",children:[(0,t.jsx)("p",{className:"text-[10px] font-bold uppercase tracking-widest text-slate-500 mb-2",children:"Install Extras"}),[{extra:"[cli]",hint:"CLI tools (Rich/Typer)"},{extra:"[server]",hint:"FastAPI + Uvicorn"},{extra:"[openai]",hint:"OpenAI provider"},{extra:"[gemini]",hint:"Gemini provider"},{extra:"[anthropic]",hint:"Claude provider"},{extra:"[all]",hint:"Everything"}].map(e=>(0,t.jsxs)("div",{className:"flex items-center justify-between py-1",children:[(0,t.jsx)("code",{className:"text-[10px] font-mono font-semibold text-blue-700",children:e.extra}),(0,t.jsx)("span",{className:"text-[10px] text-slate-400",children:e.hint})]},e.extra))]})]}),(0,t.jsxs)("main",{className:"space-y-8 min-w-0",children:["api"!==e&&"concepts"!==e&&k&&(0,t.jsx)("div",{className:"space-y-8",children:k.content.map(e=>(0,t.jsxs)("div",{className:"bg-white border border-slate-200 rounded-lg overflow-hidden",children:[(0,t.jsx)("div",{className:"px-6 py-4 border-b border-slate-100",children:(0,t.jsx)("h3",{className:"text-base font-bold text-slate-900",children:e.title})}),(0,t.jsx)("div",{className:"px-6 pt-4 pb-2",children:(0,t.jsx)("p",{className:"text-sm text-slate-600 leading-relaxed whitespace-pre-line",children:e.body})}),e.code.map((a,r)=>(0,t.jsxs)("div",{className:"mx-6 mb-4 rounded-lg border border-slate-800 bg-slate-950 overflow-hidden",children:[(0,t.jsxs)("div",{className:"flex items-center justify-between px-4 py-2 border-b border-slate-800",children:[(0,t.jsx)("span",{className:"text-[11px] font-mono text-slate-400",children:a.label}),(0,t.jsx)("button",{onClick:()=>w(a.snippet,`${e.title}-${r}`),className:"flex items-center gap-1 text-[11px] font-mono text-slate-500 hover:text-white transition-colors",children:b===`${e.title}-${r}`?(0,t.jsxs)(t.Fragment,{children:[(0,t.jsx)(n.CheckCircle2,{size:11,className:"text-emerald-400"})," Copied"]}):(0,t.jsxs)(t.Fragment,{children:[(0,t.jsx)(s.Copy,{size:11})," Copy"]})})]}),(0,t.jsx)("pre",{className:"px-4 py-3 text-xs font-mono text-slate-200 leading-relaxed overflow-x-auto",children:a.snippet})]},r))]},e.title))}),"concepts"===e&&k&&(0,t.jsx)("div",{className:"space-y-4",children:k.content.map(e=>(0,t.jsxs)("div",{className:"bg-white border border-slate-200 rounded-lg overflow-hidden",children:[(0,t.jsxs)("button",{onClick:()=>C(_===e.title?null:e.title),className:"w-full flex items-center justify-between px-6 py-4 text-left hover:bg-slate-50 transition-colors",children:[(0,t.jsx)("h3",{className:"text-sm font-bold text-slate-900",children:e.title}),_===e.title?(0,t.jsx)(o.ChevronDown,{size:15,className:"text-slate-500"}):(0,t.jsx)(i.ChevronRight,{size:15,className:"text-slate-500"})]}),_===e.title&&(0,t.jsxs)("div",{className:"px-6 pb-5 border-t border-slate-100 pt-4 space-y-4",children:[(0,t.jsx)("p",{className:"text-sm text-slate-600 leading-relaxed whitespace-pre-line",children:e.body}),e.code.map((e,a)=>(0,t.jsxs)("div",{className:"rounded-lg border border-slate-800 bg-slate-950 overflow-hidden",children:[(0,t.jsxs)("div",{className:"flex items-center justify-between px-4 py-2 border-b border-slate-800",children:[(0,t.jsx)("span",{className:"text-[11px] font-mono text-slate-400",children:e.label}),(0,t.jsx)("button",{onClick:()=>w(e.snippet,`concept-${a}`),className:"flex items-center gap-1 text-[11px] font-mono text-slate-500 hover:text-white transition-colors",children:b===`concept-${a}`?(0,t.jsxs)(t.Fragment,{children:[(0,t.jsx)(n.CheckCircle2,{size:11,className:"text-emerald-400"}),"Copied"]}):(0,t.jsxs)(t.Fragment,{children:[(0,t.jsx)(s.Copy,{size:11}),"Copy"]})})]}),(0,t.jsx)("pre",{className:"px-4 py-3 text-xs font-mono text-slate-200 leading-relaxed overflow-x-auto",children:e.snippet})]},a))]})]},e.title))}),"api"===e&&(0,t.jsxs)("div",{className:"grid grid-cols-1 xl:grid-cols-[1fr_440px] gap-6",children:[(0,t.jsxs)("div",{className:"bg-white border border-slate-200 rounded-lg overflow-hidden",children:[(0,t.jsxs)("div",{className:"px-4 py-3 border-b border-slate-200 space-y-3",children:[(0,t.jsxs)("div",{className:"flex items-center gap-2 px-3 py-2 rounded border border-slate-200 bg-slate-50",children:[(0,t.jsx)(l.Search,{size:12,className:"text-slate-400 shrink-0"}),(0,t.jsx)("input",{value:f,onChange:e=>v(e.target.value),placeholder:"Search endpoints…",className:"flex-1 text-[13px] bg-transparent outline-none text-slate-700 placeholder:text-slate-400"}),f&&(0,t.jsx)("button",{onClick:()=>v(""),children:(0,t.jsx)(d.X,{size:12,className:"text-slate-400"})})]}),(0,t.jsx)("div",{className:"flex flex-wrap gap-1.5",children:A.map(e=>(0,t.jsx)("button",{onClick:()=>j(e),className:`text-[11px] font-medium px-2.5 py-1 rounded border transition-colors ${N===e?"bg-blue-600 text-white border-blue-600":"bg-white text-slate-600 border-slate-200 hover:border-slate-300"}`,children:e},e))})]}),(0,t.jsxs)("div",{className:"divide-y divide-slate-100 max-h-[600px] overflow-y-auto",children:[0===T.length&&(0,t.jsx)("div",{className:"px-4 py-8 text-center text-sm text-slate-400",children:"No endpoints match your search."}),T.map(e=>(0,t.jsxs)("button",{onClick:()=>u(e),className:`w-full text-left px-4 py-3 transition-colors ${x.path===e.path?"bg-blue-50 border-l-2 border-blue-600":"hover:bg-slate-50 border-l-2 border-transparent"}`,children:[(0,t.jsxs)("div",{className:"flex items-center gap-2 mb-1",children:[(0,t.jsx)("span",{className:`text-[10px] font-mono font-bold px-1.5 py-0.5 rounded border ${g[e.method]}`,children:e.method}),(0,t.jsx)("code",{className:"text-[12px] font-mono font-semibold text-slate-800 truncate",children:e.path})]}),(0,t.jsx)("p",{className:"text-[11px] text-slate-500 leading-snug",children:e.desc})]},e.path))]})]}),(0,t.jsxs)("div",{className:"bg-white border border-slate-200 rounded-lg overflow-hidden flex flex-col",children:[(0,t.jsxs)("div",{className:"px-5 py-4 border-b border-slate-200",children:[(0,t.jsxs)("div",{className:"flex items-center gap-2 mb-1",children:[(0,t.jsx)("span",{className:`text-[10px] font-mono font-bold px-1.5 py-0.5 rounded border ${g[x.method]}`,children:x.method}),(0,t.jsx)("code",{className:"text-sm font-mono font-bold text-slate-900",children:x.path})]}),(0,t.jsx)("p",{className:"text-[13px] text-slate-600 mt-1",children:x.desc})]}),x.params.length>0&&(0,t.jsxs)("div",{className:"px-5 py-4 border-b border-slate-200",children:[(0,t.jsx)("p",{className:"text-[10px] font-bold uppercase tracking-widest text-slate-500 mb-3",children:"Parameters"}),(0,t.jsx)("div",{className:"space-y-2",children:x.params.map(e=>(0,t.jsxs)("div",{className:"flex items-start gap-3",children:[(0,t.jsx)("code",{className:"text-[11px] font-mono font-semibold text-slate-800 bg-slate-100 border border-slate-200 px-1.5 py-0.5 rounded shrink-0",children:e.name}),(0,t.jsx)("span",{className:"text-[11px] font-mono text-blue-600 shrink-0",children:e.type}),(0,t.jsx)("span",{className:"text-[11px] text-slate-500",children:e.desc})]},e.name))})]}),(0,t.jsxs)("div",{className:"flex-1 flex flex-col",children:[(0,t.jsxs)("div",{className:"flex items-center justify-between px-5 py-3 border-b border-slate-100",children:[(0,t.jsx)("p",{className:"text-[10px] font-bold uppercase tracking-widest text-slate-500",children:"Example Response"}),(0,t.jsx)("button",{onClick:()=>w(x.response,"response"),className:"flex items-center gap-1 text-[11px] font-mono text-slate-500 hover:text-slate-800 transition-colors",children:"response"===b?(0,t.jsxs)(t.Fragment,{children:[(0,t.jsx)(n.CheckCircle2,{size:11,className:"text-emerald-500"}),"Copied"]}):(0,t.jsxs)(t.Fragment,{children:[(0,t.jsx)(s.Copy,{size:11}),"Copy JSON"]})})]}),(0,t.jsx)("div",{className:"flex-1 bg-slate-950 p-4 font-mono overflow-auto",children:(0,t.jsx)("pre",{className:"text-[11px] text-slate-200 leading-relaxed",children:JSON.stringify(JSON.parse(x.response),null,2)})})]})]})]})]})]})})]})}])},37757,e=>{"use strict";var t=e.i(43476),a=e.i(71645),s=e.i(22016),n=e.i(67927);e.s(["PageHeader",0,function({title:e,description:r,subtitle:i,breadcrumbs:o,actions:l,badge:d}){let c=r||i;return(0,t.jsxs)("div",{className:"mb-6 pb-4 border-b border-slate-200",children:[o&&o.length>0&&(0,t.jsx)("nav",{className:"flex items-center gap-1.5 text-xs text-slate-500 mb-2",children:o.map((e,r)=>{let i=r===o.length-1;return(0,t.jsxs)(a.default.Fragment,{children:[r>0&&(0,t.jsx)(n.ChevronRight,{size:12,className:"text-slate-400"}),e.href&&!i?(0,t.jsx)(s.default,{href:e.href,className:"hover:text-slate-800 transition-colors",children:e.label}):(0,t.jsx)("span",{className:i?"text-slate-900 font-medium":"",children:e.label})]},r)})}),(0,t.jsxs)("div",{className:"flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3",children:[(0,t.jsxs)("div",{children:[(0,t.jsxs)("div",{className:"flex items-center gap-2.5",children:[(0,t.jsx)("h1",{className:"text-xl font-semibold text-slate-900 tracking-tight",children:e}),d&&(0,t.jsx)("div",{children:d})]}),c&&(0,t.jsx)("p",{className:"mt-1 text-xs text-slate-500 max-w-3xl leading-relaxed",children:c})]}),l&&(0,t.jsx)("div",{className:"flex items-center gap-2 flex-shrink-0",children:l})]})]})}])}]);