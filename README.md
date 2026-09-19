# AgentGuard

**Causal Security & Deterministic Policy Enforcement SDK for Multi-Agent AI Systems**

---

## 1. What is AgentGuard?

**AgentGuard** is an enterprise-grade causal security and enforcement platform for autonomous AI agent networks. 

When multi-agent systems coordinate to solve complex workflows, agents delegate authority to other agents, ingest external MCP/web context, invoke third-party tools, and access sensitive enterprise resources. AgentGuard establishes the causal security layer that tracks data provenance, bounds delegated authority, isolates untrusted context taint, and deterministically enforces security policies.

---

## 2. Why AgentGuard Exists

Traditional AI security tools focus on single-prompt chatbot filtering or passive observability dashboards. In autonomous multi-agent environments, these tools fail because they cannot answer causal questions:

```
Who initiated the action?
  └─ Which agent performed it?
      └─ Who delegated the authority?
          └─ What context influenced the action?
              └─ Did untrusted context propagate across agents?
                  └─ Was the final action within original user intent?
                      └─ Why was the tool execution allowed or blocked?
```

AgentGuard provides deterministic enforcement and full causal chain reconstruction from user prompt to database query.

---

## 3. Core Architectural Principle

```
+-------------------------------------------------------------------------+
|                              AI REASONS.                                |
|                   DETERMINISTIC SECURITY POLICY ENFORCES.               |
+-------------------------------------------------------------------------+
```

- **AI Secura** (Cybersecurity LLM): Analyzes structured security context, detects intent drift, indirect prompt injections, and attack indicators. **Never directly executes enforcement actions.**
- **APIRIS** (API Decision Intelligence): Evaluates endpoint risk, CVE intelligence, vendor reputation, and anomalies.
- **AgentGuard Deterministic Policy Engine**: Enforces strict policy decisions (`ALLOW`, `MONITOR`, `HUMAN_APPROVAL`, `QUARANTINE`, `BLOCK`, `REVOKE`).

---

## 4. Architecture Overview

```
                          +-------------------------+
                          |   User / Application    |
                          +------------+------------+
                                       |
                                       v
                          +-------------------------+
                          |      Planner Agent      |
                          +------------+------------+
                                       |  (Delegates authority)
                                       v
                          +-------------------------+
+------------------+      |    Researcher Agent     |
|   External MCP   | ---> +------------+------------+
|   (Untrusted)    |                   |  (Propagates context)
+------------------+                   v
                          +-------------------------+
                          |     DataExtraction      |
                          +------------+------------+
                                       |
                                       v
                          +-------------------------+
                          |     Protected Tool      |
                          +------------+------------+
                                       |
                   +-------------------+-------------------+
                   |                                       |
                   v                                       v
     +---------------------------+           +---------------------------+
     |   AI Secura (Reasoning)   |           |   APIRIS (API Intel)      |
     +-------------+-------------+           +-------------+-------------+
                   |                                       |
                   +-------------------+-------------------+
                                       | Signals
                                       v
                          +-------------------------+
                          |  Deterministic Policy   |
                          |        Evaluator        |
                          +------------+------------+
                                       |
                                       v
                          [ALLOW / BLOCK / QUARANTINE]
```

---

## 5. Installation

AgentGuard runs completely locally with **zero external cloud dependencies** required for Phase 1.

```bash
# Clone the repository
git clone https://github.com/agentguard/agentguard.git
cd agentguard

# Install SDK in editable mode
pip install -e ./sdk
```

Requirements: Python 3.11+ and Pydantic v2.

---

## 6. Quick Start

```python
from agentguard import AgentGuard, AgentTrustLevel, ContextSource, TaintState, SensitivityLevel

# 1. Initialize AgentGuard client
guard = AgentGuard()

# 2. Register Agents
planner = guard.agent(
    name="planner",
    capabilities=["plan", "web_search", "db_read"],
    trust_level=AgentTrustLevel.HIGH
)
researcher = guard.agent(
    name="researcher",
    capabilities=["web_search", "db_read"],
    trust_level=AgentTrustLevel.MEDIUM
)

# 3. Define a Protected Tool
@guard.protected_tool(
    name="query_db",
    required_capabilities=["db_read"],
    sensitivity=SensitivityLevel.HIGH
)
def query_db(query: str, api_token: str = "sk-secret-key-12345"):
    # Sensitive tokens are automatically redacted from logs/traces
    return {"results": ["record_1", "record_2"]}

# 4. Execute Scoped Task with Delegation and Provenance
with guard.task(intent="Analyze quarterly metrics", initiating_user="alice@company.com") as task:
    with planner.delegate(researcher, capabilities=["web_search", "db_read"]):
        # Ingest context
        ctx = guard.context(data="Query params", source=ContextSource.USER)
        
        # Execute tool
        data = query_db(query="SELECT * FROM metrics")

# 5. Render Causal Tree
guard.print_causal_tree(task.trace_id)
```

---

## 7. Key Features

### 7.1. Agent Registration & Identity
Agents are registered with declared capabilities and trust levels (`HIGH`, `MEDIUM`, `LOW`, `UNTRUSTED`).
```python
agent = guard.agent(
    name="financial_analyst",
    framework="crewai",
    version="1.0.0",
    capabilities=["extract_records", "summarize"],
    trust_level=AgentTrustLevel.MEDIUM
)
```

### 7.2. Task Tracing & Correlation
Tasks establish root trace IDs and correlation coordinates (`trace_id`, `span_id`, `task_id`, `agent_id`, `delegation_id`) with async-safe context variable propagation.
```python
with guard.task(intent="Perform security audit", initiating_user="ciso@enterprise.com"):
    ...
```

### 7.3. Recursive Delegation & Monotonic Authority
Supports recursive delegation (`User -> Planner -> Researcher -> Analyst -> DataAgent`). Monotonic authority reduction strictly forbids agents from delegating capabilities they do not possess.
```python
with planner.delegate(researcher, capabilities=["public_search"]):
    with researcher.delegate(data_agent, capabilities=["public_search"]):
        ...
```

### 7.4. Context Provenance & Taint Tracking
Context artifacts track their full lineage across multi-agent hops. Untrusted inputs carry `TaintState.UNTRUSTED` or `TAINTED` and cannot flow into sensitive sinks without explicit sanitization.
```python
ctx = guard.context(
    data="Untrusted web data",
    source=ContextSource.EXTERNAL_MCP,
    taint_state=TaintState.UNTRUSTED
)
# Propagate to downstream agent
child_ctx = ctx.propagate(to_agent_id=data_agent.agent_id, action="sanitized_filter", guard=guard)
```

### 7.5. Deterministic Policy Enforcement
The policy engine verifies capabilities, delegation grants, taint states, and APIRIS/AI Secura signals before rendering a decision:
- `ALLOW`: Permitted to execute.
- `MONITOR`: Permitted under continuous audit telemetry.
- `HUMAN_APPROVAL`: Pauses for explicit confirmation.
- `BLOCK`: Access denied; raises `PermissionError`.
- `QUARANTINE`: Context or agent isolated.
- `REVOKE`: Delegation grant immediately cancelled.

---

## 8. AI Secura & APIRIS Integrations (Dependency Inversion)

AgentGuard provides clean protocol interfaces so that internal intelligence engines can be plugged in seamlessly:

### AI Secura Interface
```python
class SecurityReasoner(Protocol):
    def analyze(self, context: SecurityContext) -> SecurityAnalysis: ...
```

### APIRIS Interface
```python
class APIIntelligence(Protocol):
    def analyze(self, request: ToolRequest) -> APIAnalysis: ...
```

Both interfaces include local fallback adapters (`LocalAISecuraAdapter` and `LocalAPIRISAdapter`) for Phase 1 local execution and unit testing.

---

## 9. Running Tests and Examples

```bash
# Run complete test suite (25+ tests)
pytest sdk/tests -v

# Run the end-to-end multi-agent causal trace example
python examples/basic/e2e_causal_trace.py
```

---

## 10. MVP Roadmap

- [x] **Phase 1: Foundation SDK** — Domain models, async correlation, event system, recursive delegation, taint propagation, protected tool interceptor, deterministic policy evaluator, causal graph reconstructor.
- [ ] **Phase 2: FastAPI Gateway & Sidecar** — HTTP interceptor middleware, MCP proxy layer, token bucket rate limiter.
- [ ] **Phase 3: Persistent Storage & SQLite/Postgres Sink** — Persistent event store, vector indexing for causal queries.
- [ ] **Phase 4: Advanced Taint Flow Analysis** — Field-level taint tracking, dynamic AST sanitizer.
- [ ] **Phase 5: AI Secura Production Adapter** — Live inference integration for cybersecurity reasoning.
- [ ] **Phase 6: APIRIS Live Connector** — Real-time API reputation and vulnerability telemetry feeds.
- [ ] **Phase 7: Enterprise Security Dashboard** — Visual causal DAG explorer, incident management, real-time kill switch.
