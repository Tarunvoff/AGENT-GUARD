# AgentGuard Platform Architecture Audit

**Version:** 0.9.0  
**Date:** September 2026  
**Status:** Baseline Comprehensive Audit  

---

## 1. Executive Summary

This document performs an exhaustive audit of the existing **AgentGuard** codebase across Phase 1 through Phase 9. It documents the architecture, package structure, APIs, CLI, dashboard, AI integrations, security enforcement engines, testing footprint, and identified extension points required to evolve AgentGuard into a production-ready, SDK-first, and CLI-first security control plane.

### Core Principle
$$\text{LLM REASONS} \quad\longrightarrow\quad \text{DETERMINISTIC POLICY ENFORCES}$$

AgentGuard maintains a strict separation of concerns: AI intelligence and reasoning (e.g. AI Secura, APIRIS, LLM providers) are strictly **advisory**. The deterministic policy evaluation layer is **authoritative and fail-safe**.

---

## 2. Package & Repository Structure

The repository is organized as follows:

```
AGENT-GUARD/
├── assets/                     # Branding, diagrams, visual assets
├── dashboard/                  # Next.js 16.3.5 / React 19 web control plane
│   ├── src/
│   │   ├── app/                # App router pages (20+ security views)
│   │   └── components/         # Control plane UI components
│   └── package.json
├── docs/                       # Architectural documentation & specifications
│   └── architecture/
├── examples/                   # Multi-agent reference architectures & scenarios
├── models/                     # Custom modelfiles and prompt artifacts
├── reports/                    # Generated posture, incident, and compliance reports
├── run_live.py                 # Live event demo runner
├── sdk/                        # AgentGuard Python SDK (v0.9.0)
│   ├── pyproject.toml          # Package metadata, entrypoints (agentguard, ag)
│   ├── agentguard/             # Core library package
│   │   ├── __init__.py         # Public exports
│   │   ├── __main__.py         # CLI entrypoint (Typer + Rich)
│   │   ├── client.py           # AgentGuard client & runtime coordinator
│   │   ├── config.py           # Configuration schema (AgentGuardConfig)
│   │   ├── llm_config.py       # Provider configuration
│   │   ├── serve.py            # Unified backend + dashboard launcher
│   │   ├── watch.py            # Live telemetry stream
│   │   ├── agents/             # Agent runtime (Agent, AgentIdentity, AgentCapability)
│   │   ├── api/                # FastAPI application & REST models
│   │   ├── approval/           # HITL approval flows
│   │   ├── context/            # Context, Provenance, TaintState tracking
│   │   ├── decisions/          # SecurityDecision and DecisionAction models
│   │   ├── delegation/         # DelegationScope and AuthorityGrant
│   │   ├── drift/              # BehavioralBaselineTracker & Drift detectors
│   │   ├── evaluation/         # Intent & policy evaluation
│   │   ├── forensics/          # ForensicService, QueryEngine, AccessDiff
│   │   ├── gates/              # CI/CD SecurityGateEvaluator
│   │   ├── gateway/            # MCPGateway and HTTPGateway interceptors
│   │   ├── incidents/          # IncidentEngine & StateMachine
│   │   ├── integrations/       # AI Secura, APIRIS, and Ollama adapter
│   │   ├── offensive/          # OffensiveEngine, AdaptiveEngine, MutationEngine
│   │   ├── persistence/        # SQLiteStorage, PostgresStorage, SIEMExporter
│   │   ├── policy/             # PolicyEvaluator, IntentAnalyzer
│   │   ├── posture/            # PostureEngine, PostureDiffEngine
│   │   ├── providers/          # Pluggable SecurityAIProvider registry
│   │   ├── response/           # Automated response & quarantine engine
│   │   ├── risk/               # Risk assessment & scoring
│   │   ├── tasks/              # TaskContext & intent tracking
│   │   ├── tools/              # ToolDefinition, protected_tool decorator
│   │   └── tracing/            # CausalGraph, TraceManager, correlation
│   └── tests/                  # 219+ unit and integration test suite
└── start_all.bat               # Windows quick-launch script
```

---

## 3. Existing Security Architecture & Subsystems

### 3.1 SDK Facade (`agentguard/client.py`)
- Central client `AgentGuard` coordinating:
  - Context & Taint Propagation (`guard.context(...)`, `guard.sanitize_context(...)`)
  - Identity & Delegation (`guard.agent(...)`, `agent.delegate(...)`)
  - Tool Protection (`@guard.protected_tool(...)`, `guard.evaluate_tool_invocation(...)`)
  - Tracing & Causal DAG (`guard.tracer`, `guard.reconstruct_trace(...)`)
  - Subsystem engines: Posture, Incidents, Response, Drift, Gates.

### 3.2 Pluggable AI Providers (`agentguard/providers/`)
- Abstract base class: `SecurityAIProvider`
- Concrete providers:
  - `AISecuraProvider` / `LocalAISecuraAdapter`
  - `OllamaProvider` (local LLM inference with fast health check)
  - `OpenAIProvider`
  - `GeminiProvider`
  - `AnthropicProvider`
  - `NullSecurityAIProvider` (deterministic-only baseline)
- Provider Registry: `ProviderRegistry` with automatic failover chain and health checking.
- **Invariance:** Deterministic security rules never fail-open if an AI provider is unreachable.

### 3.3 APIRIS Intelligence (`agentguard/integrations/apiris.py`)
- Tracks tool/API metadata, sensitive resource mappings, behavioral latency/cost profiles, and external vulnerability intelligence.

### 3.4 Offensive Validation Engine (`agentguard/offensive/`)
- `OffensiveEngine`: Corpus of MITRE ATLAS attack vectors (prompt injections, unauthorized delegations, indirect context poisoning).
- `AdaptiveEngine`: Mutation strategies, multi-turn attack escalation, and automated regression generation.
- Execution counters track `intended`, `requested`, `allowed`, `attempted`, `executed`.

### 3.5 Forensics & Execution Truth (`agentguard/forensics/`)
- `ForensicService` & `ForensicQueryEngine`:
  - Access profile generation for agents and resources.
  - Snapshot diffing (`AccessDiff`) for drift and anomaly discovery.
  - Causal forensic explanation (`why was this action blocked?`).
  - Strict tracking of **Execution Truth**:
    - INTENDED
    - REQUESTED
    - ALLOWED
    - ATTEMPTED
    - EXECUTED

### 3.6 Continuous Security Control Plane (`posture`, `incidents`, `drift`, `gates`)
- `PostureEngine`: Continuous posture score (0-100) and grade (A/B/C/F), dimension-level breakdowns.
- `IncidentEngine`: Lifecycle state machine (`OPEN` -> `INVESTIGATING` -> `CONTAINED` -> `RESOLVED` -> `CLOSED`).
- `BehavioralBaselineTracker`: Real-time anomaly detection in tool usage, context trust, and authority hops.
- `SecurityGateEvaluator`: CI/CD gate with deterministic threshold validation (`pass`/`fail`).

---

## 4. Existing CLI & UX Audit

### 4.1 CLI Implementation (`agentguard/__main__.py`)
- Built using **Typer** and **Rich**.
- Commands currently implemented:
  - `status`: Displays high-level security status.
  - `posture`: Displays posture scorecard.
  - `incidents`: Lists and inspects incidents.
  - `drift`: Displays behavioral drift events.
  - `gate`: Evaluates CI/CD quality gate.
  - `watch`: Live event stream (`agentguard/watch.py`).
  - `serve`: Launches backend + dashboard (`agentguard/serve.py`).
  - `ai`: Manages AI providers (`ai status`, `ai benchmark`).
  - `attack`: Lists and executes offensive validation attacks.

### 4.2 Required Extensions for Full Vision
- Branded interactive REPL console (`ag >` shell mode on running `agentguard` with no arguments).
- Dark terminal visual identity (electric purple, violet, magenta, near-black, standard semantic colors).
- Rich interactive sub-commands (`agent inspect`, `agent graph`, `context inspect`, `policy test`, `forensic why`, `doctor`, `demo`, `init`).
- `--json` machine-readable output across all major commands.

---

## 5. Existing Dashboard & API Audit

### 5.1 FastAPI Backend (`agentguard/api/server.py`)
- Endpoints:
  - `/api/v1/overview`, `/api/v1/status`, `/api/v1/health`
  - `/api/v1/agents`, `/api/v1/resources`, `/api/v1/access-matrix`
  - `/api/v1/incidents`, `/api/v1/forensics`, `/api/v1/traces`
  - `/api/v1/posture`, `/api/v1/drift`, `/api/v1/gates`
  - `/api/v1/offensive/attacks`, `/api/v1/offensive/campaigns`
  - `/api/v1/events/stream` (SSE / WebSocket live event streaming)

### 5.2 Next.js Dashboard (`dashboard/`)
- Modern React 19 / Next.js 16 application with dark mode UI.
- All core security control plane views implemented (Command Center, Live Activity, Agents, Tasks, MCP, Incidents, Posture, Gates, etc.).
- Bundling requirement: Provide a standalone bundled static distribution or embedded server runner inside the Python package so `pip install agentguard` can serve the dashboard without requiring Node.js.

---

## 6. Testing Baseline

- **Test Suite:** `sdk/tests/`
- **Current Passing Count:** 219 tests (0 failures, 4 deselected ollama integration tests).
- **Execution Command:** `$env:PYTHONPATH="e:\AGENT-GUARD;e:\AGENT-GUARD\sdk"; pytest sdk/tests -m "not ollama" -q`

---

## 7. Extension Points & Roadmap

1. **SDK Public Facade Extension:** Add streamlined high-level methods to `AgentGuard` (`observe`, `correlate`, `analyze`, `enforce`, `authorize`, `register_agent`, `explain`, `forensics`, `@guard.agent`, `with guard.agent_context`).
2. **Interactive CLI Shell:** Full `ag >` interactive command center with command history, tab completion, brand ASCII logo, and rich formatting.
3. **Agent Graph & Topology:** First-class ASCII/Rich graph visualization of agent hierarchies, MCP gateways, and tool access.
4. **Offline Embedded Dashboard Serving:** Package static assets or built artifacts into the wheel so `agentguard dashboard` operates standalone.
5. **Doctor & Demo Commands:** Automated health audit (`agentguard doctor`) and self-contained end-to-end multi-agent security simulation (`agentguard demo`).
