# AgentGuard SDK & Platform Evolution Audit

## Overview & Architecture

AgentGuard has evolved into a production-grade, SDK-first, CLI-first continuous security control plane for autonomous multi-agent AI systems.

### Core Guarantees & Invariants
1. **Deterministic Security Boundary**: The enforcement path (`PolicyEvaluator`, `TaintTracker`, `AgentIdentity`) is 100% deterministic and mathematically sound.
2. **AI Intelligence as Advisory**: AI Security Providers (`SecurityAIProvider`) offer threat reasoning and vulnerability insights, but **never** act as the sole authorization authority.
3. **Fail-Safe Deny**: If all AI intelligence providers are offline or malformed, the system falls back to deterministic deny policies.
4. **Single-Pane-of-Glass CLI & UI**: Unified commands for monitoring, CI/CD gates, offensive validation, live telemetry, and embedded dashboard serving.

---

## Modular Component Map

| Component / Subsystem | Location | Description |
| :--- | :--- | :--- |
| **CLI & Runtime Interface** | `sdk/agentguard/__main__.py` | Rich & Typer CLI with ASCII banner, structured status tables, REPL console (`ag>`), and subcommands (`status`, `posture`, `incidents`, `drift`, `gate`, `attack`, `watch`, `serve`, `ai`) |
| **Provider Registry** | `sdk/agentguard/providers/` | Modular `SecurityAIProvider` registry with ordered failover across `OllamaProvider`, `OpenAIProvider`, `GeminiProvider`, `AnthropicProvider`, and `NullProvider` |
| **Live Telemetry Watcher** | `sdk/agentguard/watch.py` | `rich.live` streaming terminal feed of causal trace events, posture evaluations, and security decisions |
| **Embedded Control Plane Serve** | `sdk/agentguard/serve.py` | Unified launcher for FastAPI backend and Next.js dashboard frontend |
| **Security Posture Engine** | `sdk/agentguard/posture/` | 5-dimension continuous posture evaluator with time-series snapshots and automated findings |
| **Incident Management Engine** | `sdk/agentguard/incidents/` | 7-stage incident lifecycle with causal timelines and automated root-cause analysis |
| **Behavioral Drift Engine** | `sdk/agentguard/drift/` | Statistical baseline tracker for authority, tool access, and context degradation |
| **CI/CD Quality Gates** | `sdk/agentguard/gates/` | Strict release gates with zero-bypass, zero-unauthorized execution, and regression criteria |
| **Offensive Validation** | `sdk/agentguard/offensive/` | Automated red-teaming corpus, mutation engine, and regression lifecycle testing |

---

## CLI Command Tree

```
agentguard
├── status               # High-level security posture summary and active providers
├── posture              # Posture scorecard, dimension breakdown, and active findings (--json supported)
├── incidents            # Security incident log and detail inspector (list, show <id>)
├── drift                # Behavioral drift and anomaly detections
├── gate                 # CI/CD security quality gate evaluator (exit code 0/1)
├── attack               # Offensive validation commands
│   ├── list             # List baseline and regression attack corpus
│   ├── run              # Run validation attack campaign (--type, --limit)
│   └── replay           # Replay an attack against the current policy
├── watch                # Real-time causal security event stream with Rich tables
├── serve                # Start FastAPI backend and Next.js dashboard together
├── console              # Interactive REPL shell (ag>)
└── ai                   # Manage Security AI intelligence providers
    ├── status           # List all registered providers, health, and latency
    └── benchmark        # Benchmark reasoning throughput and risk advisory
```

---

## Failover Sequence

```mermaid
graph TD
    A[Security Event / Context Packet] --> B[PolicyEvaluator (Deterministic Boundary)]
    B -->|Parallel Advisory Request| C[ProviderRegistry.analyze]
    C --> D{Ollama Available?}
    D -- Yes --> E[Ollama Security Reasoning]
    D -- No --> F{OpenAI Available?}
    F -- Yes --> G[OpenAI GPT-4o-mini]
    F -- No --> H{Gemini Available?}
    H -- Yes --> I[Gemini Flash]
    H -- No --> J{Anthropic Available?}
    J -- Yes --> K[Claude 3.5 Sonnet]
    J -- No --> L[NullProvider -> None (Fail-Safe)]
    E --> M[Aggregate Advisory & Causal Trace]
    G --> M
    I --> M
    K --> M
    L --> M
    M --> N[Deterministic Enforcement Decision: ALLOW / BLOCK / HITL]
```
