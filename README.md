# ActShield

**Security Control Plane for Autonomous AI**

ActShield gives autonomous and multi-agent AI systems identity, authority containment, context provenance, taint tracking, deterministic policy enforcement, threat modeling, forensic investigation, and continuous offensive validation.

```
pip install actshield
```

---

## What it does

AI agents can read documents, call APIs, browse the web, delegate to sub-agents, and execute tools against production systems. Standard application security does not account for the fact that the agent's reasoning — and therefore its actions — can be directly influenced by external content.

ActShield sits between agents and the tools they can execute. It:

1. **Observes** every context element that enters the agent system, records its origin, and marks its trust level
2. **Correlates** agent identity, delegated authority, and context provenance before any tool request
3. **Analyzes** intent using both deterministic rules and AI-powered reasoning (AI Secura / configurable providers)
4. **Enforces** deterministic policy — allow, monitor, require human-in-the-loop, quarantine, block, or revoke
5. **Records** structured evidence for every decision: who, what, when, why, context, authority, policy, outcome
6. **Investigates** through a forensic engine that answers the full causal chain
7. **Validates** the security boundary continuously with an adaptive offensive testing engine
8. **Gates** deployment through CI/CD security quality controls

---

## Architecture

```
Agents
   │
   ▼
ActShield SDK
   │
   ├── Identity & Agent Registry
   ├── Delegation & Authority Containment
   ├── Context Provenance Tracking
   ├── Taint Tracking
   ├── MCP Gateway
   ├── HTTP Gateway
   └── Tool Interception
   │
   ▼
Security Analysis
   │
   ├── AI Secura / Configurable LLM Provider
   └── APIRIS (API Risk Intelligence)
   │
   ▼
Deterministic Policy Evaluator
   │
   ├── ALLOW
   ├── MONITOR
   ├── HITL (Human-in-the-Loop)
   ├── QUARANTINE
   ├── BLOCK
   └── REVOKE
   │
   ▼
Evidence
   │
   ├── Forensics & Causal Traces
   ├── Incident Engine
   ├── Drift Detection
   ├── Posture Scoring
   └── Security Gates
   │
   ▼
Offensive Validation
   │
   └── Adaptive Attack Campaigns → Regression → Secured Replay
```

---

## Security Model

**LLMs reason. Deterministic policies enforce.**

ActShield maintains a strict separation:

- **AI Secura** and other LLM providers provide advisory analysis — risk assessment, intent classification, anomaly detection
- **PolicyEvaluator** makes the final enforcement decision deterministically based on rules, authority, taint state, and AI advisory score
- If AI is unavailable, enforcement falls through to deterministic policy — never to ALLOW by default

**Core invariants:**

| Invariant | Description |
|-----------|-------------|
| Authority containment | Effective authority ≤ delegated authority ≤ declared authority |
| Taint propagation | Context derived from untrusted sources is tainted and cannot authorize CRITICAL tool execution |
| Fail-safe | AI failure → deterministic policy evaluation, not ALLOW |
| Provenance | Every context element has a recorded origin and trust level |
| Auditability | Every security decision produces structured, immutable evidence |

---

## Installation

```bash
pip install actshield
```

With optional AI provider support:

```bash
pip install actshield[openai]
pip install actshield[gemini]
pip install actshield[anthropic]
pip install actshield[ollama]
pip install actshield[dashboard]   # FastAPI + dashboard support
pip install actshield[all]         # All optional dependencies
```

---

## Quick Start

### SDK

```python
from actshield import ActShield

guard = ActShield(mode="strict")

@guard.protect(tool="customer_db.read", sensitivity="critical")
async def read_customer_data(query: str):
    # This function will not execute without:
    # - Valid agent authority for customer_db.read
    # - Clean (non-tainted) context provenance
    # - Policy evaluation: ALLOW or HITL
    ...
```

### CLI

```bash
# Start the security control plane
actshield serve

# System status
actshield status

# Security posture scorecard
actshield posture

# Registered agents
actshield agents

# Live event stream
actshield watch

# System diagnostic
actshield doctor
```

### Dashboard

```bash
actshield serve
# → http://localhost:3000
```

---

## Threat Modeling

ActShield includes a formal threat modeling subsystem. The threat model sits above the runtime engine and maps assets, trust boundaries, and actors to the controls that protect them.

```bash
# Full threat analysis report
actshield threat analyze

# List all identified threats
actshield threat list

# Inspect a specific threat
actshield threat inspect thr_indirect_pi

# Render attack graph
actshield threat graph

# Generate Markdown report
actshield threat report --output threat-report.md

# Export JSON
actshield threat export --format json --output threat-model.json
```

Example output:

```
ACTSHIELD  THREAT ANALYSIS
System: ActShield-Monitored Agent System
Analysis Time: 2026-09-21 08:30:00 UTC
Overall Risk: 2.8 / 10.0

Threat Inventory
  Assets             8
  Trust Boundaries   7
  Threat Actors      8
  Identified Threats 10
  Attack Scenarios   3

Severity Breakdown
  CRITICAL    2  ██
  HIGH        6  ██████
  MEDIUM      1  █
  LOW         1  █

Control Domain Coverage
  Identity               ✓
  Authority              ✓
  Context                ✓
  Tool Security          ✓
  MCP                    ✓
  Data Access            ✓
  Delegation             ✓
  Enforcement            ✓
  Evidence               ✓
```

---

## AI Providers

ActShield uses AI for security reasoning but does not depend on any single provider.

```yaml
# actshield.yaml
ai:
  provider: ai_secura   # ai_secura | ollama | openai | gemini | anthropic | null
  failure_mode: fail_safe
```

| Provider | Description |
|----------|-------------|
| `ai_secura` | Built-in security-specialized reasoning (default) |
| `ollama` | Local LLM inference — no external API calls |
| `openai` | OpenAI API |
| `gemini` | Google Gemini API |
| `anthropic` | Anthropic Claude API |
| `null` | Deterministic-only mode — AI advisory disabled |

```bash
actshield ai list
actshield ai use ollama
actshield ai status
```

---

## APIRIS

APIRIS (API Risk Intelligence Service) analyzes outbound API calls for risk signals: unusual endpoints, data exfiltration patterns, known-bad destinations, and protocol anomalies.

```yaml
apiris:
  enabled: true
  mode: strict
```

---

## Enforcement Decisions

| Decision | Meaning |
|----------|---------|
| `ALLOW` | Request is within authority, context is clean, policy permits |
| `MONITOR` | Request is permitted but flagged for observation |
| `HITL` | Human approval required before execution |
| `QUARANTINE` | Agent isolated pending investigation |
| `BLOCK` | Request denied — authority, taint, or policy violation |
| `REVOKE` | Agent authority revoked |

---

## Forensics

```bash
# Why did this event occur?
actshield forensic why <event-id>

# Investigate a full causal trace
actshield forensic trace <trace-id>

# Assess downstream impact
actshield forensic impact <event-id>

# Full forensic incident report
actshield forensic report <incident-id>
```

The forensic engine answers:

- WHO caused it and through which delegation chain?
- WHAT context influenced the decision?
- WHERE did that context originate?
- WHAT authority existed at the time of execution?
- WHY was it blocked or allowed?
- WHAT changed after remediation?

---

## Offensive Validation

ActShield includes an adaptive offensive security validation engine for testing the security boundary against a controlled corpus of attacks.

```bash
# Run adaptive attack campaign
actshield attack adaptive

# List available attack cases
actshield attack list
```

> **Important:** The offensive engine operates in `LOCAL_ONLY` mode. It cannot target external systems.

---

## Security Gates (CI/CD)

```bash
actshield gate evaluate --min-score 85

# Exit codes:
# 0 = PASS
# 1 = SECURITY FAILURE
# 2 = SYSTEM/CONFIG ERROR
```

```bash
actshield gate evaluate --json
```

Gate checks:
- Posture score above threshold
- No unauthorized sensitive executions
- No bypass events
- No open critical regressions
- Offensive test pass rate

---

## Configuration

`actshield.yaml`:

```yaml
version: 1

runtime:
  mode: strict   # strict | monitor | audit

ai:
  provider: ai_secura
  failure_mode: fail_safe

apiris:
  enabled: true

dashboard:
  enabled: true
  host: 127.0.0.1   # Never expose to 0.0.0.0 without explicit security controls

telemetry:
  enabled: true
  structured_logging: true

offensive:
  mode: local_only   # local_only is the only supported mode

storage:
  backend: sqlite    # sqlite | postgres
```

Environment variable overrides:

```bash
ACTSHIELD_MODE=strict
ACTSHIELD_AI_PROVIDER=ollama
ACTSHIELD_APIRIS_ENABLED=true
```

---

## Security Guarantees

ActShield makes specific, verifiable security claims:

1. **A tainted context cannot authorize CRITICAL tool execution** — taint propagation is deterministic; CRITICAL tools require explicit authority and clean provenance
2. **AI failure cannot produce ALLOW** — if the AI provider is unavailable, enforcement falls through to deterministic policy with fail-safe defaults
3. **Authority cannot be escalated beyond the delegation chain** — the containment invariant is enforced before any tool execution
4. **Every enforcement decision produces evidence** — no security decision is made without a structured audit record
5. **The offensive engine cannot target external systems** — LOCAL_ONLY is enforced at the engine level, not just configuration

ActShield does **not** claim:
- 100% prevention of all prompt injection (content-level semantic attacks remain a research problem)
- Protection against malicious code executing inside a trusted process (supply chain attacks require defense-in-depth)
- Compliance certification without additional implementation work

---

## Project Structure

```
actshield/
├── sdk/
│   └── actshield/
│       ├── agents/           Agent identity and registry
│       ├── api/              FastAPI REST endpoints
│       ├── approval/         HITL approval management
│       ├── cli/              Typer+Rich CLI
│       ├── context/          Context + provenance + taint
│       ├── decisions/        Security decision records
│       ├── delegation/       Authority grants + delegation chains
│       ├── drift/            Behavioral baseline + drift detection
│       ├── evaluation/       Evaluation harness
│       ├── forensics/        Causal investigation engine
│       ├── gates/            CI/CD security quality gates
│       ├── gateway/          MCP + HTTP gateway interceptors
│       ├── incidents/        Incident state machine
│       ├── integrations/     AI Secura + APIRIS + Ollama adapters
│       ├── offensive/        Adaptive attack + mutation engine
│       ├── persistence/      SQLite/Postgres + SIEM export
│       ├── policy/           Deterministic policy evaluator
│       ├── posture/          Security posture scoring
│       ├── providers/        AI provider registry + adapters
│       ├── response/         Automated response orchestration
│       ├── risk/             Risk models and assessment
│       ├── tasks/            Task tracking
│       ├── threatmodel/      Formal threat modeling subsystem
│       ├── tools/            Tool interception + sensitivity
│       └── tracing/          Causal event tracing
├── dashboard/                Next.js security console
├── docs/
│   ├── architecture/
│   └── security/
└── examples/
```

---

## Running Tests

```bash
cd sdk
pip install -e ".[dev]"
pytest tests/ -v

# Exclude tests requiring external services
pytest tests/ -v -m "not ollama and not integration"
```

---

## Performance

| Metric | Target |
|--------|--------|
| Policy evaluation latency | < 5ms (deterministic path) |
| Tool interception overhead | < 10ms (non-AI path) |
| AI advisory latency | 100–2000ms (provider-dependent, async) |
| Dashboard initial load | < 2s |
| Event buffer | 500 events max in browser state |

---

## License

Apache 2.0

---

*ActShield — Security Control Plane for Autonomous AI*
