# ActShield Security Model

**The Deterministic AI Security Control Plane Specification**

---

## 1. Core Architectural Principle

> **"LLMs reason. Deterministic policies enforce."**

In autonomous AI systems, large language models generate plans, invoke tools, reason over context, and delegate to sub-agents. However, LLMs are fundamentally non-deterministic, vulnerable to prompt injection, context contamination, and reasoning drift.

**ActShield** enforces a strict security separation:
- **AI Advisory Layer (AI Secura / Configurable Providers):** Provides intent classification, risk scoring, behavioral anomaly detection, and semantic analysis.
- **Deterministic Policy Layer:** Enforces invariant rules, authority containment, taint barriers, human-in-the-loop triggers, and cryptographic causal provenance.

An AI model's recommendation can raise an alert or suggest human review, but can **never** independently authorize execution when deterministic security invariants are violated.

---

## 2. The 4 MANTA Principles

AgentGuard adheres to the 4 MANTA foundational principles for multi-agent security:

### 1. Monotonic Authority Containment
An agent cannot grant, assume, or delegate permissions it does not possess. Sub-agents inherit a strictly monotonic subset of their parent agent's declared authority:
$$\text{Authority}(\text{Child}) \subseteq \text{Authority}(\text{Parent}) \subseteq \text{DeclaredAuthority}$$

### 2. Attributable Context Provenance & Taint Tracking
Every piece of data entering the agent context is tracked from origin (user prompt, local document, external web, untrusted MCP tool output). Untrusted data marks context as `TAINTED`. Tainted contexts cannot flow into sensitive sinks (databases, credentials, system shells) without explicit deterministic sanitization.

### 3. Non-Bypassable Tool Interception (Reference Monitor)
All tool invocations and execution requests are intercepted by the AgentGuard runtime before execution occurs. The control plane checks:
- Caller identity and active task binding
- Delegated capability tokens
- Context taint state
- Deterministic policy boundaries
- Risk evaluation scores (APIRIS)

### 4. Transparent Forensic Causality
The runtime generates complete, correlated causal traces differentiating the lifecycle of execution:
- `INTENDED`: What the agent planned to do.
- `REQUESTED`: The concrete tool call and arguments requested.
- `ALLOWED`: The policy decision rendered by the deterministic evaluator.
- `ATTEMPTED`: The invocation passed to the interceptor.
- `EXECUTED`: The actual runtime execution outcome.

---

## 3. Delegation & Authority Model

### Agent Identity
Each agent registers with a cryptographic or unique identity `AgentIdentity(agent_id, name, trust_level, capabilities)`.

```python
from agentguard import AgentGuard, Agent

guard = AgentGuard(mode="strict")
orchestrator = guard.register_agent(
    name="orchestrator",
    capabilities={"delegate", "research", "report"},
    trust_level="HIGH"
)
```

### Delegation Chains
When an agent delegates a task to another agent:
```python
sub_agent = orchestrator.delegate(
    to_agent="researcher-001",
    capabilities={"research"}, # Must be subset of parent's capabilities
    task_id="tsk_8892"
)
```
If `orchestrator` attempts to delegate `{"database_admin"}`, AgentGuard blocks the delegation instantly with an `AuthorityEscalationAttempt` event.

---

## 4. Context Taint & Provenance Tracking

Data origins are classified into trust tiers:
- `TRUSTED_INTERNAL`: Core system prompts, verified configuration, enterprise database records.
- `USER_VERIFIED`: Directly authenticated user inputs.
- `UNTRUSTED_EXTERNAL`: Web pages, public APIs, untrusted user files.
- `MCP_EXTERNAL`: Model Context Protocol tool outputs from third-party servers.

```python
from agentguard import Context, SourceType, TrustLevel

# Context from external tool is marked TAINTED
mcp_context = guard.create_context(
    source_type=SourceType.MCP_EXTERNAL,
    trust_level=TrustLevel.UNTRUSTED,
    content="Downloaded document content..."
)
# Attempting to call sensitive DB tool with tainted context -> BLOCKED
```

---

## 5. Failure Semantics & Resilience

| Failure Scenario | Control Plane Behavior | Justification |
|-------------------|------------------------|---------------|
| AI Secura / LLM Provider Timeout | Fallback to Deterministic Policy (FAIL_CLOSED) | Prevents denial-of-service or lag from opening execution holes |
| Provider Network Error | Enforce default capability boundaries | Safe degradation |
| Malformed / Corrupted AI Output | Quarantine task & trigger HITL | Defensive isolation |
| Context Taint Overflow | Block sink invocation | Data leak prevention |
| Unauthorized Delegation | Terminate delegation branch & log incident | Zero privilege escalation |

---

## 6. Incident Response & 7-Stage Lifecycle

When a policy violation or abnormal drift occurs, AgentGuard tracks the incident through seven stages:
1. `DETECTED` → Anomaly or policy boundary breach registered.
2. `TRIAGED` → Severity and affected agents calculated.
3. `INVESTIGATING` → Forensic causal trace assembled.
4. `CONTAINED` → Offending agent quarantined or capabilities restricted.
5. `REMEDIATED` → Policy rules updated or malicious input sanitized.
6. `VALIDATED` → Attack replay executed to verify defense.
7. `CLOSED` → Audit trail finalized and archived.
