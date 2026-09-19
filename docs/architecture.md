# AgentGuard Architecture Documentation

## 1. Overview & Core Mission

AgentGuard is the causal security and deterministic enforcement layer for multi-agent AI ecosystems. When autonomous agents delegate tasks to other agents, ingest external/MCP context, invoke tools/APIs, and access sensitive resources, AgentGuard provides deterministic security governance, lineage tracking, and causal graph reconstruction.

```
+--------------------------------------------------------------------------------+
|                               AgentGuard Core                                  |
|                                                                                |
|  +--------------------------------------------------------------------------+  |
|  | Causal Correlation & Distributed Tracing (Trace, Span, Task, Event)      |  |
|  +--------------------------------------------------------------------------+  |
|  | Agent Identity & Trust Lifecycle (HIGH, MEDIUM, LOW, UNTRUSTED)          |  |
|  +--------------------------------------------------------------------------+  |
|  | Recursive Delegation & Monotonic Authority Containment                   |  |
|  +--------------------------------------------------------------------------+  |
|  | Context Provenance & Taint Lineage Tracking (TRUSTED, UNTRUSTED, TAINTED)|  |
|  +--------------------------------------------------------------------------+  |
|  | Protected Tool Execution & Secret Redaction Hooks                         |  |
|  +--------------------------------------------------------------------------+  |
|  | Deterministic Policy Evaluator (ALLOW/MONITOR/APPROVAL/BLOCK/REVOKE)     |  |
|  +--------------------------------------------------------------------------+  |
|                         ^                                  ^                   |
|                         | Signals                          | Signals           |
|  +-----------------------------------+  +-----------------------------------+  |
|  |      AI Secura (Security LLM)     |  |   APIRIS (API Decision Intel)     |  |
|  |   Reasoning, Intent & Threat Intel|  |   API Risk, Anomaly, CVE Intel    |  |
|  +-----------------------------------+  +-----------------------------------+  |
+--------------------------------------------------------------------------------+
```

---

## 2. Fundamental Security Principle

> **"AI reasons. Deterministic security policy enforces."**

- **AI Secura** provides qualitative security reasoning, detecting intent drift, indirect prompt injections, and attack indicators. AI Secura **never directly executes irreversible enforcement decisions**.
- **APIRIS** provides tool and API decision intelligence, analyzing endpoint reputation, CVE exposure, parameters, and network anomaly signals.
- **AgentGuard Policy Engine** deterministically aggregates intelligence signals, evaluates capability containment, verifies taint boundaries, and executes policy verdicts:
  - `ALLOW`
  - `MONITOR`
  - `HUMAN_APPROVAL`
  - `QUARANTINE`
  - `BLOCK`
  - `REVOKE`

---

## 3. Causal Questions Answered

AgentGuard provides deterministic answers to the 12 core multi-agent security questions:

1. **Who initiated the action?** Tracked via `Task.initiating_user` and `initiating_application`.
2. **Which agent performed it?** Correlated via `CorrelationContext.agent_id`.
3. **Who delegated the authority?** Tracked via `Delegation.delegator_agent_id`.
4. **What authority was delegated?** Formally bounded via `AuthorityGrant.granted_capabilities`.
5. **What context influenced the action?** Tracked through `ToolRequest.context_ids`.
6. **Where did that context originate?** Detailed in `Context.provenance` (source URI, originating agent, timestamps).
7. **Did untrusted context propagate across agents?** Captured in `Provenance.hops` with persistent `TaintState`.
8. **Did the final action remain within original user intent?** Evaluated against `Task.original_intent` with AI Secura reasoning.
9. **Did the agent exceed its delegated authority?** Verified through monotonic capability subset checks.
10. **What API/tool/resource was ultimately accessed?** Emitted in `tool.invoked` and `resource.access_requested` events.
11. **Why was the action allowed or blocked?** Documented in `SecurityDecision.reason_code` and `explanation`.
12. **Can the complete causal chain be reconstructed?** Traversed from root `User` to final `Decision` via `AgentGuard.reconstruct_trace()`.

---

## 4. Subsystem Architecture

### 4.1. Correlation & Tracing (`agentguard.tracing`)
- Implements `CorrelationContext` using Python's `contextvars.ContextVar` for async-safe, thread-safe context propagation across tasks, spans, and agent handoffs.
- Strongly typed `SecurityEvent` model covering 16 standard lifecycle events.
- `TraceManager` stores events and dynamically reconstructs the causal DAG (`CausalGraph`), exporting to JSON or rendering universal ASCII execution trees.

### 4.2. Identity & Delegation (`agentguard.agents`, `agentguard.delegation`)
- `AgentIdentity`: Unique agent ID, framework, version, trust level (`HIGH`, `MEDIUM`, `LOW`, `UNTRUSTED`), and capabilities.
- Recursive Delegation: Agents can delegate to other agents to arbitrary depth without hardcoded limits.
- **Monotonic Authority Containment**: A delegator can only grant capabilities that it currently holds (or was granted by its parent delegator). Escalation attempts trigger immediate security incidents and `PermissionError`.

### 4.3. Context & Taint Lineage (`agentguard.context`)
- Tracks data provenance across hops without polluting global agent state.
- `TaintState`: `TRUSTED`, `UNTRUSTED`, `TAINTED`, `UNKNOWN`.
- Conservative worst-case combination rules ensure untrusted inputs remain tainted through multi-agent transformations.

### 4.4. Protected Tools & Resources (`agentguard.tools`)
- `@guard.protected_tool` decorator intercepts synchronous and asynchronous invocations.
- Evaluates policy before invoking the target function.
- Automatically redacts sensitive credentials, passwords, and tokens (`sk-...`, Bearer tokens, private keys) from event logs.

### 4.5. Integration Adapters (`agentguard.integrations`)
- Follows the **Dependency Inversion Principle**:
  - `SecurityReasoner` Protocol for AI Secura.
  - `APIIntelligence` Protocol for APIRIS.
- Clean local reference adapters (`LocalAISecuraAdapter`, `LocalAPIRISAdapter`) allow offline execution, CI/CD testing, and smooth production replacement in later phases.
