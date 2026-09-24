# ActShield — End-to-End System & User Flows

This document details the complete operational workflows, runtime execution paths, and developer interaction lifecycles across the **ActShield** AI Security Control Plane.

---

## Table of Contents

1. [Flow 1: Agent Registration & Monotonic Delegation Lifecycle](#flow-1-agent-registration--monotonic-delegation-lifecycle)
2. [Flow 2: Tool Interception, Context Taint & Deterministic Policy Enforcement](#flow-2-tool-interception-context-taint--deterministic-policy-enforcement)
3. [Flow 3: Model Context Protocol (MCP) Security Gateway Flow](#flow-3-model-context-protocol-mcp-security-gateway-flow)
4. [Flow 4: Security Incident Lifecycle & 7-Stage Response](#flow-4-security-incident-lifecycle--7-stage-response)
5. [Flow 5: Causal Forensics & Root-Cause Analysis Flow](#flow-5-causal-forensics--root-cause-analysis-flow)
6. [Flow 6: Behavioral Baseline Drift Detection Flow](#flow-6-behavioral-baseline-drift-detection-flow)
7. [Flow 7: CI/CD Security Quality Gate Evaluation Flow](#flow-7-cicd-security-quality-gate-evaluation-flow)
8. [Flow 8: Embedded Control Plane Dashboard & Live Telemetry Flow](#flow-8-embedded-control-plane-dashboard--live-telemetry-flow)

---

## Flow 1: Agent Registration & Monotonic Delegation Lifecycle

This flow governs how agents register with cryptographic identities and delegate tasks down a hierarchy while guaranteeing that privileges strictly diminish monotonically.

```mermaid
sequenceDiagram
    autonumber
    actor Dev as Developer / App
    participant Guard as ActShield SDK
    participant Registry as Agent Registry
    participant DelMgr as Delegation Manager
    participant Invariant as Monotonic Validator

    Dev->>Guard: ActShield(mode="strict").start()
    Dev->>Guard: register_agent(name="orchestrator", capabilities={"delegate", "read_docs", "report"})
    Guard->>Registry: Create AgentIdentity(id="agt_orch01", trust="HIGH")
    Registry-->>Dev: Orchestrator Agent Instance

    Dev->>Guard: orchestrator.delegate(to_agent="researcher", capabilities={"read_docs"}, task_id="tsk_01")
    Guard->>DelMgr: Request delegation token
    DelMgr->>Invariant: Validate Authority(Child) ⊆ Authority(Parent)
    
    alt Valid Delegation (Subset of Capabilities)
        Invariant-->>DelMgr: PASSED
        DelMgr->>Registry: Bind DelegationToken(delegator="agt_orch01", delegate="agt_res02")
        DelMgr-->>Dev: Delegated Agent Context (Authorized)
    else Privilege Escalation Attempt (Child requests unowned capability)
        Invariant-->>DelMgr: REJECTED (Escalation Detected)
        DelMgr->>Guard: Emit AuthorityEscalationAttempt Event
        DelMgr-->>Dev: Raise AuthorityEscalationError (BLOCKED)
    end
```

### Key Stages
1. **Identity Registration**: Agent is assigned an immutable identity `AgentIdentity` with declared capability bounds.
2. **Delegation Request**: Parent agent initiates sub-task delegation with a specified capability subset.
3. **Monotonic Invariant Check**: System verifies:
   $$\text{Capabilities}(\text{Child}) \subseteq \text{Capabilities}(\text{Parent})$$
4. **Token Issuance or Violation Block**: If valid, an immutable scoped token is generated; if an escalation is attempted, execution is blocked immediately.

---

## Flow 2: Tool Interception, Context Taint & Deterministic Policy Enforcement

This flow illustrates what happens when an agent attempts to invoke a protected tool or sensitive sink (database, shell, API).

```mermaid
flowchart TD
    A([Agent Calls @guard.protect Tool]) --> B[ToolInterceptor Captures Invocations]
    B --> C[Extract Execution Context]
    
    subgraph Context Extraction
        C1[Active Agent ID & Identity]
        C2[Delegation Token & Capabilities]
        C3[Context Provenance & Taint State]
        C4[Task ID & Intended Action]
    end
    C --> C1 & C2 & C3 & C4

    C1 & C2 & C3 & C4 --> D{Is Context TAINTED?}
    
    D -- Yes --> E{Is Target Tool a Sensitive Sink?}
    E -- Yes --> F[BLOCK: Tainted Sink Access Violation]
    E -- No --> G[Query APIRIS Risk Engine]
    
    D -- No --> H{Agent Possesses Required Capability?}
    H -- No --> I[BLOCK: Missing Capability Token]
    H -- Yes --> G

    G --> J[Deterministic Policy Evaluator]
    
    J --> K{Policy Decision}
    K -- ALLOW --> L[Execute Native Tool Function]
    K -- HITL --> M[Pause & Request Human Approval]
    K -- BLOCK --> N[Abort Execution & Log Violation]
    K -- QUARANTINE --> O[Isolate Agent & Revoke Delegation]

    L --> P[Record EXECUTED Event in Causal Graph]
    M --> Q{Human Approves?}
    Q -- Yes --> L
    Q -- No --> N
    N --> R[Record BLOCKED Event in Incident Log]
```

### Key Stages
1. **Interception**: `@guard.protect` intercepts arguments and execution context before function body runs.
2. **Taint Evaluation**: Checks if data entering the prompt chain was tagged `UNTRUSTED_EXTERNAL` or `MCP_EXTERNAL`.
3. **Deterministic Authorization**: Policy engine checks deterministic capability match; advisory AI provides risk weighting.
4. **Enforcement Execution**: Binary deterministic outcome (`ALLOW`, `HITL`, `BLOCK`, `QUARANTINE`).

---

## Flow 3: Model Context Protocol (MCP) Security Gateway Flow

This flow protects against rogue MCP servers, tool poisoning, and prompt injection via external tools.

```mermaid
sequenceDiagram
    autonumber
    participant Agent as Autonomous Agent
    participant Gateway as ActShield MCPGateway
    participant RemoteMCP as Remote MCP Server
    participant TaintEngine as Taint & Provenance Engine

    Note over Agent,Gateway: Discovery Phase
    Agent->>Gateway: list_tools()
    Gateway->>RemoteMCP: MCP JSON-RPC: tools/list
    RemoteMCP-->>Gateway: Return Exposed Tools & Schemas
    Gateway->>Gateway: Sanitize tool schemas & detect prompt injection payloads
    Gateway-->>Agent: Filtered, Validated Tool Definitions

    Note over Agent,Gateway: Tool Execution Phase
    Agent->>Gateway: call_tool(name="fetch_user_doc", args={...})
    Gateway->>Gateway: Validate Agent Authority & Active Task
    Gateway->>RemoteMCP: MCP JSON-RPC: tools/call
    RemoteMCP-->>Gateway: Return Raw Tool Result Content
    
    Gateway->>TaintEngine: Ingest payload (SourceType.MCP_EXTERNAL)
    TaintEngine->>TaintEngine: Assign TrustLevel.UNTRUSTED & Mark Context TAINTED
    Gateway-->>Agent: Return Tool Result with Tainted Context Binding
```

---

## Flow 4: Security Incident Lifecycle & 7-Stage Response

When a policy boundary breach or malicious attempt occurs, ActShield transitions the incident through 7 rigorous stages.

```
  ┌──────────────┐     ┌───────────┐     ┌─────────────────┐     ┌─────────────┐
  │ 1. DETECTED  │ ──> │ 2. TRIAGED│ ──> │ 3. INVESTIGATING│ ──> │ 4. CONTAINED│
  └──────────────┘     └───────────┘     └─────────────────┘     └─────────────┘
                                                                        │
  ┌──────────────┐     ┌─────────────┐     ┌─────────────────┐          │
  │  7. CLOSED   │ <── │ 6.VALIDATED │ <── │ 5. REMEDIATED   │ <────────┘
  └──────────────┘     └─────────────┘     └─────────────────┘
```

```mermaid
stateDiagram-v2
    [*] --> DETECTED: Policy Breach / Taint Violation Occurs
    DETECTED --> TRIAGED: Calculate Severity (CRITICAL/HIGH/MED/LOW)
    TRIAGED --> INVESTIGATING: Assemble Causal Graph & Trace Lineage
    INVESTIGATING --> CONTAINED: Isolate Agent / Revoke Delegation Token
    CONTAINED --> REMEDIATED: Apply Rule Fix / Sanitize Context Inputs
    REMEDIATED --> VALIDATED: Replay Attack Trace to Verify Defense
    VALIDATED --> CLOSED: Archive Cryptographic Audit Evidence
    CLOSED --> [*]
```

---

## Flow 5: Causal Forensics & Root-Cause Analysis Flow

ActShield tracks the 5-stage causal lifecycle (`INTENDED` → `REQUESTED` → `ALLOWED` → `ATTEMPTED` → `EXECUTED`) to enable instant root-cause analysis.

```mermaid
sequenceDiagram
    autonumber
    actor SecOps as Security Engineer
    participant CLI as ActShield CLI / API
    participant Forensic as Forensic Engine
    participant Graph as CausalGraph Store

    SecOps->>CLI: actshield forensic why evt_8891a4
    CLI->>Forensic: Query root-cause explanation for Event ID
    Forensic->>Graph: Trace parent nodes, prompts, delegations, context origins
    Graph-->>Forensic: Return correlated 5-Stage Causal Chain
    
    Note over Forensic: Lineage Reconstruction:
    Note over Forensic: 1. INTENDED: User asked agent to summarize reports
    Note over Forensic: 2. REQUESTED: Agent requested 'query_customer_db'
    Note over Forensic: 3. CONTEXT: Ingested untrusted web document (TAINTED)
    Note over Forensic: 4. ALLOWED: Evaluator rejected (Rule: Tainted Sink Access)
    Note over Forensic: 5. OUTCOME: BLOCKED at interceptor before DB call

    Forensic-->>CLI: Structured Root-Cause Report
    CLI-->>SecOps: Render Terminal Panel / JSON Explanation
```

---

## Flow 6: Behavioral Baseline Drift Detection Flow

Detects silent agent compromise, gradual context pollution, or deviation from established multi-turn operational baselines.

```mermaid
flowchart LR
    A[Agent Runtime Telemetry] --> B[BehavioralBaselineTracker]
    
    subgraph Metrics Extraction
        B --> M1[Invocation Frequency]
        B --> M2[Parameter Entropy]
        B --> M3[Error & Retry Rate]
        B --> M4[Capability Distance]
    end

    M1 & M2 & M3 & M4 --> C[Compute Statistical Z-Score vs Baseline]
    
    C --> D{Deviation > Threshold?}
    D -- Normal (Score >= 85) --> E[Posture: HEALTHY - Continue Execution]
    D -- Moderate Drift (60-84) --> F[Elevate APIRIS Risk → Require HITL]
    D -- Critical Drift (< 60) --> G[QUARANTINE Agent & Trigger Incident]
```

---

## Flow 7: CI/CD Security Quality Gate Evaluation Flow

Enforces automated security quality gates during continuous integration to prevent vulnerable agent configurations from merging.

```mermaid
sequenceDiagram
    autonumber
    actor Pipeline as GitHub Actions / CI Runner
    participant CLI as ActShield Gate CLI
    participant Posture as PostureEngine
    participant Evaluator as SecurityGateEvaluator

    Pipeline->>CLI: actshield gate evaluate --min-score 85.0 --json
    CLI->>Posture: evaluate_current_posture()
    Posture-->>CLI: Return SecurityPostureSnapshot (Score, Dimensions, Findings)
    
    CLI->>Evaluator: evaluate(snapshot, min_score=85.0)
    
    Evaluator->>Evaluator: Check 1: Zero unauthorized DB calls
    Evaluator->>Evaluator: Check 2: Zero offensive attack bypasses
    Evaluator->>Evaluator: Check 3: Zero open regressions
    Evaluator->>Evaluator: Check 4: Zero failed replays
    Evaluator->>Evaluator: Check 5: Posture score >= 85.0

    alt All 5 Checks Passed
        Evaluator-->>CLI: GateStatus.PASSED (exit_code=0)
        CLI-->>Pipeline: JSON Output + Exit 0 (CI Pipeline Continues)
    else Any Check Failed
        Evaluator-->>CLI: GateStatus.FAILED (exit_code=1)
        CLI-->>Pipeline: JSON Failure Report + Exit 1 (Build Blocked)
    end
```

---

## Flow 8: Embedded Control Plane Dashboard & Live Telemetry Flow

The zero-configuration embedded control plane delivers real-time visibility through static Next.js assets served by FastAPI.

```mermaid
sequenceDiagram
    autonumber
    actor User as User / Admin Browser
    participant Web as Control Plane UI (Port 8000)
    participant API as FastAPI Backend (/api/v1/*)
    participant Core as ActShield Runtime Engines

    User->>Web: Navigate to http://localhost:8000/
    Web->>API: GET /api/v1/posture/latest
    API->>Core: Fetch PostureSnapshot
    API-->>Web: Posture Scorecard (100/100, Grade A)

    Web->>API: GET /api/v1/agents
    API->>Core: Fetch Agent Registry & Delegation Hierarchy
    API-->>Web: Topology Graph Nodes & Edges

    Web->>API: Connect SSE /api/v1/events/stream
    loop Real-Time Telemetry Stream
        Core->>API: New SecurityEvent (Tool Request, Policy Decision, Incident)
        API-->>Web: Push Event to Live Dashboard Feed
        Web->>User: Real-time UI Update (Charts, Graph nodes, Incident cards)
    end
```

---

## Summary Matrix of Project Flows

| Flow | Primary Actors | Key Invariant / Mechanism | Output Artifact |
|---|---|---|---|
| **1. Delegation** | Orchestrator $\to$ Sub-Agent | Monotonicity: $\text{Auth}(\text{Child}) \subseteq \text{Auth}(\text{Parent})$ | `DelegationToken` |
| **2. Interception** | Agent $\to$ Tool Sink | Zero-Trust Interceptor + Taint-Sink Barriers | `SecurityDecision` (`ALLOW`/`BLOCK`/`HITL`) |
| **3. MCP Gateway** | Agent $\to$ Remote MCP Server | Schema Validation + Automatic Resource Taint | Sanitized Tools & Tainted Context |
| **4. Incident Cycle** | Control Plane $\to$ SecOps | 7-Stage Incident Lifecycle | `IncidentReport` (Audit Trail) |
| **5. Forensics** | SecOps Engineer $\to$ CLI | 5-Stage Causal Lifecycle Lineage | `CausalGraph` (`why` explanation) |
| **6. Drift Tracking** | Runtime Monitor $\to$ Agent | Statistical Baseline Deviation Z-Score | `DriftAnomalyEvent` / Dynamic HITL |
| **7. CI/CD Gate** | CI Runner $\to$ Quality Gate | 5 Deterministic Quality Gate Checks | Gate JSON Output + Exit Code `0`/`1` |
| **8. Control Plane** | Admin Browser $\to$ UI/API | Embedded Next.js Dashboard + SSE Stream | Live Multi-Agent Visual Telemetry |
