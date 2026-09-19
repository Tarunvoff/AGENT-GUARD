# 🛡️ AgentGuard

## Security Control Plane for Autonomous AI

> **When AI can act, security must follow the action.**

---

## The Problem Is No Longer Just What AI Says

On September 18, 2026, Google confirmed that during cybersecurity testing, Gemini unintentionally accessed real company systems.

The testing environment was intended to contain simulated companies. However, unintended internet access combined with a naming collision caused Gemini to reach real systems. In some cases, credentials were guessed or retrieved from publicly available sources. Google said the model stopped after recognizing that the targets were real.

The important lesson isn't about one model.

It is about **what happens when an AI system moves from generating an answer to taking an action.**

An autonomous agent can:

```text
Reason
  ↓
Choose a target
  ↓
Use context
  ↓
Delegate to another agent
  ↓
Call an MCP server
  ↓
Call an API
  ↓
Use credentials
  ↓
Access a resource
  ↓
Execute an action
```

And once this happens at enterprise scale, the security problem changes.

---

# The 1,000-Agent Problem

Imagine an enterprise running hundreds or thousands of autonomous agents.

```text
                         ENTERPRISE AI

        ┌──────────────┬──────────────┬──────────────┐
        ↓              ↓              ↓
     Agents           MCP            APIs
        ↓              ↓              ↓
   Sub-agents      External Data    Tools
        ↓              ↓              ↓
        └──────────────┼──────────────┘
                       ↓
                Enterprise Systems
                       ↓
                  Sensitive Data
```

An agent may no longer operate alone.

It can delegate.

A delegated agent can delegate again.

A tool can return external content.

An MCP server can introduce untrusted context.

That context can influence another agent.

That agent can request a privileged tool.

And the final action may be several hops away from the original user instruction.

Traditional security systems can answer:

> Who is this agent?

> What resource was accessed?

> What event happened?

But autonomous AI introduces a deeper question:

> **Why did this action happen?**

And even more importantly:

> **Who authorized it, what influenced it, what authority was delegated, and did the final action remain within the original intent?**

That is the gap AgentGuard is designed to address.

---

# Introducing AgentGuard

## A Cross-Boundary Causal Security Control Plane for Multi-Agent AI

AgentGuard sits between autonomous AI systems and the resources they can influence.

```text
                         ENTERPRISE AI

                   Agents / Sub-Agents
                            │
                     MCP / APIs / Tools
                            │
                            ▼
                     ┌──────────────┐
                     │  AGENTGUARD  │
                     │              │
                     │ Identity     │
                     │ Authority    │
                     │ Context      │
                     │ Provenance   │
                     │ Taint        │
                     │ Policy       │
                     │ Evidence     │
                     └──────┬───────┘
                            │
                            ▼
                   Enterprise Resources
```

AgentGuard follows an action across:

```text
Identity
   ↓
Task
   ↓
Delegation
   ↓
Context
   ↓
Provenance
   ↓
Authority
   ↓
Tool / API
   ↓
Policy
   ↓
Execution
```

The result is not just an alert.

It is a **causal security record of why the action happened and what actually happened.**

---

# The AgentGuard Security Loop

Everything in AgentGuard revolves around four stages:

# OBSERVE → CORRELATE → ANALYZE → ENFORCE

We call this the **4 MANTA flow**.

---

## 01 — OBSERVE

First, AgentGuard captures what the autonomous system is doing.

```text
Agent
Task
Tool
MCP
API
Context
Resource
Trace
Execution
```

The objective is simple:

> **Don't lose the action.**

Every important operation receives identity and trace context.

---

## 02 — CORRELATE

Observation alone is not enough.

AgentGuard connects the events.

```text
User
 ↓
Planner
 ↓ delegation
Research Agent
 ↓
MCP
 ↓
External Context
 ↓
Analysis Agent
 ↓
Data Agent
 ↓
Sensitive Tool
```

AgentGuard tracks:

```text
Identity
+
Delegation
+
Authority
+
Context
+
Provenance
+
Taint
+
Causal Trace
```

This allows security teams to answer:

> **What caused this action?**

---

# 03 — ANALYZE

AgentGuard combines two intelligence layers.

```text
                    SECURITY ANALYSIS

                         │
             ┌───────────┴───────────┐
             │                       │
             ▼                       ▼
        AI SECURA                 APIRIS
    Security Reasoning       API / Tool Intelligence
```

---

# AI Secura

## The Security Reasoning Layer

AI Secura analyzes the security meaning of an action.

It evaluates:

```text
Original Intent
Agent Chain
Delegation
Context Provenance
Taint
Requested Capability
Target Resource
Previous Actions
```

And produces structured analysis such as:

```text
Threat
Attack Type
Intent Alignment
Authority Violation
Risk
Confidence
Reason
Recommendation
```

For example:

```json
{
  "threat": "indirect_prompt_injection",
  "intent_alignment": "VIOLATED",
  "authority_violation": true,
  "risk": "CRITICAL",
  "recommendation": "BLOCK"
}
```

AI Secura provides **security reasoning**.

It does not become the final authorization mechanism.

---

# APIRIS

## API & Tool Intelligence

AgentGuard also integrates APIRIS for API and tool intelligence.

APIRIS analyzes signals such as:

```text
API / Tool
Vendor
Security Risk
Anomalies
CVE Signals
Latency
Cost
Recommendation
```

The separation is intentional:

```text
AI Secura
     ↓
"What does this action mean from a security perspective?"

APIRIS
     ↓
"What do we know about the API / tool being used?"

Policy Engine
     ↓
"Is this action allowed?"
```

---

# 04 — ENFORCE

This is where AgentGuard differs from an AI-only security system.

The AI can reason.

But the policy engine makes the security decision.

```text
                 SECURITY ANALYSIS
                         │
                         ▼
                DETERMINISTIC POLICY
                         │
             ┌───────────┼───────────┐
             ▼           ▼           ▼
           ALLOW        HITL        BLOCK
```

AgentGuard enforces deterministic controls around:

```text
Capability containment
Delegation validity
Trust level
Taint boundaries
Sensitive resources
Authority boundaries
Tool access
Execution policy
```

### Core principle:

> **LLM reasons. Deterministic policy enforces.**

---

# The Attack We Built

To demonstrate the problem, we built a complete multi-agent enterprise simulation.

The benign task:

> Generate a financial analysis.

The architecture:

```text
User
 ↓
Planner Agent
 ↓
Research Agent
 ↓
External MCP
 ↓
Analysis Agent
 ↓
Data Agent
 ↓
Enterprise Database
```

Now introduce an indirect prompt injection.

The external MCP returns a malicious instruction requesting internal customer records.

AgentGuard sees:

```text
External MCP
     ↓
UNTRUSTED CONTEXT
     ↓
TAINTED CONTEXT
     ↓
Agent Handoff
     ↓
Analysis
     ↓
Data Agent
     ↓
customer_db.read
```

The important part is that the malicious instruction did not need to directly call the database.

It influenced an agent several steps later.

AgentGuard preserves that causal relationship.

---

# The Security Decision

When the Data Agent attempts:

```text
customer_db.read
```

AgentGuard evaluates:

```text
Who?
   ↓
DataAgent

What?
   ↓
customer_db.read

Where did the context come from?
   ↓
External MCP

Trust?
   ↓
UNTRUSTED

Taint?
   ↓
TAINTED

Authority?
   ↓
NOT CONTAINED

Target?
   ↓
CRITICAL RESOURCE
```

The result:

```text
                 POLICY ENGINE

                     BLOCK
                       │
                       ▼
             Sensitive DB Call = 0
```

The most important distinction is:

```text
INTENDED       → NO
REQUESTED      → YES
ALLOWED        → NO
ATTEMPTED      → YES
EXECUTED       → NO
```

### Requested does not mean executed.

This distinction becomes critical during incident response.

---

# The Causal Security Graph

AgentGuard doesn't represent the event as a flat log.

It builds a causal graph.

```text
                    USER
                     │
                     ▼
                PLANNER AGENT
                     │
                delegation
                     │
                     ▼
              RESEARCH AGENT
                     │
                     ▼
              EXTERNAL MCP
                     │
              malicious context
                     │
                     ▼
             UNTRUSTED CONTEXT
                     │
                  tainted
                     │
                     ▼
             ANALYSIS AGENT
                     │
                     ▼
                DATA AGENT
                     │
               attempted
                     │
                     ▼
             customer_db.read
                     │
                     ▼
                 POLICY
                     │
                   BLOCK
```

This lets security teams investigate:

> **What caused the action?**

rather than simply:

> **What was the last event?**

---

# Authority Is Not Just Identity

One of AgentGuard's core models is:

```text
DECLARED
   ↓
DELEGATED
   ↓
EFFECTIVE
   ↓
ATTEMPTED
   ↓
ACTUAL
```

For example:

```text
Planner Agent

Declared:
financial_analysis

        ↓

Research Agent

Delegated:
financial_document_search

        ↓

Data Agent

Attempts:
customer_db.read

        ↓

Policy

Authority violation

        ↓

Actual execution:

BLOCKED
```

This allows AgentGuard to distinguish:

> What an agent **could** do

from

> What an agent **attempted** to do

from

> What an agent **actually did**

---

# Context Provenance & Taint

Autonomous systems increasingly consume information from outside their trust boundary.

AgentGuard tracks where context originated.

```text
USER INPUT
   ↓
AGENT OUTPUT
   ↓
MCP RESPONSE
   ↓
EXTERNAL DOCUMENT
   ↓
API RESPONSE
```

Each context object can carry:

```text
Source
Trust
Provenance
Taint
Timestamp
Parent
Trace
```

For example:

```text
Source:
external_mcp

Trust:
UNTRUSTED

Taint:
TAINTED

Propagation:
MCP
 ↓
Research Agent
 ↓
Analysis Agent
 ↓
Data Agent
 ↓
Sensitive Tool
```

This prevents security context from disappearing when information moves between agents.

---

# Defensive Security Is Only Half the Problem

A security boundary that is never attacked is only a hypothesis.

So AgentGuard includes an offensive validation engine.

```text
             DEFENSIVE SIDE

Observe
   ↓
Correlate
   ↓
Analyze
   ↓
Enforce
   ↓
Evidence
```

And:

```text
             OFFENSIVE SIDE

Attack Seed
   ↓
Mutation
   ↓
Defense Response
   ↓
Boundary Search
   ↓
Bypass?
   ↓
Regression
   ↓
Secured Replay
```

The two sides form a loop:

```text
        DEFEND
          ↓
        ATTACK
          ↓
        OBSERVE
          ↓
        LEARN
          ↓
       IMPROVE
          ↓
        REPLAY
```

---

# Adaptive Offensive Validation

Phase 5 extends static attack replay into adaptive security validation.

The engine can:

```text
Select Attack Seed
       ↓
Observe Defense
       ↓
Analyze Result
       ↓
Understand Defense
       ↓
Plan Mutation
       ↓
Explore Boundary
       ↓
Detect Bypass
       ↓
Create Regression
       ↓
Replay Against Secured System
```

The system maintains full mutation lineage.

```text
Attack Seed
│
├── Mutation A
│   ├── Mutation A1
│   └── Mutation A2
│
├── Mutation B
│   └── Mutation B1
│
└── Boundary Probe
```

Every node maintains:

```text
Attack ID
Parent
Depth
Mutation
Defense Response
Evidence
Result
```

---

# We Deliberately Tried to Break the Defense

AgentGuard includes a controlled vulnerable target.

The offensive engine discovered a bypass:

```text
ATTACK
   ↓
ALLOW
   ↓
TOOL EXECUTED
   ↓
Sensitive DB Calls = 1
   ↓
BYPASS DETECTED
```

Instead of simply reporting the bypass, AgentGuard creates a regression.

```text
BYPASS
  ↓
REGRESSION FIXTURE
  ↓
SECURED REPLAY
  ↓
BLOCK
  ↓
Sensitive DB Calls = 0
```

This turns an attack into a permanent security test.

---

# Phase 5 Validation

Our controlled adaptive campaign produced:

```text
70 attack variants
10 seed trees

70 / 70 blocked
0 unauthorized DB calls

AI Secura availability: 100%
APIRIS availability: 100%

Mean latency: 0.64 ms
P95 latency: 0.93 ms
```

We also demonstrated a deliberate vulnerable target:

```text
Vulnerable Target

ALLOW
Tool executed: true
Sensitive DB calls: 1
        ↓
BYPASS DETECTED
        ↓
REGRESSION CREATED
        ↓
SECURED REPLAY
        ↓
BLOCK
Sensitive DB calls: 0
```

These results come from our controlled local validation environment and should not be interpreted as a guarantee against arbitrary real-world attacks.

---

# LOCAL-ONLY OFFENSIVE SECURITY

The offensive engine is deliberately constrained.

```text
OFFENSIVE_MODE = LOCAL_ONLY
```

The system refuses:

```text
External Targets
External IPs
Unapproved URLs
Destructive Commands
```

All attack validation occurs against synthetic or explicitly controlled targets.

The objective is:

> **Break the defense without breaking the world.**

---

# Forensics

Detection is only the beginning.

When something happens, the security team needs to reconstruct the event.

AgentGuard's forensic model answers:

```text
WHO?
WHY?
WHAT CONTEXT?
WHERE DID IT COME FROM?
WHAT AUTHORITY EXISTED?
WHAT WAS REQUESTED?
WHAT WAS ATTEMPTED?
WHAT WAS ACTUALLY EXECUTED?
WHY WAS IT ALLOWED OR BLOCKED?
```

A forensic investigation can connect:

```text
Agent
 ↓
Task
 ↓
Delegation
 ↓
Context
 ↓
Provenance
 ↓
Taint
 ↓
Authority
 ↓
Tool
 ↓
Policy
 ↓
Execution
 ↓
Impact
```

Instead of:

> "Suspicious database access detected."

The security team gets:

> "DataAgent attempted `customer_db.read` after receiving tainted context originating from an untrusted external MCP response. The requested capability exceeded the effective delegated authority. Deterministic policy blocked the operation. Runtime evidence confirms zero sensitive database executions."

That is the difference between an alert and a forensic explanation.

---

# Why This Matters to a CISO

AgentGuard is designed around five security outcomes.

### 1. VISIBILITY

Know what autonomous agents are actually doing.

### 2. CONTROL

Prevent actions that cross authority or trust boundaries.

### 3. EXPLAINABILITY

Understand why an agent took an action.

### 4. CONTINUOUS VALIDATION

Continuously attack the security boundary in a controlled environment.

### 5. FORENSICS

Distinguish:

```text
Requested
Attempted
Allowed
Executed
Blocked
```

This turns autonomous AI from a black-box execution layer into an observable and enforceable security surface.

---

# The Complete AgentGuard Architecture

```text
                         ENTERPRISE AI
                              │
                 ┌────────────┼────────────┐
                 ▼            ▼            ▼
              AGENTS         MCP          APIs
                 │            │            │
                 └────────────┼────────────┘
                              ▼
                        AGENTGUARD
                              │
               ┌──────────────┼──────────────┐
               ▼              ▼              ▼
            OBSERVE        CORRELATE       ANALYZE
                                               │
                                     ┌─────────┴─────────┐
                                     ▼                   ▼
                                 AI SECURA             APIRIS
                                     └─────────┬─────────┘
                                               ▼
                                          ENFORCEMENT
                                               │
                                  ┌────────────┼────────────┐
                                  ▼            ▼            ▼
                                ALLOW         HITL         BLOCK
                                                              │
                                                              ▼
                                                          EVIDENCE
                                                              │
                                                              ▼
                                                          FORENSICS
                                                              │
                                                              ▼
                                                   OFFENSIVE VALIDATION
                                                              │
                                                              ▼
                                                          REGRESSION
                                                              │
                                                              ▼
                                                      SECURED REPLAY
```

---

# The Core Security Principle

AgentGuard is built around one principle:

> **The model can change its mind. The security boundary should not.**

AI models are probabilistic.

Enterprise authorization cannot be.

That is why AgentGuard separates:

```text
AI REASONING
      +
API / TOOL INTELLIGENCE
      ↓
DETERMINISTIC POLICY
      ↓
EXECUTION CONTROL
      ↓
RUNTIME EVIDENCE
```

---

# What AgentGuard Ultimately Provides

```text
IDENTITY
    +
AUTHORITY
    +
CONTEXT
    +
PROVENANCE
    +
INTENT
    +
TAINT
    +
POLICY
    +
EXECUTION EVIDENCE
    +
OFFENSIVE VALIDATION
    +
FORENSICS

             ↓

       AGENTGUARD
```

---

# From AI That Answers to AI That Acts

The first generation of AI security asked:

> "Is this prompt safe?"

The next generation needs to ask:

> "Is this action safe?"

And enterprise AI requires an even deeper question:

> **"Is this action authorized, contextually valid, within delegated authority, and actually executed as intended?"**

AgentGuard is built around that problem.

---

# 🚀 The Vision

As autonomous agents become part of enterprise workflows, security cannot remain attached only to the model.

Security has to follow the action.

Across:

```text
Agents
↓
Delegations
↓
MCP
↓
APIs
↓
Tools
↓
Context
↓
Authority
↓
Resources
↓
Execution
```

That is the control plane AgentGuard is building.

---

## The Future Is Not Just Agents That Can Act.

# It Is Agents Whose Actions Have

## Identity.

## Authority.

## Context.

## Control.

---

### AgentGuard

**Observe. Correlate. Analyze. Enforce.**

**Attack the boundary. Prove it holds. Explain what happened.**
