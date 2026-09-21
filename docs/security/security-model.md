# ActShield Security Model

This document describes the security architecture of ActShield, the controls it enforces, and the precise claims it makes and does not make.

---

## Fundamental Design Principle

**LLMs reason. Deterministic policies enforce.**

ActShield uses AI models for security reasoning — risk assessment, intent analysis, anomaly detection. It uses deterministic rule evaluation for enforcement decisions. These two functions are explicitly separated.

This separation is critical. AI models are probabilistic and can be influenced by adversarial inputs. The PolicyEvaluator is deterministic and cannot be influenced by agent context or external content.

---

## Authority Model

ActShield models three authority states for every agent action:

| State | Description |
|-------|-------------|
| `DECLARED` | Authority the agent claims to have |
| `DELEGATED` | Authority explicitly granted to the agent by its parent in the delegation chain |
| `EFFECTIVE` | The intersection: min(DECLARED, DELEGATED) — the authority actually available |

**Containment invariant:** `EFFECTIVE ≤ DELEGATED ≤ DECLARED`

This invariant is enforced deterministically before any tool execution. An agent cannot claim authority beyond what its delegation chain explicitly granted.

### Action states

| State | Description |
|-------|-------------|
| `INTENDED` | What the task was supposed to accomplish |
| `REQUESTED` | What the agent requested |
| `ALLOWED` | What policy permitted |
| `ATTEMPTED` | What was attempted |
| `EXECUTED` | What actually ran |

ActShield maintains the distinction between these states in every audit record.

---

## Context Security

### Provenance

Every context element that enters the agent system is tagged with:

- **Source** — where it came from (user input, MCP server, web content, RAG retrieval, internal system)
- **Trust level** — `INTERNAL`, `EXTERNAL`, `UNTRUSTED`
- **Hop chain** — the full path the context took through the system

Provenance is recorded at ingestion time and is immutable.

### Taint Tracking

Context derived from external or untrusted sources is marked `TAINTED`.

Taint propagates: if context element A is tainted and influences context element B, element B is also tainted.

**Taint enforcement rule:** A tainted context cannot authorize execution of a `CRITICAL` sensitivity tool without an explicit authority grant that overrides the taint check. This override must be configured in policy, not inferred.

### Trust Levels

| Level | Sources | Tool access |
|-------|---------|------------|
| `INTERNAL` | Authenticated internal system | All permitted tools |
| `EXTERNAL` | Web content, external APIs | Restricted — cannot access CRITICAL |
| `UNTRUSTED` | Poisoned/adversarial (detected) | None — blocked |

---

## AI Advisory Boundary

AI models (AI Secura, Ollama, OpenAI, Gemini, Anthropic) provide:

- Intent alignment score
- Risk assessment
- Threat classification
- Anomaly signals

AI advisory scores are **inputs** to the PolicyEvaluator — they are not the policy.

The PolicyEvaluator makes the final enforcement decision based on:
1. Rule conditions (deterministic)
2. Authority check (deterministic)
3. Taint state (deterministic)
4. AI advisory score (probabilistic — used as signal, not decision)

### AI Failure Behavior

If the AI provider is unavailable:

```
AI unavailable
    ↓
PolicyEvaluator uses: rules + authority + taint
    ↓
Fail-safe default: BLOCK (for CRITICAL tools) or MONITOR (for non-critical)
```

**AI failure never produces ALLOW for sensitive operations.**

---

## Tool Sensitivity Classification

Every tool registered with ActShield has a `SensitivityLevel`:

| Level | Description | AI failure behavior |
|-------|-------------|-------------------|
| `LOW` | Non-sensitive operations | ALLOW with monitoring |
| `MEDIUM` | Moderately sensitive | MONITOR |
| `HIGH` | Sensitive data access | HITL required |
| `CRITICAL` | Customer data, credentials, infrastructure | BLOCK if tainted or authority insufficient |

---

## MCP Security

External MCP servers are treated as untrusted until proven otherwise.

All MCP communications pass through `MCPGateway`:
- Responses are inspected before entering agent context
- Content is taint-marked with `EXTERNAL` provenance
- Provenance records are attached to all derived context

A compromised MCP server that returns adversarial instructions will:
1. Have its response intercepted
2. Have all derived context marked `EXTERNAL/TAINTED`
3. Be unable to trigger CRITICAL tool execution (taint blocks it)

---

## Offensive Validation (LOCAL_ONLY)

The offensive engine tests the security boundary using an adaptive attack corpus.

**LOCAL_ONLY constraint:**
- The offensive engine can only target registered `AttackTarget` instances
- It cannot be configured to attack external systems
- This constraint is enforced in `OffensiveEngine`, not just configuration

The offensive engine produces machine-readable regression records. Failed security tests become regression cases that are replayed on each validation run.

---

## Secret Handling

ActShield does not log secrets. The logging pipeline applies a redaction filter to:
- API keys (patterns: `sk-...`, `Bearer ...`, known formats)
- Passwords and tokens
- Full document content of CRITICAL assets

Structured events record metadata about secret access attempts — not the secrets themselves.

---

## Dashboard Security

By default, `actshield serve` binds to `127.0.0.1` (localhost only).

Deployment modes:

| Mode | Bind address | Authentication |
|------|-------------|----------------|
| Local development | `127.0.0.1` | None required |
| Team development | `0.0.0.0` (explicit) | Network-level access control required |
| Production | Reverse proxy with auth | OAuth/OIDC or API key |

> **Warning:** Do not expose ActShield dashboard to `0.0.0.0` without network-level access controls in non-development environments. The dashboard provides full visibility into agent security state and must be treated as sensitive infrastructure tooling.

---

## What ActShield Does Not Claim

ActShield makes specific, bounded security claims. It does not claim:

| Claim | Reality |
|-------|---------|
| 100% prompt injection prevention | Content-level semantic injection is an open research problem. ActShield reduces impact through taint + authority. |
| Protection against in-process supply chain attacks | Code executing inside a trusted process is outside ActShield's enforcement boundary. |
| STRIDE/MITRE compliance certification | ActShield maps to these frameworks but does not claim official certification. |
| Zero latency enforcement | Enforcement adds measurable latency. Targets: <5ms deterministic, 100–2000ms with AI advisory. |
| Complete AI reasoning transparency | LLM reasoning is probabilistic. Only enforcement decisions are deterministic and auditable. |

---

## Auditability

Every important security action produces a `SecurityEvent` with:

```
who:       agent_id, agent_name, trust_level
what:      tool_id, tool_name, sensitivity, resource
when:      timestamp, trace_id, span_id
why:       intent_analysis, ai_advisory, risk_assessment
context:   provenance, taint_state, context_source
authority: declared, delegated, effective, required
policy:    rules_evaluated, rule_matched
decision:  action (ALLOW|MONITOR|HITL|BLOCK|QUARANTINE|REVOKE)
outcome:   executed, blocked, escalated
```

These records are written to the configured storage backend (SQLite or PostgreSQL) and are immutable after creation.
