# Changelog

All notable changes to the **AgentGuard** (formerly ActShield) project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.9.2] - 2026-09-25

### Added
- Comprehensive in-depth documentation detailing the 6 fundamental multi-agent security challenges and ActShield's deterministic countermeasures:
  1. Indirect Prompt Injection & Context Poisoning (Attributable Context Provenance & Taint Sinks)
  2. Authority Escalation & Confused Deputy Attacks (Monotonic Delegation Invariant)
  3. Rogue Tool Integrations & MCP Poisoning (MCP Security Gateway)
  4. Non-Deterministic LLM-Policing-LLM Governance (Deterministic Code Invariant & Fail-Closed Fallback)
  5. Black-Box Execution & Absence of Causal Forensics (5-Stage Causal Lifecycle & Forensic Graph)
  6. Silent Behavioral Drift & Agent Compromise (Statistical Baseline Deviation Engine & Dynamic APIRIS)

## [0.9.1] - 2026-09-25

### Changed
- Standardized package and branding identity under `actshield`.

## [0.9.0] - 2026-09-24

### Added
- **Unified Public Identity (`agentguard`)**:
  - Primary package namespace `agentguard` with 100% backward-compatible `actshield` alias.
  - Dual CLI commands: `agentguard`, `actshield`, and `as-guard`.
- **Pluggable AI Provider Architecture**:
  - Standardized `SecurityAIProvider` and `SecurityReasoner` interfaces.
  - Multi-provider adapters for OpenAI, Gemini, Anthropic, Ollama, Hugging Face, AI Secura, and Custom backends.
  - Deterministic fallback when AI providers are unavailable or timeout (fail-closed / fail-safe).
- **Comprehensive Enterprise CLI**:
  - Full command suite: `status`, `posture`, `agents`, `incidents`, `drift`, `version`, `doctor`, `demo`, `watch`, `serve`, `tasks`, `policies`, `tools`, `mcp`, `config`, `replay`, `regression`, `apiris`, `report`, `ai`, `attack` / `offensive`, `gate`, `dashboard`, `threat`, `forensic` / `forensics`.
  - Machine-readable `--json` support across all management commands.
  - Automated CI/CD security gate evaluator: `agentguard gate evaluate`.
- **Model Context Protocol (MCP) Gateway Security**:
  - Indirect prompt injection protection and tool poisoning detection.
  - Strict taint propagation on MCP resources and exposed tools.
- **Embedded Control Plane Dashboard**:
  - Standalone Next.js static dashboard embedded directly inside the Python distribution package.
  - Zero-configuration launch via `agentguard serve` serving UI, FastAPI REST API, and interactive Swagger docs.
- **Continuous Security Posture & Threat Modeling**:
  - 6-dimension posture scorecard (Threat Prevention, Boundary Adherence, Delegation Hygiene, Taint Containment, Offensive Immunity, Drift Stability).
  - Built-in STRIDE + AI threat modeling analyzer, reporting, and graph generation.
- **Adversarial & Failure-Injection Test Suite**:
  - 271 test cases covering multi-agent identity, causal tracing, context taint, delegation monotonicity, failure semantics, MCP gateway, and gate evaluation.

### Changed
- Standardized package metadata in `pyproject.toml` with dual package distribution (`agentguard` + `actshield`).
- Refactored CLI gate evaluator to consume live runtime `SecurityPostureSnapshot` metrics.
- Upgraded `Doctor` diagnostic engine to perform automated runtime health checks across all security subsystems.

### Security
- Invariant enforcement: **"LLMs reason; deterministic policies enforce."**
- Complete isolation between advisory AI scoring and deterministic policy execution.
