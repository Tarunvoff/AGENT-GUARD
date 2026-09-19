// AgentGuard Frontend — Core TypeScript Data Models
// Maps exactly to the backend API contract from Phase 6.5

// ─── Enumerations ─────────────────────────────────────────────────────────

export type AccessDecision = 'ALLOW' | 'HITL' | 'BLOCK' | 'MONITOR' | 'UNKNOWN';
export type TrustLevel = 'high' | 'medium' | 'low' | 'untrusted';
export type TaintState = 'CLEAN' | 'TAINTED' | 'SANITIZED' | 'UNKNOWN';
export type IncidentSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
export type IncidentStatus = 'ACTIVE' | 'CONTAINED' | 'INVESTIGATING' | 'RESOLVED';
export type AttackType =
  | 'INDIRECT_PROMPT_INJECTION'
  | 'DIRECT_PROMPT_INJECTION'
  | 'AUTHORITY_IMPERSONATION'
  | 'AUTHORITY_ESCALATION'
  | 'TOOL_POISONING'
  | 'MCP_SERVER_POISONING'
  | 'CONTEXT_MANIPULATION'
  | 'TAINT_LAUNDERING'
  | 'DELEGATION_ESCALATION'
  | 'MULTI_HOP_ESCALATION'
  | 'DATA_EXFILTRATION'
  | 'INTENT_DRIFT'
  | 'JAILBREAK'
  | 'CUSTOM';

export type EventType =
  | 'agent.created'
  | 'task.created'
  | 'tool.request'
  | 'tool.executed'
  | 'tool.blocked'
  | 'delegation.created'
  | 'context.received'
  | 'context.tainted'
  | 'policy.decision'
  | 'mcp.request'
  | 'mcp.response'
  | 'attack.detected'
  | 'incident.created';

export type ContextSource =
  | 'user'
  | 'system_prompt'
  | 'agent_output'
  | 'tool_result'
  | 'mcp_response'
  | 'external_document'
  | 'api_response'
  | 'memory'
  | 'external_mcp';

export type SensitivityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE';

// ─── Core Models ──────────────────────────────────────────────────────────

export interface Agent {
  agent_id: string;
  name: string;
  framework?: string;
  version?: string;
  trust_level: TrustLevel;
  capabilities: string[];
  status: 'active' | 'idle' | 'delegated' | 'blocked';
  current_task_id?: string;
  risk_level?: SensitivityLevel;
  metadata?: Record<string, unknown>;
}

export interface AgentAccessProfile {
  agent_id: string;
  agent_name: string;
  trust_level: TrustLevel;
  declared: string[];
  delegated: string[];
  effective: string[];
  restricted: string[];
  reachable_tools: string[];
  reachable_resources: string[];
  total_attempts: number;
  total_blocked: number;
  total_allowed: number;
  total_executions: number;
}

export interface Capability {
  name: string;
  description?: string;
  sensitivity?: SensitivityLevel;
}

export interface Resource {
  resource_id: string;
  name: string;
  resource_type: string;
  sensitivity: SensitivityLevel;
  exposing_tools: string[];
  authorized_agents: string[];
  attempted_agents: string[];
  actual_access_agents: string[];
  blocked_agents: string[];
  total_attempts: number;
  total_blocked: number;
  total_executions: number;
}

export interface Task {
  task_id: string;
  intent: string;
  status: 'active' | 'completed' | 'failed' | 'blocked';
  root_agent_id?: string;
  current_agent_id?: string;
  initiating_user?: string;
  delegation_chain: string[];
  risk_level?: SensitivityLevel;
  created_at: string;
  updated_at?: string;
  trace_id?: string;
}

export interface Delegation {
  delegation_id: string;
  delegator_agent_id: string;
  delegate_agent_id: string;
  granted_capabilities: string[];
  depth: number;
  parent_delegation_id?: string;
  task_id?: string;
  trace_id?: string;
  status: 'active' | 'completed' | 'revoked' | 'expired';
  created_at: string;
  expires_at?: string;
  constraints?: string[];
}

export interface Context {
  context_id: string;
  source: ContextSource;
  trust_level: TrustLevel;
  taint_state: TaintState;
  content_summary?: string;
  provenance: Provenance;
  parent_context_id?: string;
  children_context_ids: string[];
  agent_id?: string;
  trace_id?: string;
  timestamp: string;
  hash?: string;
}

export interface Provenance {
  source: ContextSource;
  trust_level: string;
  source_uri?: string;
  hops: ProvenanceHop[];
  sanitized: boolean;
}

export interface ProvenanceHop {
  from_agent?: string;
  to_agent?: string;
  timestamp: string;
  hop_type: 'propagated' | 'delegated' | 'created' | 'modified';
}

export interface ToolDefinition {
  tool_id: string;
  name: string;
  sensitivity: SensitivityLevel;
  required_capabilities: string[];
  target_resources: Resource[];
  description?: string;
}

export interface MCPServer {
  server_id: string;
  name: string;
  uri: string;
  trust_level: TrustLevel;
  tools: string[];
  total_requests: number;
  blocked_requests: number;
  incidents: number;
  last_seen?: string;
  risk_level?: SensitivityLevel;
}

export interface SecurityEvent {
  event_id: string;
  event_type: EventType;
  timestamp: string;
  trace_id?: string;
  agent_id?: string;
  task_id?: string;
  tool_name?: string;
  resource_name?: string;
  decision?: AccessDecision;
  taint_state?: TaintState;
  risk_level?: SensitivityLevel;
  summary: string;
  payload?: Record<string, unknown>;
}

export interface Trace {
  trace_id: string;
  task_id?: string;
  events: SecurityEvent[];
  agents_involved: string[];
  resources_touched: string[];
  final_decision?: AccessDecision;
  taint_introduced: boolean;
  started_at: string;
  completed_at?: string;
}

// ─── Policy & Decisions ───────────────────────────────────────────────────

export interface PolicyDecision {
  decision_id: string;
  trace_id?: string;
  agent_id: string;
  tool_name: string;
  action: AccessDecision;
  reason_code: string;
  explanation: string;
  risk_score: number;
  timestamp: string;
}

export interface PolicyRule {
  policy_id: string;
  name: string;
  description: string;
  enabled: boolean;
  action: AccessDecision;
  conditions: string[];
}

// ─── AI Analysis ──────────────────────────────────────────────────────────

export interface AISecuraAnalysis {
  available: boolean;
  model?: string;
  threat_type?: AttackType;
  intent_alignment: 'ALIGNED' | 'VIOLATED' | 'UNKNOWN';
  authority_assessment: 'CONTAINED' | 'VIOLATED' | 'UNKNOWN';
  risk_level: SensitivityLevel;
  confidence?: number;
  reasoning?: string;
  recommendation: AccessDecision;
  attack_techniques?: string[];
}

export interface APIRISAnalysis {
  available: boolean;
  endpoint?: string;
  vendor?: string;
  risk_level: SensitivityLevel;
  anomaly_detected: boolean;
  security_signals: string[];
  cve_references: string[];
  recommendation: string;
  latency_ms?: number;
}

// ─── Attack / Offensive ───────────────────────────────────────────────────

export interface Attack {
  attack_id: string;
  campaign_id?: string;
  attack_type: AttackType;
  target: string;
  entry_point: string;
  expected_decision: AccessDecision;
  actual_decision: AccessDecision;
  bypassed: boolean;
  tool_executed: boolean;
  execution_count: number;
  sensitive_db_calls: number;
  mutation_lineage: string[];
  adaptive_iteration: number;
  status: 'PASS' | 'BYPASS' | 'ERROR';
  timestamp?: string;
}

export interface AttackForensics {
  report_id: string;
  attack_id: string;
  campaign_id?: string;
  attack_type: string;
  target: string;
  agent_id: string;
  original_intent: string;
  mutation_lineage: string[];
  taint_state: string;
  policy_decision: AccessDecision;
  policy_reason_code: string;
  tool_executed: boolean;
  execution_count: number;
  sensitive_db_calls: number;
  bypassed: boolean;
  reachable_resources: string[];
  regression_status: string;
}

export interface MutationNode {
  node_id: string;
  attack_id: string;
  parent_id?: string;
  depth: number;
  attack_type: AttackType;
  decision: AccessDecision;
  bypassed: boolean;
  children: MutationNode[];
  iteration: number;
}

export interface Campaign {
  campaign_id: string;
  name?: string;
  total_attacks: number;
  bypasses: number;
  blocks: number;
  bypass_rate: number;
  sensitive_db_calls?: number;
  mean_latency_ms?: number;
  p95_latency_ms?: number;
  ai_secura_availability?: number;
  apiris_availability?: number;
  started_at?: string;
  completed_at?: string;
}

// ─── Forensics ────────────────────────────────────────────────────────────

export interface AccessAttempt {
  attempt_id: string;
  agent_id: string;
  tool_name: string;
  resource_name?: string;
  resource_sensitivity: SensitivityLevel;
  decision: AccessDecision;
  policy_reason: string;
  taint_state: TaintState;
  authority_contained: boolean;
  executed: boolean;
  execution_count: number;
  trace_id?: string;
  timestamp: string;
}

export interface ActualAccess {
  access_id: string;
  agent_id: string;
  tool_name: string;
  resource_name?: string;
  execution_count: number;
  sensitive_db_calls: number;
  trace_id?: string;
  timestamp: string;
}

export interface AccessSnapshot {
  snapshot_id: string;
  label: string;
  timestamp: string;
  agents: Record<string, {
    agent_id: string;
    effective_capabilities: string[];
    reachable_resources: string[];
    active_delegations: string[];
  }>;
  resources: Record<string, unknown>;
  delegations: Record<string, unknown>;
  context_count: number;
  tainted_context_count: number;
}

export interface AccessDiff {
  diff_id: string;
  before_snapshot_id: string;
  after_snapshot_id: string;
  authority_changed: boolean;
  new_capabilities: string[];
  lost_capabilities: string[];
  attack_detected: boolean;
  taint_changed: boolean;
  context_changed: boolean;
  summary: string;
}

export interface ForensicExplanation {
  explanation_id: string;
  agent_id: string;
  tool_name: string;
  resource_name?: string;
  resource_sensitivity: string;
  original_intent: string;
  context_trust: string;
  taint_state: string;
  delegated_authority: string[];
  requested_capability?: string;
  effective_authority: string;
  policy_decision: AccessDecision;
  policy_reason_code: string;
  policy_explanation: string;
  ai_secura_summary?: string;
  apiris_summary?: string;
  tool_executed: boolean;
  execution_count: number;
  sensitive_db_calls: number;
  bypass_detected: boolean;
}

// ─── Incidents ────────────────────────────────────────────────────────────

export interface Incident {
  incident_id: string;
  incident_type: string;
  severity: IncidentSeverity;
  agent_id?: string;
  resource_name?: string;
  tool_name?: string;
  decision: AccessDecision;
  executed: boolean;
  trace_id?: string;
  attack_id?: string;
  status: IncidentStatus;
  description: string;
  timestamp: string;
}

export interface Regression {
  regression_id: string;
  attack_type: AttackType;
  attack_id: string;
  expected_decision: AccessDecision;
  observed_decision: AccessDecision;
  current_decision?: AccessDecision;
  replay_decision?: AccessDecision;
  secured: boolean;
  mutation_lineage: string[];
  sensitive_db_calls_before: number;
  sensitive_db_calls_after: number;
  created_at: string;
}

// ─── Overview / Metrics ───────────────────────────────────────────────────

export interface Overview {
  agents: number;
  active_tasks?: number;
  protected_tools: number;
  mcp_servers?: number;
  attacks_today: number;
  blocked: number;
  hitl: number;
  bypasses: number;
  sensitive_attempts: number;
  sensitive_prevented: number;
  sensitive_executed: number;
  campaigns: number;
  regressions: number;
  incidents: number;
  availability: {
    active_tasks: boolean;
    mcp_servers: boolean;
  };
}

export interface Metrics {
  total_agents: number;
  total_attacks: number;
  bypass_rate: number;
  block_rate: number;
  sensitive_prevention_rate: number;
}

export interface AccessMatrix {
  matrix_id: string;
  agents: string[];
  resources: string[];
  table: Record<string, Record<string, string>>;
  effective_permissions: Record<string, Record<string, boolean>>;
}

// ─── Health ───────────────────────────────────────────────────────────────

export interface HealthStatus {
  status: 'ok' | 'degraded' | 'error';
  version: string;
  timestamp: string;
  components: Record<string, string>;
}

// ─── Graph Node/Edge Types ────────────────────────────────────────────────

export type NodeType =
  | 'user'
  | 'agent'
  | 'task'
  | 'tool'
  | 'resource'
  | 'mcp'
  | 'context'
  | 'policy'
  | 'decision';

export type EdgeType =
  | 'delegates'
  | 'caused'
  | 'propagated'
  | 'requested'
  | 'blocked'
  | 'executed'
  | 'analyzed'
  | 'authorized'
  | 'attempted'
  | 'tainted';

export interface GraphNode {
  id: string;
  type: NodeType;
  label: string;
  trust_level?: TrustLevel;
  taint_state?: TaintState;
  decision?: AccessDecision;
  risk?: SensitivityLevel;
  data?: Record<string, unknown>;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  type: EdgeType;
  label?: string;
  animated?: boolean;
  data?: Record<string, unknown>;
}

// ─── Demo Scenario ────────────────────────────────────────────────────────

export type DemoScenario =
  | 'benign_task'
  | 'indirect_prompt_injection'
  | 'controlled_bypass_and_regression';

export interface DemoStep {
  step: number;
  title: string;
  description: string;
  highlight?: string;
  decision?: AccessDecision;
  taint?: TaintState;
}
