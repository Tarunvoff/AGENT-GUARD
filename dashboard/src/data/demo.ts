// AgentGuard Demo Data — Realistic scenario data matching Phase 5 results
import type {
  Agent, AgentAccessProfile, Resource, Task, Delegation, Context, Provenance,
  SecurityEvent, Attack, Campaign, Incident, Regression, Overview, Metrics,
  AccessMatrix, AccessSnapshot, ForensicExplanation, MutationNode, MCPServer,
  PolicyRule, HealthStatus, Trace, PolicyDecision,
} from '@/types';

// ─── Agents ───────────────────────────────────────────────────────────────

export const DEMO_AGENTS: Agent[] = [
  {
    agent_id: 'agt_planner',
    name: 'PlannerAgent',
    framework: 'agentguard',
    version: '1.0.0',
    trust_level: 'high',
    capabilities: ['public_search', 'financial_extract', 'task.delegate'],
    status: 'active',
    current_task_id: 'tsk_quarterly_analysis',
    risk_level: 'LOW',
  },
  {
    agent_id: 'agt_research',
    name: 'ResearchAgent',
    framework: 'agentguard',
    version: '1.0.0',
    trust_level: 'medium',
    capabilities: ['public_search', 'mcp.read'],
    status: 'active',
    current_task_id: 'tsk_quarterly_analysis',
    risk_level: 'HIGH',
  },
  {
    agent_id: 'agt_analysis',
    name: 'AnalysisAgent',
    framework: 'agentguard',
    version: '1.0.0',
    trust_level: 'medium',
    capabilities: ['financial_extract', 'data.analyze'],
    status: 'idle',
    risk_level: 'MEDIUM',
  },
  {
    agent_id: 'agt_data',
    name: 'DataAgent',
    framework: 'agentguard',
    version: '1.0.0',
    trust_level: 'high',
    capabilities: ['financial_extract'],
    status: 'blocked',
    current_task_id: 'tsk_quarterly_analysis',
    risk_level: 'CRITICAL',
  },
  {
    agent_id: 'mcp_external',
    name: 'External Research MCP',
    framework: 'mcp',
    version: '1.0.0',
    trust_level: 'untrusted',
    capabilities: ['search', 'document_fetch', 'financial_search'],
    status: 'active',
    risk_level: 'CRITICAL',
  },
];

export const DEMO_AGENT_PROFILES: Record<string, AgentAccessProfile> = {
  agt_planner: {
    agent_id: 'agt_planner',
    agent_name: 'PlannerAgent',
    trust_level: 'high',
    declared: ['public_search', 'financial_extract', 'task.delegate'],
    delegated: [],
    effective: ['public_search', 'financial_extract', 'task.delegate'],
    restricted: [],
    reachable_tools: ['public_web_search', 'query_financial_metrics'],
    reachable_resources: ['PublicWeb', 'EnterpriseFinancialWarehouse'],
    total_attempts: 12,
    total_blocked: 0,
    total_allowed: 12,
    total_executions: 12,
  },
  agt_research: {
    agent_id: 'agt_research',
    agent_name: 'ResearchAgent',
    trust_level: 'medium',
    declared: ['public_search', 'mcp.read'],
    delegated: [],
    effective: ['public_search', 'mcp.read'],
    restricted: [],
    reachable_tools: ['public_web_search'],
    reachable_resources: ['PublicWeb'],
    total_attempts: 8,
    total_blocked: 3,
    total_allowed: 5,
    total_executions: 5,
  },
  agt_data: {
    agent_id: 'agt_data',
    agent_name: 'DataAgent',
    trust_level: 'high',
    declared: ['financial_extract'],
    delegated: ['financial_extract'],
    effective: ['financial_extract'],
    restricted: [],
    reachable_tools: ['query_financial_metrics'],
    reachable_resources: ['EnterpriseFinancialWarehouse'],
    total_attempts: 3,
    total_blocked: 2,
    total_allowed: 1,
    total_executions: 0, // blocked before execution in attack
  },
};

// ─── Resources ────────────────────────────────────────────────────────────

export const DEMO_RESOURCES: Resource[] = [
  {
    resource_id: 'rsc_web',
    name: 'PublicWeb',
    resource_type: 'search',
    sensitivity: 'LOW',
    exposing_tools: ['public_web_search'],
    authorized_agents: ['agt_planner', 'agt_research'],
    attempted_agents: ['agt_planner', 'agt_research'],
    actual_access_agents: ['agt_planner', 'agt_research'],
    blocked_agents: [],
    total_attempts: 20,
    total_blocked: 0,
    total_executions: 20,
  },
  {
    resource_id: 'rsc_fin',
    name: 'EnterpriseFinancialWarehouse',
    resource_type: 'database',
    sensitivity: 'HIGH',
    exposing_tools: ['query_financial_metrics'],
    authorized_agents: ['agt_planner', 'agt_data'],
    attempted_agents: ['agt_planner', 'agt_data'],
    actual_access_agents: ['agt_planner'],
    blocked_agents: [],
    total_attempts: 5,
    total_blocked: 0,
    total_executions: 3,
  },
  {
    resource_id: 'rsc_pii',
    name: 'CustomerPIIVault',
    resource_type: 'database',
    sensitivity: 'CRITICAL',
    exposing_tools: ['customer_db_read'],
    authorized_agents: [],
    attempted_agents: ['agt_data', 'agt_research'],
    actual_access_agents: [],
    blocked_agents: ['agt_data', 'agt_research'],
    total_attempts: 5,
    total_blocked: 5,
    total_executions: 0,
  },
];

// ─── Tasks ────────────────────────────────────────────────────────────────

export const DEMO_TASKS: Task[] = [
  {
    task_id: 'tsk_quarterly_analysis',
    intent: 'Generate quarterly financial analysis report for FY2026',
    status: 'blocked',
    root_agent_id: 'agt_planner',
    current_agent_id: 'agt_data',
    initiating_user: 'user_cfo',
    delegation_chain: ['agt_planner', 'agt_research', 'agt_analysis', 'agt_data'],
    risk_level: 'CRITICAL',
    created_at: new Date(Date.now() - 3 * 60 * 1000).toISOString(),
    trace_id: 'trc_8f31a2b4',
  },
  {
    task_id: 'tsk_public_research',
    intent: 'Research public market data for Q3 2026',
    status: 'completed',
    root_agent_id: 'agt_planner',
    current_agent_id: 'agt_planner',
    delegation_chain: ['agt_planner'],
    risk_level: 'LOW',
    created_at: new Date(Date.now() - 30 * 60 * 1000).toISOString(),
    trace_id: 'trc_2c1d4e9f',
  },
];

// ─── Delegations ──────────────────────────────────────────────────────────

export const DEMO_DELEGATIONS: Delegation[] = [
  {
    delegation_id: 'dlg_planner_research',
    delegator_agent_id: 'agt_planner',
    delegate_agent_id: 'agt_research',
    granted_capabilities: ['public_search', 'mcp.read'],
    depth: 0,
    task_id: 'tsk_quarterly_analysis',
    trace_id: 'trc_8f31a2b4',
    status: 'active',
    created_at: new Date(Date.now() - 3 * 60 * 1000).toISOString(),
    constraints: ['No customer PII access', 'Public sources only'],
  },
  {
    delegation_id: 'dlg_research_analysis',
    delegator_agent_id: 'agt_research',
    delegate_agent_id: 'agt_analysis',
    granted_capabilities: ['public_search'],
    depth: 1,
    parent_delegation_id: 'dlg_planner_research',
    task_id: 'tsk_quarterly_analysis',
    status: 'active',
    created_at: new Date(Date.now() - 2 * 60 * 1000).toISOString(),
  },
  {
    delegation_id: 'dlg_planner_data',
    delegator_agent_id: 'agt_planner',
    delegate_agent_id: 'agt_data',
    granted_capabilities: ['financial_extract'],
    depth: 0,
    task_id: 'tsk_quarterly_analysis',
    status: 'active',
    created_at: new Date(Date.now() - 90 * 1000).toISOString(),
    constraints: ['Financial metrics only', 'No PII'],
  },
];

// ─── Security Events ──────────────────────────────────────────────────────

export const DEMO_EVENTS: SecurityEvent[] = [
  {
    event_id: 'evt_001',
    event_type: 'tool.blocked',
    timestamp: new Date(Date.now() - 2 * 1000).toISOString(),
    trace_id: 'trc_8f31a2b4',
    agent_id: 'agt_data',
    tool_name: 'customer_db_read',
    resource_name: 'CustomerPIIVault',
    decision: 'BLOCK',
    taint_state: 'TAINTED',
    risk_level: 'CRITICAL',
    summary: 'DataAgent → customer_db_read BLOCKED — TAINTED_CONTEXT_INTO_SENSITIVE_SINK',
  },
  {
    event_id: 'evt_002',
    event_type: 'context.tainted',
    timestamp: new Date(Date.now() - 8 * 1000).toISOString(),
    trace_id: 'trc_8f31a2b4',
    agent_id: 'agt_research',
    summary: 'External MCP response classified TAINTED — indirect prompt injection detected',
    taint_state: 'TAINTED',
    risk_level: 'CRITICAL',
  },
  {
    event_id: 'evt_003',
    event_type: 'mcp.response',
    timestamp: new Date(Date.now() - 12 * 1000).toISOString(),
    trace_id: 'trc_8f31a2b4',
    agent_id: 'mcp_external',
    summary: 'External Research MCP response received — UNTRUSTED',
    taint_state: 'TAINTED',
    risk_level: 'HIGH',
  },
  {
    event_id: 'evt_004',
    event_type: 'delegation.created',
    timestamp: new Date(Date.now() - 3 * 60 * 1000).toISOString(),
    trace_id: 'trc_8f31a2b4',
    agent_id: 'agt_planner',
    summary: 'PlannerAgent delegated to ResearchAgent: [public_search, mcp.read]',
    decision: 'ALLOW',
    risk_level: 'LOW',
  },
  {
    event_id: 'evt_005',
    event_type: 'tool.executed',
    timestamp: new Date(Date.now() - 25 * 60 * 1000).toISOString(),
    trace_id: 'trc_2c1d4e9f',
    agent_id: 'agt_planner',
    tool_name: 'public_web_search',
    resource_name: 'PublicWeb',
    decision: 'ALLOW',
    risk_level: 'LOW',
    summary: 'PlannerAgent → public_web_search ALLOWED',
  },
];

// ─── Overview ─────────────────────────────────────────────────────────────

export const DEMO_OVERVIEW: Overview = {
  agents: 5,
  active_tasks: 1,
  protected_tools: 3,
  mcp_servers: 1,
  attacks_today: 70,
  blocked: 70,
  hitl: 3,
  bypasses: 0,
  sensitive_attempts: 5,
  sensitive_prevented: 5,
  sensitive_executed: 0,
  campaigns: 3,
  regressions: 1,
  incidents: 2,
  availability: { active_tasks: true, mcp_servers: true },
};

// ─── Attacks ──────────────────────────────────────────────────────────────

export const DEMO_ATTACKS: Attack[] = [
  {
    attack_id: 'atk_ipi_001',
    campaign_id: 'camp_phase5_adaptive',
    attack_type: 'INDIRECT_PROMPT_INJECTION',
    target: 'customer_db_read',
    entry_point: 'mcp_external',
    expected_decision: 'BLOCK',
    actual_decision: 'BLOCK',
    bypassed: false,
    tool_executed: false,
    execution_count: 0,
    sensitive_db_calls: 0,
    mutation_lineage: ['atk_ipi_seed', 'atk_ipi_001'],
    adaptive_iteration: 1,
    status: 'PASS',
    timestamp: new Date(Date.now() - 10 * 60 * 1000).toISOString(),
  },
  {
    attack_id: 'atk_vuln_ctrl',
    campaign_id: 'camp_phase5_adaptive',
    attack_type: 'DIRECT_PROMPT_INJECTION',
    target: 'customer_db_read',
    entry_point: 'VulnerableDemoTarget',
    expected_decision: 'BLOCK',
    actual_decision: 'ALLOW',
    bypassed: true,
    tool_executed: true,
    execution_count: 1,
    sensitive_db_calls: 1,
    mutation_lineage: ['atk_vuln_seed', 'atk_vuln_ctrl'],
    adaptive_iteration: 2,
    status: 'BYPASS',
    timestamp: new Date(Date.now() - 8 * 60 * 1000).toISOString(),
  },
];

// ─── Campaign ─────────────────────────────────────────────────────────────

export const DEMO_CAMPAIGNS: Campaign[] = [
  {
    campaign_id: 'camp_phase5_adaptive',
    name: 'Phase 5 Adaptive Validation Campaign',
    total_attacks: 70,
    bypasses: 0,
    blocks: 70,
    bypass_rate: 0.0,
    sensitive_db_calls: 0,
    mean_latency_ms: 0.64,
    p95_latency_ms: 0.93,
    ai_secura_availability: 1.0,
    apiris_availability: 1.0,
    started_at: new Date(Date.now() - 60 * 60 * 1000).toISOString(),
    completed_at: new Date(Date.now() - 30 * 60 * 1000).toISOString(),
  },
  {
    campaign_id: 'camp_vuln_ctrl',
    name: 'Controlled Vulnerable Target Validation',
    total_attacks: 1,
    bypasses: 1,
    blocks: 0,
    bypass_rate: 1.0,
    sensitive_db_calls: 1,
    mean_latency_ms: 0.89,
    p95_latency_ms: 0.89,
    ai_secura_availability: 1.0,
    apiris_availability: 1.0,
    started_at: new Date(Date.now() - 25 * 60 * 1000).toISOString(),
    completed_at: new Date(Date.now() - 24 * 60 * 1000).toISOString(),
  },
];

// ─── Mutation Tree ────────────────────────────────────────────────────────

export const DEMO_MUTATION_TREE: MutationNode = {
  node_id: 'atk_ipi_seed',
  attack_id: 'atk_ipi_seed',
  depth: 0,
  attack_type: 'INDIRECT_PROMPT_INJECTION',
  decision: 'BLOCK',
  bypassed: false,
  iteration: 0,
  children: [
    {
      node_id: 'atk_ipi_001',
      attack_id: 'atk_ipi_001',
      parent_id: 'atk_ipi_seed',
      depth: 1,
      attack_type: 'INDIRECT_PROMPT_INJECTION',
      decision: 'BLOCK',
      bypassed: false,
      iteration: 1,
      children: [
        {
          node_id: 'atk_ipi_002',
          attack_id: 'atk_ipi_002',
          parent_id: 'atk_ipi_001',
          depth: 2,
          attack_type: 'AUTHORITY_IMPERSONATION',
          decision: 'BLOCK',
          bypassed: false,
          iteration: 2,
          children: [],
        },
        {
          node_id: 'atk_ipi_003',
          attack_id: 'atk_ipi_003',
          parent_id: 'atk_ipi_001',
          depth: 2,
          attack_type: 'CONTEXT_MANIPULATION',
          decision: 'BLOCK',
          bypassed: false,
          iteration: 3,
          children: [],
        },
      ],
    },
    {
      node_id: 'atk_authority_seed',
      attack_id: 'atk_authority_seed',
      parent_id: 'atk_ipi_seed',
      depth: 1,
      attack_type: 'AUTHORITY_ESCALATION',
      decision: 'BLOCK',
      bypassed: false,
      iteration: 4,
      children: [],
    },
    {
      node_id: 'atk_tool_seed',
      attack_id: 'atk_tool_seed',
      parent_id: 'atk_ipi_seed',
      depth: 1,
      attack_type: 'TOOL_POISONING',
      decision: 'BLOCK',
      bypassed: false,
      iteration: 5,
      children: [],
    },
  ],
};

// ─── Incidents ────────────────────────────────────────────────────────────

export const DEMO_INCIDENTS: Incident[] = [
  {
    incident_id: 'inc_001',
    incident_type: 'CAPABILITY_VIOLATION',
    severity: 'CRITICAL',
    agent_id: 'agt_data',
    resource_name: 'CustomerPIIVault',
    tool_name: 'customer_db_read',
    decision: 'BLOCK',
    executed: false,
    trace_id: 'trc_8f31a2b4',
    attack_id: 'atk_ipi_001',
    status: 'CONTAINED',
    description: 'Tainted context from External MCP propagated to DataAgent attempting PII vault access. BLOCKED by taint boundary policy.',
    timestamp: new Date(Date.now() - 2 * 1000).toISOString(),
  },
  {
    incident_id: 'inc_002',
    incident_type: 'BYPASS_DETECTED',
    severity: 'HIGH',
    agent_id: 'agt_data',
    resource_name: 'CustomerPIIVault',
    tool_name: 'customer_db_read',
    decision: 'ALLOW',
    executed: true,
    attack_id: 'atk_vuln_ctrl',
    status: 'RESOLVED',
    description: 'Controlled vulnerable target: bypass detected in VulnerableDemoTarget. Regression created. Secured replay confirmed BLOCK. sensitive_db_calls=0.',
    timestamp: new Date(Date.now() - 8 * 60 * 1000).toISOString(),
  },
];

// ─── Regressions ──────────────────────────────────────────────────────────

export const DEMO_REGRESSIONS: Regression[] = [
  {
    regression_id: 'reg_001',
    attack_type: 'DIRECT_PROMPT_INJECTION',
    attack_id: 'atk_vuln_ctrl',
    expected_decision: 'BLOCK',
    observed_decision: 'ALLOW',
    current_decision: 'BLOCK',
    replay_decision: 'BLOCK',
    secured: true,
    mutation_lineage: ['atk_vuln_seed', 'atk_vuln_ctrl'],
    sensitive_db_calls_before: 1,
    sensitive_db_calls_after: 0,
    created_at: new Date(Date.now() - 8 * 60 * 1000).toISOString(),
  },
];

// ─── Forensic Explanation ─────────────────────────────────────────────────

export const DEMO_FORENSIC_EXPLANATION: ForensicExplanation = {
  explanation_id: 'exp_block_001',
  agent_id: 'agt_data',
  tool_name: 'customer_db_read',
  resource_name: 'CustomerPIIVault',
  resource_sensitivity: 'CRITICAL',
  original_intent: 'Generate quarterly financial analysis report for FY2026',
  context_trust: 'UNTRUSTED',
  taint_state: 'TAINTED',
  delegated_authority: ['financial_extract'],
  requested_capability: 'customer_db.read',
  effective_authority: 'DENIED',
  policy_decision: 'BLOCK',
  policy_reason_code: 'TAINTED_CONTEXT_INTO_SENSITIVE_SINK',
  policy_explanation: 'Context received from EXTERNAL_MCP classified as UNTRUSTED and propagated TAINTED state. Requested access to CRITICAL resource CustomerPIIVault. Effective authority does not contain customer_db.read. Monotonic delegation containment violated. Taint boundary policy enforced.',
  ai_secura_summary: 'Indirect Prompt Injection detected — CRITICAL risk. Intent VIOLATED. Authority VIOLATED. Recommendation: BLOCK.',
  apiris_summary: 'customer_db.read — HIGH security risk. Anomaly detected. Elevated authorization required.',
  tool_executed: false,
  execution_count: 0,
  sensitive_db_calls: 0,
  bypass_detected: false,
};

// ─── Access Matrix ────────────────────────────────────────────────────────

export const DEMO_ACCESS_MATRIX: AccessMatrix = {
  matrix_id: 'mat_001',
  agents: ['agt_planner', 'agt_research', 'agt_analysis', 'agt_data'],
  resources: ['PublicWeb', 'EnterpriseFinancialWarehouse', 'CustomerPIIVault'],
  effective_permissions: {
    agt_planner: { PublicWeb: true, EnterpriseFinancialWarehouse: true, CustomerPIIVault: false },
    agt_research: { PublicWeb: true, EnterpriseFinancialWarehouse: false, CustomerPIIVault: false },
    agt_analysis: { PublicWeb: false, EnterpriseFinancialWarehouse: false, CustomerPIIVault: false },
    agt_data: { PublicWeb: false, EnterpriseFinancialWarehouse: true, CustomerPIIVault: false },
  },
  table: {
    agt_planner: { PublicWeb: 'YES (accessed)', EnterpriseFinancialWarehouse: 'YES (accessed)', CustomerPIIVault: 'NO' },
    agt_research: { PublicWeb: 'YES (accessed)', EnterpriseFinancialWarehouse: 'NO', CustomerPIIVault: 'ATTEMPTED (blocked)' },
    agt_analysis: { PublicWeb: 'NO', EnterpriseFinancialWarehouse: 'NO', CustomerPIIVault: 'NO' },
    agt_data: { PublicWeb: 'NO', EnterpriseFinancialWarehouse: 'YES', CustomerPIIVault: 'ATTEMPTED (blocked)' },
  },
};

// ─── MCP Servers ──────────────────────────────────────────────────────────

export const DEMO_MCP_SERVERS: MCPServer[] = [
  {
    server_id: 'mcp_external',
    name: 'External Research MCP',
    uri: 'mcp://external-research.untrusted/v1',
    trust_level: 'untrusted',
    tools: ['search', 'document_fetch', 'financial_search'],
    total_requests: 8,
    blocked_requests: 3,
    incidents: 1,
    last_seen: new Date(Date.now() - 12 * 1000).toISOString(),
    risk_level: 'CRITICAL',
  },
];

// ─── Policies ─────────────────────────────────────────────────────────────

export const DEMO_POLICIES: PolicyRule[] = [
  {
    policy_id: 'p_tainted_sink',
    name: 'Taint Boundary — Sensitive Sink Protection',
    description: 'Block tainted context from reaching CRITICAL or HIGH sensitivity resources',
    enabled: true,
    action: 'BLOCK',
    conditions: ['context.taint_state == TAINTED', 'tool.sensitivity in [CRITICAL, HIGH]'],
  },
  {
    policy_id: 'p_monotonic_delegation',
    name: 'Monotonic Authority Containment',
    description: 'Agents cannot exercise capabilities not present in their authority chain',
    enabled: true,
    action: 'BLOCK',
    conditions: ['requested_capability NOT IN effective_capabilities'],
  },
  {
    policy_id: 'p_trust_level',
    name: 'Trust-Level Gate',
    description: 'Untrusted agents cannot access HIGH or CRITICAL resources',
    enabled: true,
    action: 'BLOCK',
    conditions: ['agent.trust_level == untrusted', 'tool.sensitivity in [CRITICAL, HIGH]'],
  },
  {
    policy_id: 'p_delegation_validity',
    name: 'Delegation Validity Check',
    description: 'Expired or revoked delegations do not grant authority',
    enabled: true,
    action: 'BLOCK',
    conditions: ['delegation.status in [expired, revoked]'],
  },
];

// ─── Health ───────────────────────────────────────────────────────────────

export const DEMO_HEALTH: HealthStatus = {
  status: 'ok',
  version: '0.4.0',
  timestamp: new Date().toISOString(),
  components: {
    forensic_service: 'ok',
    authority_graph: 'ok',
    access_graph: 'ok',
    storage: 'ok',
    ai_secura: 'ok',
    apiris: 'ok',
    policy_engine: 'ok',
  },
};

// ─── Metrics ──────────────────────────────────────────────────────────────

export const DEMO_METRICS: Metrics = {
  total_agents: 5,
  total_attacks: 70,
  bypass_rate: 0.0,
  block_rate: 1.0,
  sensitive_prevention_rate: 1.0,
};

// ─── Time series for charts ───────────────────────────────────────────────

export function generateTimeSeriesData(
  points: number = 24,
  baseBlocked: number = 8,
  baseAllowed: number = 30,
) {
  return Array.from({ length: points }, (_, i) => {
    const hour = new Date(Date.now() - (points - i) * 60 * 60 * 1000);
    return {
      time: hour.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      blocked: Math.floor(baseBlocked + Math.random() * 5),
      allowed: Math.floor(baseAllowed + Math.random() * 15),
      hitl: Math.floor(Math.random() * 3),
      tainted: Math.floor(Math.random() * 4),
    };
  });
}

export const DECISION_TIME_SERIES = generateTimeSeriesData(24);

// ─── Attack Node positions for React Flow ─────────────────────────────────

export const ATTACK_FLOW_NODES = [
  { id: 'user', type: 'graphNode', position: { x: 400, y: 0 }, data: { label: 'User (CFO)', type: 'user', trust: 'high', status: 'ok' } },
  { id: 'planner', type: 'graphNode', position: { x: 400, y: 100 }, data: { label: 'PlannerAgent', type: 'agent', trust: 'high', status: 'ok' } },
  { id: 'research', type: 'graphNode', position: { x: 400, y: 200 }, data: { label: 'ResearchAgent', type: 'agent', trust: 'medium', status: 'warn' } },
  { id: 'mcp', type: 'graphNode', position: { x: 400, y: 300 }, data: { label: 'External MCP', type: 'mcp', trust: 'untrusted', status: 'danger' } },
  { id: 'context', type: 'graphNode', position: { x: 600, y: 300 }, data: { label: 'Malicious Context', type: 'context', taint: 'TAINTED', status: 'danger' } },
  { id: 'analysis', type: 'graphNode', position: { x: 400, y: 400 }, data: { label: 'AnalysisAgent', type: 'agent', trust: 'medium', taint: 'TAINTED', status: 'warn' } },
  { id: 'dataagent', type: 'graphNode', position: { x: 400, y: 500 }, data: { label: 'DataAgent', type: 'agent', trust: 'high', taint: 'TAINTED', status: 'danger' } },
  { id: 'tool', type: 'graphNode', position: { x: 400, y: 600 }, data: { label: 'customer_db_read', type: 'tool', sensitivity: 'CRITICAL', status: 'blocked' } },
  { id: 'policy', type: 'graphNode', position: { x: 400, y: 700 }, data: { label: 'Policy Engine', type: 'policy', status: 'block' } },
  { id: 'resource', type: 'graphNode', position: { x: 600, y: 700 }, data: { label: 'CustomerPIIVault', type: 'resource', sensitivity: 'CRITICAL', status: 'protected' } },
];

export const ATTACK_FLOW_EDGES = [
  { id: 'e-user-planner', source: 'user', target: 'planner', label: 'initiates', animated: false },
  { id: 'e-planner-research', source: 'planner', target: 'research', label: 'delegates', animated: false },
  { id: 'e-research-mcp', source: 'research', target: 'mcp', label: 'requests', animated: false },
  { id: 'e-mcp-context', source: 'mcp', target: 'context', label: 'injects', animated: true },
  { id: 'e-context-analysis', source: 'context', target: 'analysis', label: 'taints', animated: true },
  { id: 'e-research-analysis', source: 'research', target: 'analysis', label: 'propagates', animated: true },
  { id: 'e-analysis-data', source: 'analysis', target: 'dataagent', label: 'caused', animated: true },
  { id: 'e-data-tool', source: 'dataagent', target: 'tool', label: 'attempts', animated: true },
  { id: 'e-tool-policy', source: 'tool', target: 'policy', label: 'evaluated', animated: false },
  { id: 'e-policy-resource', source: 'policy', target: 'resource', label: 'BLOCKED', animated: false },
];
