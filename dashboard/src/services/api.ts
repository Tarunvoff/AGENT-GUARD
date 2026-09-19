// AgentGuard API Service — abstraction over backend endpoints
// Falls back to mock data in development

import type {
  Agent, AgentAccessProfile, Resource, Task, Delegation, Context,
  SecurityEvent, Attack, Campaign, Incident, Regression, Overview, Metrics,
  AccessMatrix, AccessSnapshot, ForensicExplanation, MutationNode,
  MCPServer, PolicyRule, HealthStatus, PolicyDecision,
} from '@/types';

import * as demo from '@/data/demo';

const BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';
const USE_MOCK = process.env.NEXT_PUBLIC_USE_MOCK !== 'false';

async function apiFetch<T>(path: string, fallback: T): Promise<T> {
  if (USE_MOCK) return fallback;
  try {
    const res = await fetch(`${BASE_URL}${path}`, {
      headers: { 'Accept': 'application/json' },
      next: { revalidate: 5 },
    });
    if (!res.ok) return fallback;
    return res.json() as T;
  } catch {
    return fallback;
  }
}

// ─── Health ───────────────────────────────────────────────────────────────

export async function getHealth(): Promise<HealthStatus> {
  return apiFetch('/api/v1/health', demo.DEMO_HEALTH);
}

// ─── Overview ─────────────────────────────────────────────────────────────

export async function getOverview(): Promise<Overview> {
  return apiFetch('/api/v1/overview', demo.DEMO_OVERVIEW);
}

export async function getMetrics(): Promise<Metrics> {
  return apiFetch('/api/v1/metrics', demo.DEMO_METRICS);
}

// ─── Agents ───────────────────────────────────────────────────────────────

export async function getAgents(): Promise<Agent[]> {
  return apiFetch('/api/v1/agents', demo.DEMO_AGENTS);
}

export async function getAgent(agentId: string): Promise<Agent | null> {
  return apiFetch(
    `/api/v1/agents/${agentId}`,
    demo.DEMO_AGENTS.find(a => a.agent_id === agentId) ?? null,
  );
}

export async function getAgentAccess(agentId: string): Promise<AgentAccessProfile | null> {
  return apiFetch(
    `/api/v1/agents/${agentId}/access`,
    demo.DEMO_AGENT_PROFILES[agentId] ?? null,
  );
}

export async function getAgentAttempts(agentId: string) {
  return apiFetch(`/api/v1/agents/${agentId}/attempts`, []);
}

export async function getAgentActualAccess(agentId: string) {
  return apiFetch(`/api/v1/agents/${agentId}/actual-access`, []);
}

// ─── Resources ────────────────────────────────────────────────────────────

export async function getResources(): Promise<Resource[]> {
  return apiFetch('/api/v1/resources', demo.DEMO_RESOURCES);
}

export async function getResource(resourceName: string): Promise<Resource | null> {
  return apiFetch(
    `/api/v1/resources/${resourceName}`,
    demo.DEMO_RESOURCES.find(r => r.name === resourceName) ?? null,
  );
}

// ─── Tasks ────────────────────────────────────────────────────────────────

export async function getTasks(): Promise<Task[]> {
  return apiFetch('/api/v1/tasks', demo.DEMO_TASKS);
}

export async function getTask(taskId: string): Promise<Task | null> {
  return apiFetch(
    `/api/v1/tasks/${taskId}`,
    demo.DEMO_TASKS.find(t => t.task_id === taskId) ?? null,
  );
}

// ─── Delegations ──────────────────────────────────────────────────────────

export async function getDelegations(): Promise<Delegation[]> {
  return apiFetch('/api/v1/delegations', demo.DEMO_DELEGATIONS);
}

// ─── Security Events ──────────────────────────────────────────────────────

export async function getEvents(limit: number = 50): Promise<SecurityEvent[]> {
  return apiFetch('/api/v1/events', demo.DEMO_EVENTS.slice(0, limit));
}

// ─── Attacks ──────────────────────────────────────────────────────────────

export async function getAttacks(): Promise<Attack[]> {
  return apiFetch('/api/v1/attacks', demo.DEMO_ATTACKS);
}

export async function getAttack(attackId: string): Promise<Attack | null> {
  return apiFetch(
    `/api/v1/attacks/${attackId}`,
    demo.DEMO_ATTACKS.find(a => a.attack_id === attackId) ?? null,
  );
}

export async function getAttackForensics(attackId: string): Promise<ForensicExplanation | null> {
  return apiFetch(
    `/api/v1/attacks/${attackId}/forensics`,
    attackId === 'atk_ipi_001' ? demo.DEMO_FORENSIC_EXPLANATION : null,
  );
}

// ─── Campaigns ────────────────────────────────────────────────────────────

export async function getCampaigns(): Promise<Campaign[]> {
  return apiFetch('/api/v1/campaigns', demo.DEMO_CAMPAIGNS);
}

// ─── Incidents ────────────────────────────────────────────────────────────

export async function getIncidents(): Promise<Incident[]> {
  return apiFetch('/api/v1/incidents', demo.DEMO_INCIDENTS);
}

export async function getIncident(incidentId: string): Promise<Incident | null> {
  return apiFetch(
    `/api/v1/incidents/${incidentId}`,
    demo.DEMO_INCIDENTS.find(i => i.incident_id === incidentId) ?? null,
  );
}

// ─── Regressions ──────────────────────────────────────────────────────────

export async function getRegressions(): Promise<Regression[]> {
  return apiFetch('/api/v1/regressions', demo.DEMO_REGRESSIONS);
}

// ─── Forensics ────────────────────────────────────────────────────────────

export async function getForensicExplanation(agentId: string, toolName: string) {
  return apiFetch(
    `/api/v1/forensics/explain?agent_id=${agentId}&tool_name=${toolName}`,
    agentId === 'agt_data' ? demo.DEMO_FORENSIC_EXPLANATION : null,
  );
}

// ─── Access Matrix ────────────────────────────────────────────────────────

export async function getAccessMatrix(): Promise<AccessMatrix> {
  return apiFetch('/api/v1/access/matrix', demo.DEMO_ACCESS_MATRIX);
}

export async function getSnapshots(): Promise<AccessSnapshot[]> {
  return apiFetch('/api/v1/access/snapshots', []);
}

// ─── Policies ────────────────────────────────────────────────────────────

export async function getPolicies(): Promise<PolicyRule[]> {
  return apiFetch('/api/v1/policies', demo.DEMO_POLICIES);
}

// ─── MCP ─────────────────────────────────────────────────────────────────

export async function getMCPServers(): Promise<MCPServer[]> {
  return apiFetch('/api/v1/mcp', demo.DEMO_MCP_SERVERS);
}

// ─── Websocket / SSE mock event stream ───────────────────────────────────

type EventHandler = (event: SecurityEvent) => void;

const MOCK_STREAM_EVENTS: SecurityEvent[] = [...demo.DEMO_EVENTS];
let streamIndex = 0;
const handlers: EventHandler[] = [];

export function subscribeToEventStream(handler: EventHandler): () => void {
  handlers.push(handler);

  // Emit mock events on interval
  const interval = setInterval(() => {
    const event = MOCK_STREAM_EVENTS[streamIndex % MOCK_STREAM_EVENTS.length];
    const fresh = {
      ...event,
      event_id: `evt_live_${Date.now()}`,
      timestamp: new Date().toISOString(),
    };
    handlers.forEach(h => h(fresh));
    streamIndex++;
  }, 4000);

  return () => {
    clearInterval(interval);
    const idx = handlers.indexOf(handler);
    if (idx >= 0) handlers.splice(idx, 1);
  };
}
