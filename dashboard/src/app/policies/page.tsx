'use client';

import { useState } from 'react';
import { ScrollText, Plus, ChevronDown, ChevronRight, Shield, AlertTriangle, CheckCircle2, Edit3, Search } from 'lucide-react';

const DEMO_POLICIES = [
  {
    policy_id: 'pol_no_pii_export',
    name: 'No PII Export',
    description: 'Block any action that would send PII data to external systems or untrusted agents.',
    enabled: true,
    priority: 1,
    action: 'BLOCK',
    triggers: ['export_pii', 'upload_s3', 'send_email'],
    conditions: ['resource.sensitivity == CRITICAL', 'destination.trusted == false'],
    matched_count_24h: 3,
    last_triggered: '2026-09-19T10:30:00Z',
    tags: ['data-protection', 'critical'],
  },
  {
    policy_id: 'pol_hitl_customer_access',
    name: 'HITL on Customer Data Access',
    description: 'Require human approval before any agent reads from the customers table.',
    enabled: true,
    priority: 2,
    action: 'HITL',
    triggers: ['read_db:customers'],
    conditions: ['resource.name == customers', 'agent.trust_level < HIGH'],
    matched_count_24h: 1,
    last_triggered: '2026-09-19T09:11:00Z',
    tags: ['customer-data', 'hitl'],
  },
  {
    policy_id: 'pol_no_untrusted_mcp',
    name: 'Block Untrusted MCP Servers',
    description: 'Prevent any agent from calling tools hosted on unverified external MCP servers.',
    enabled: true,
    priority: 3,
    action: 'BLOCK',
    triggers: ['mcp_tool_call'],
    conditions: ['tool.server.trusted == false'],
    matched_count_24h: 1,
    last_triggered: '2026-09-19T10:45:00Z',
    tags: ['mcp', 'supply-chain'],
  },
  {
    policy_id: 'pol_delegation_depth',
    name: 'Delegation Depth Limit',
    description: 'HITL review required when delegation depth reaches or exceeds 3.',
    enabled: true,
    priority: 4,
    action: 'HITL',
    triggers: ['delegation_chain'],
    conditions: ['delegation.depth >= 3'],
    matched_count_24h: 0,
    last_triggered: null,
    tags: ['delegation', 'containment'],
  },
  {
    policy_id: 'pol_monitor_external_calls',
    name: 'Monitor All External API Calls',
    description: 'Log and monitor any HTTP call to an external service — do not block but alert.',
    enabled: true,
    priority: 5,
    action: 'MONITOR',
    triggers: ['http_call'],
    conditions: ['destination.internal == false'],
    matched_count_24h: 7,
    last_triggered: '2026-09-19T11:05:00Z',
    tags: ['monitoring', 'egress'],
  },
  {
    policy_id: 'pol_allow_internal_read',
    name: 'Allow Internal DB Reads (Permitted Agents)',
    description: 'Permitted agents may read from internal database tables that are not marked CRITICAL.',
    enabled: true,
    priority: 10,
    action: 'ALLOW',
    triggers: ['read_db'],
    conditions: ['resource.sensitivity != CRITICAL', 'agent.id in [orchestrator_v2, data_agent, report_agent]'],
    matched_count_24h: 128,
    last_triggered: '2026-09-19T11:10:00Z',
    tags: ['baseline', 'allow'],
  },
];

const ACTION_STYLES: Record<string, string> = {
  BLOCK: 'text-red-400 border-red-500/30 bg-red-500/10',
  HITL: 'text-amber-400 border-amber-500/20 bg-amber-500/10',
  ALLOW: 'text-emerald-400 border-emerald-500/20 bg-emerald-500/10',
  MONITOR: 'text-sky-400 border-sky-500/20 bg-sky-500/10',
};

export default function PoliciesPage() {
  const [search, setSearch] = useState('');
  const [actionFilter, setActionFilter] = useState('all');
  const [expanded, setExpanded] = useState<string | null>(null);

  const filtered = DEMO_POLICIES.filter(p => {
    const matchSearch = p.name.toLowerCase().includes(search.toLowerCase()) || p.description.toLowerCase().includes(search.toLowerCase());
    const matchAction = actionFilter === 'all' || p.action === actionFilter;
    return matchSearch && matchAction;
  });

  return (
    <div className="p-6 space-y-5 min-h-screen bg-[#090d16]">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-white flex items-center gap-2">
            <ScrollText size={18} className="text-sky-400" />
            Policies
          </h1>
          <p className="text-sm text-zinc-500 mt-1">
            Deterministic security policies — enforcement is <span className="text-emerald-400 font-semibold">never delegated to AI</span>
          </p>
        </div>
        <div className="flex items-center gap-2">
          <div className="rounded-lg bg-emerald-500/10 border border-emerald-500/20 px-3 py-1.5 text-xs text-emerald-400 flex items-center gap-1.5">
            <Shield size={11} />
            {DEMO_POLICIES.filter(p => p.enabled).length} active policies
          </div>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-4 gap-3">
        {[
          { action: 'BLOCK', label: 'Block Policies' },
          { action: 'HITL', label: 'HITL Policies' },
          { action: 'ALLOW', label: 'Allow Policies' },
          { action: 'MONITOR', label: 'Monitor Policies' },
        ].map(({ action, label }) => {
          const style = ACTION_STYLES[action] || '';
          const count = DEMO_POLICIES.filter(p => p.action === action).length;
          return (
            <div key={action} className={`rounded-xl border p-3 text-center ${style}`}>
              <div className="text-[10px] text-zinc-500 uppercase tracking-wider mb-1">{label}</div>
              <div className="text-xl font-bold font-mono">{count}</div>
            </div>
          );
        })}
      </div>

      {/* Search + Filter */}
      <div className="flex gap-3 items-center">
        <div className="relative flex-1 max-w-xs">
          <Search size={13} className="absolute left-3 top-1/2 -translate-y-1/2 text-zinc-500" />
          <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search policies..."
            className="w-full pl-8 pr-3 py-2 bg-zinc-800/60 border border-zinc-700/50 rounded-lg text-sm text-zinc-200 placeholder:text-zinc-600 focus:outline-none focus:border-sky-500/50"
          />
        </div>
        {['all', 'BLOCK', 'HITL', 'ALLOW', 'MONITOR'].map(f => (
          <button key={f} onClick={() => setActionFilter(f)}
            className={`px-2.5 py-1 text-[11px] rounded font-medium uppercase tracking-wider transition-colors ${
              actionFilter === f ? 'bg-sky-500/15 border border-sky-500/30 text-sky-300' : 'text-zinc-500 hover:text-zinc-300'
            }`}>
            {f}
          </button>
        ))}
      </div>

      {/* Policy Cards */}
      <div className="space-y-2">
        {filtered.map(policy => {
          const actionStyle = ACTION_STYLES[policy.action] || '';
          const isExpanded = expanded === policy.policy_id;
          return (
            <div key={policy.policy_id} className="rounded-xl border border-zinc-800/50 bg-zinc-900/30 hover:border-zinc-700/50 transition-colors">
              <div className="p-4">
                <div className="flex items-start gap-3">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1 flex-wrap">
                      <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded border ${actionStyle}`}>{policy.action}</span>
                      <span className="text-[10px] text-zinc-500 font-mono">P{policy.priority}</span>
                      <span className="font-semibold text-sm text-zinc-200">{policy.name}</span>
                      {policy.tags.map(tag => (
                        <span key={tag} className="text-[10px] text-zinc-600 bg-zinc-800/60 px-1.5 py-0.5 rounded">{tag}</span>
                      ))}
                    </div>
                    <p className="text-xs text-zinc-500 mb-2">{policy.description}</p>
                    <div className="flex items-center gap-4 text-xs text-zinc-600">
                      <span>{policy.matched_count_24h} matches (24h)</span>
                      {policy.last_triggered && <span>Last: {new Date(policy.last_triggered).toLocaleTimeString()}</span>}
                      <span className={policy.enabled ? 'text-emerald-400' : 'text-red-400'}>{policy.enabled ? '● ENABLED' : '○ DISABLED'}</span>
                    </div>
                  </div>
                  <button onClick={() => setExpanded(isExpanded ? null : policy.policy_id)} className="text-zinc-600 hover:text-zinc-400 transition-colors flex-shrink-0">
                    {isExpanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                  </button>
                </div>

                {isExpanded && (
                  <div className="mt-3 pt-3 border-t border-zinc-800/50 grid grid-cols-2 gap-4">
                    <div>
                      <div className="text-[10px] uppercase tracking-wider text-zinc-500 mb-2">Triggers</div>
                      {policy.triggers.map(t => (
                        <div key={t} className="font-mono text-[11px] text-orange-300 bg-orange-500/10 border border-orange-500/20 px-2 py-1 rounded mb-1">{t}</div>
                      ))}
                    </div>
                    <div>
                      <div className="text-[10px] uppercase tracking-wider text-zinc-500 mb-2">Conditions</div>
                      {policy.conditions.map(c => (
                        <div key={c} className="font-mono text-[11px] text-sky-300 bg-sky-500/10 border border-sky-500/20 px-2 py-1 rounded mb-1">{c}</div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
