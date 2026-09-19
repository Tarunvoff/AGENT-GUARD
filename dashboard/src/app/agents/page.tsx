'use client';

import { useState } from 'react';
import { DEMO_AGENTS } from '@/data/demo';
import type { Agent } from '@/types';
import { DecisionBadge, TrustBadge, SeverityBadge, CapabilityPill, EmptyState, SectionHeader } from '@/components/ui/security';
import { Users, Search, ChevronRight, Shield, Activity, AlertTriangle } from 'lucide-react';
import Link from 'next/link';
import { formatRelative } from '@/lib/colors';

export default function AgentsPage() {
  const [search, setSearch] = useState('');
  const [filter, setFilter] = useState<string>('all');

  const agents = DEMO_AGENTS.filter(a => {
    const matchSearch = a.name.toLowerCase().includes(search.toLowerCase()) ||
      a.agent_id.toLowerCase().includes(search.toLowerCase());
    const matchFilter = filter === 'all' || a.trust_level === filter || a.status === filter;
    return matchSearch && matchFilter;
  });

  return (
    <div className="p-6 space-y-5 min-h-screen bg-[#090d16]">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-white">Agent Inventory</h1>
          <p className="text-sm text-zinc-500 mt-1">Identity, authority, and trust level for all registered agents</p>
        </div>
        <div className="text-sm text-zinc-500">
          <span className="text-zinc-200 font-semibold">{DEMO_AGENTS.length}</span> agents registered
        </div>
      </div>

      {/* Filters */}
      <div className="flex items-center gap-3">
        <div className="relative flex-1 max-w-sm">
          <Search size={13} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-zinc-600" />
          <input
            type="text"
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Search agents..."
            className="w-full pl-7 pr-3 py-1.5 text-xs bg-zinc-900/60 border border-zinc-800/50 rounded-md text-zinc-200 placeholder:text-zinc-600 focus:outline-none focus:border-sky-500/50"
          />
        </div>
        {['all', 'high', 'medium', 'low', 'untrusted'].map(f => (
          <button
            key={f}
            onClick={() => setFilter(f)}
            className={`px-2.5 py-1 text-[11px] rounded-md font-medium uppercase tracking-wider transition-colors ${
              filter === f
                ? 'bg-sky-500/15 border border-sky-500/30 text-sky-300'
                : 'text-zinc-500 hover:text-zinc-300'
            }`}
          >
            {f}
          </button>
        ))}
      </div>

      {/* Agent grid */}
      <div className="grid grid-cols-2 xl:grid-cols-3 gap-4">
        {agents.map(agent => (
          <AgentCard key={agent.agent_id} agent={agent} />
        ))}
      </div>

      {agents.length === 0 && (
        <EmptyState
          icon={Users}
          title="No agents found"
          description="No agents match your current search and filter criteria."
        />
      )}
    </div>
  );
}

function AgentCard({ agent }: { agent: Agent }) {
  const statusColor = {
    active: 'bg-emerald-400',
    idle: 'bg-zinc-500',
    delegated: 'bg-sky-400',
    blocked: 'bg-red-400',
  }[agent.status];

  const isCritical = agent.risk_level === 'CRITICAL';

  return (
    <Link href={`/agents/${agent.agent_id}`}>
      <div className={`
        rounded-xl border p-4 bg-zinc-900/40 cursor-pointer
        transition-all duration-200 hover:border-zinc-700/60 hover:bg-zinc-900/60 group
        ${isCritical ? 'border-red-500/30 shadow-lg shadow-red-500/5' : 'border-zinc-800/50'}
      `}>
        {/* Header */}
        <div className="flex items-start justify-between mb-3">
          <div className="flex items-center gap-2">
            <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-sky-500/20 to-indigo-600/20 border border-sky-500/20 flex items-center justify-center text-xs font-bold text-sky-300">
              {agent.name.charAt(0)}
            </div>
            <div>
              <div className="text-sm font-semibold text-zinc-200 group-hover:text-white">{agent.name}</div>
              <div className="text-[10px] font-mono text-zinc-600">{agent.agent_id}</div>
            </div>
          </div>
          <div className="flex items-center gap-1.5">
            <div className={`w-1.5 h-1.5 rounded-full ${statusColor}`} />
            <span className="text-[10px] text-zinc-500 capitalize">{agent.status}</span>
          </div>
        </div>

        {/* Trust + Risk */}
        <div className="flex items-center gap-2 mb-3">
          <TrustBadge level={agent.trust_level} />
          {agent.risk_level && (
            <span className={`text-[10px] px-1.5 py-0.5 rounded border font-medium uppercase ${
              agent.risk_level === 'CRITICAL' ? 'border-red-500/30 bg-red-500/10 text-red-400' :
              agent.risk_level === 'HIGH' ? 'border-orange-500/30 bg-orange-500/10 text-orange-400' :
              'border-zinc-700 bg-zinc-800/40 text-zinc-500'
            }`}>
              {agent.risk_level}
            </span>
          )}
        </div>

        {/* Capabilities */}
        <div className="mb-3">
          <div className="text-[10px] text-zinc-600 mb-1.5 uppercase tracking-wider">Capabilities</div>
          <div className="flex flex-wrap gap-1">
            {agent.capabilities.length > 0
              ? agent.capabilities.map(cap => <CapabilityPill key={cap} name={cap} />)
              : <span className="text-[10px] text-zinc-700 italic">No capabilities</span>
            }
          </div>
        </div>

        {/* Task */}
        {agent.current_task_id && (
          <div className="pt-2.5 border-t border-zinc-800/40">
            <div className="text-[10px] text-zinc-600 flex items-center gap-1">
              <Activity size={9} />
              Current task: <span className="font-mono text-zinc-500">{agent.current_task_id}</span>
            </div>
          </div>
        )}

        <div className="flex items-center justify-end mt-2 text-[10px] text-zinc-700 group-hover:text-zinc-500">
          View profile <ChevronRight size={10} className="ml-0.5" />
        </div>
      </div>
    </Link>
  );
}
