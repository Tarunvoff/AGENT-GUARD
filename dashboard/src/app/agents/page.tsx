'use client';

import React, { useState, useMemo } from 'react';
import { PageHeader } from '@/components/ui/PageHeader';
import { FilterBar } from '@/components/ui/FilterBar';
import { DataTable, Column } from '@/components/ui/DataTable';
import { TrustBadge, SeverityBadge } from '@/components/ui/StatusBadge';
import { DetailDrawer } from '@/components/ui/DetailDrawer';
import { User, Shield, Key, Share2, Wrench, CheckCircle2, Lock, Activity } from 'lucide-react';

interface AgentRecord {
  agent_id: string;
  name: string;
  role: string;
  status: 'ACTIVE' | 'QUARANTINED' | 'STANDBY';
  trust_level: string;
  authority_scope: string;
  active_tasks: number;
  tools_count: number;
  risk_rating: string;
  last_activity: string;
  capabilities: string[];
  parent_agent?: string;
  allowed_resources: string[];
}

const DEMO_AGENTS: AgentRecord[] = [
  {
    agent_id: 'agt_orch001',
    name: 'orchestrator-001',
    role: 'Central Workflow Orchestrator',
    status: 'ACTIVE',
    trust_level: 'HIGH',
    authority_scope: 'delegate, report_generation',
    active_tasks: 2,
    tools_count: 5,
    risk_rating: 'LOW',
    last_activity: '1 min ago',
    capabilities: ['delegate', 'report_generation', 'task_dispatch'],
    allowed_resources: ['task_queue', 'internal_docs', 'reporting_bucket'],
  },
  {
    agent_id: 'agt_res002',
    name: 'research-agent-001',
    role: 'Market & Web Research Worker',
    status: 'ACTIVE',
    trust_level: 'MEDIUM',
    authority_scope: 'public_search, sec_filings (read-only)',
    active_tasks: 1,
    tools_count: 3,
    risk_rating: 'MEDIUM',
    last_activity: '3 mins ago',
    capabilities: ['public_search', 'sec_filings_read'],
    parent_agent: 'orchestrator-001',
    allowed_resources: ['public_web', 'sec_cache'],
  },
  {
    agent_id: 'agt_ana003',
    name: 'analysis-agent-001',
    role: 'Financial Analytics & Metrics Agent',
    status: 'ACTIVE',
    trust_level: 'HIGH',
    authority_scope: 'data_analysis, metrics_read',
    active_tasks: 1,
    tools_count: 4,
    risk_rating: 'LOW',
    last_activity: 'Just now',
    capabilities: ['data_analysis', 'metrics_read', 'chart_render'],
    parent_agent: 'orchestrator-001',
    allowed_resources: ['finance_ledger', 'metrics_store'],
  },
  {
    agent_id: 'agt_ext009',
    name: 'external-mcp-agent',
    role: 'Third-Party Ingestion Bot',
    status: 'QUARANTINED',
    trust_level: 'UNTRUSTED',
    authority_scope: 'none (revoked by incident INC-1048)',
    active_tasks: 0,
    tools_count: 1,
    risk_rating: 'CRITICAL',
    last_activity: '45 mins ago',
    capabilities: ['untrusted_ingest'],
    allowed_resources: [],
  },
];

export default function AgentsPage() {
  const [search, setSearch] = useState('');
  const [trustFilter, setTrustFilter] = useState('ALL');
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [selectedAgent, setSelectedAgent] = useState<AgentRecord | null>(DEMO_AGENTS[0]);
  const [isDrawerOpen, setIsDrawerOpen] = useState(false);

  const filteredData = useMemo(() => {
    return DEMO_AGENTS.filter((item) => {
      if (search) {
        const q = search.toLowerCase();
        const match =
          item.agent_id.toLowerCase().includes(q) ||
          item.name.toLowerCase().includes(q) ||
          item.role.toLowerCase().includes(q) ||
          item.authority_scope.toLowerCase().includes(q);
        if (!match) return false;
      }
      if (trustFilter !== 'ALL' && item.trust_level !== trustFilter) return false;
      if (statusFilter !== 'ALL' && item.status !== statusFilter) return false;
      return true;
    });
  }, [search, trustFilter, statusFilter]);

  const columns: Column<AgentRecord>[] = [
    {
      key: 'name',
      header: 'Agent Identity',
      render: (row) => (
        <div>
          <div className="font-semibold text-slate-900 flex items-center gap-1.5">
            <span>{row.name}</span>
          </div>
          <div className="font-mono text-[10px] text-slate-400">{row.agent_id}</div>
        </div>
      ),
    },
    {
      key: 'status',
      header: 'Status',
      width: '120px',
      render: (row) => (
        <span
          className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold ${
            row.status === 'ACTIVE'
              ? 'bg-emerald-50 text-emerald-800 border border-emerald-200'
              : 'bg-red-50 text-red-800 border border-red-200'
          }`}
        >
          <span className={`w-1.5 h-1.5 rounded-full ${row.status === 'ACTIVE' ? 'bg-emerald-600' : 'bg-red-600'}`} />
          {row.status}
        </span>
      ),
    },
    {
      key: 'trust_level',
      header: 'Trust Level',
      width: '110px',
      render: (row) => <TrustBadge trust={row.trust_level} />,
    },
    {
      key: 'authority_scope',
      header: 'Declared Authority Scope',
      render: (row) => <span className="font-mono text-[11px] text-slate-600">{row.authority_scope}</span>,
    },
    {
      key: 'active_tasks',
      header: 'Tasks',
      align: 'center',
      width: '70px',
      render: (row) => <span className="font-mono font-semibold text-slate-800">{row.active_tasks}</span>,
    },
    {
      key: 'tools_count',
      header: 'Tools',
      align: 'center',
      width: '70px',
      render: (row) => <span className="font-mono text-slate-600">{row.tools_count}</span>,
    },
    {
      key: 'risk_rating',
      header: 'Risk',
      width: '90px',
      render: (row) => <SeverityBadge severity={row.risk_rating} />,
    },
    {
      key: 'last_activity',
      header: 'Last Activity',
      align: 'right',
      width: '110px',
      render: (row) => <span className="text-slate-400 text-[11px]">{row.last_activity}</span>,
    },
  ];

  return (
    <div className="max-w-[1600px] mx-auto">
      <PageHeader
        title="Agents"
        description="Catalog of registered autonomous agents, cryptographic identities, delegated authority scopes, and continuous behavioral baselines."
        breadcrumbs={[
          { label: 'Operations', href: '/dashboard' },
          { label: 'Agents' },
        ]}
      />

      <FilterBar
        searchQuery={search}
        onSearchChange={setSearch}
        searchPlaceholder="Search agents by ID, name, capability…"
        totalCount={DEMO_AGENTS.length}
        activeCount={filteredData.length}
        onReset={() => {
          setSearch('');
          setTrustFilter('ALL');
          setStatusFilter('ALL');
        }}
        dropdowns={[
          {
            name: 'trust',
            label: 'Trust',
            value: trustFilter,
            onChange: setTrustFilter,
            options: [
              { label: 'All Trust Levels', value: 'ALL' },
              { label: 'HIGH', value: 'HIGH' },
              { label: 'MEDIUM', value: 'MEDIUM' },
              { label: 'UNTRUSTED', value: 'UNTRUSTED' },
            ],
          },
          {
            name: 'status',
            label: 'Status',
            value: statusFilter,
            onChange: setStatusFilter,
            options: [
              { label: 'All Statuses', value: 'ALL' },
              { label: 'ACTIVE', value: 'ACTIVE' },
              { label: 'QUARANTINED', value: 'QUARANTINED' },
            ],
          },
        ]}
      />

      <DataTable
        columns={columns}
        data={filteredData}
        keyExtractor={(item) => item.agent_id}
        onRowClick={(item) => {
          setSelectedAgent(item);
          setIsDrawerOpen(true);
        }}
        selectedKey={selectedAgent?.agent_id}
      />

      {/* Agent Detail Drawer */}
      <DetailDrawer
        isOpen={isDrawerOpen}
        onClose={() => setIsDrawerOpen(false)}
        title={`Agent: ${selectedAgent?.name}`}
        subtitle={selectedAgent?.agent_id}
        badge={selectedAgent && <TrustBadge trust={selectedAgent.trust_level} />}
      >
        {selectedAgent && (
          <div className="space-y-5 text-xs">
            {/* Metadata Summary */}
            <div className="grid grid-cols-2 gap-3 p-3 bg-slate-50 border border-slate-200 rounded-lg">
              <div>
                <span className="text-[10px] uppercase font-bold text-slate-400 block">STATUS</span>
                <span className="font-semibold text-slate-900">{selectedAgent.status}</span>
              </div>
              <div>
                <span className="text-[10px] uppercase font-bold text-slate-400 block">ROLE</span>
                <span className="text-slate-700">{selectedAgent.role}</span>
              </div>
              <div>
                <span className="text-[10px] uppercase font-bold text-slate-400 block">PARENT AGENT</span>
                <span className="font-mono text-slate-800">{selectedAgent.parent_agent || 'Root (None)'}</span>
              </div>
              <div>
                <span className="text-[10px] uppercase font-bold text-slate-400 block">RISK POSTURE</span>
                <SeverityBadge severity={selectedAgent.risk_rating} />
              </div>
            </div>

            {/* Declared Capabilities */}
            <div>
              <div className="text-[11px] font-bold uppercase tracking-wider text-slate-500 mb-2 flex items-center gap-1.5">
                <Key size={13} className="text-slate-400" />
                <span>Declared Capabilities</span>
              </div>
              <div className="flex flex-wrap gap-1.5">
                {selectedAgent.capabilities.map((cap) => (
                  <span key={cap} className="px-2 py-1 bg-slate-100 border border-slate-200 text-slate-800 font-mono text-[11px] rounded">
                    {cap}
                  </span>
                ))}
              </div>
            </div>

            {/* Accessible Resources */}
            <div>
              <div className="text-[11px] font-bold uppercase tracking-wider text-slate-500 mb-2 flex items-center gap-1.5">
                <Lock size={13} className="text-slate-400" />
                <span>Reachable Resources</span>
              </div>
              <div className="bg-slate-50 border border-slate-200 rounded-lg p-3 space-y-1.5">
                {selectedAgent.allowed_resources.length > 0 ? (
                  selectedAgent.allowed_resources.map((res) => (
                    <div key={res} className="flex items-center gap-1.5 text-slate-700 font-mono text-[11px]">
                      <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
                      <span>{res}</span>
                    </div>
                  ))
                ) : (
                  <span className="text-slate-400 italic">No resources accessible</span>
                )}
              </div>
            </div>

            {/* Behavioral Baseline */}
            <div>
              <div className="text-[11px] font-bold uppercase tracking-wider text-slate-500 mb-2 flex items-center gap-1.5">
                <Activity size={13} className="text-slate-400" />
                <span>Behavioral Baseline</span>
              </div>
              <div className="p-3 bg-white border border-slate-200 rounded-lg space-y-1.5">
                <div className="flex justify-between text-[11px]">
                  <span className="text-slate-500">Anomaly Rate</span>
                  <span className="font-mono font-bold text-emerald-700">0.0% (Stable)</span>
                </div>
                <div className="flex justify-between text-[11px]">
                  <span className="text-slate-500">Entropy Score</span>
                  <span className="font-mono text-slate-800">1.21 / 5.0</span>
                </div>
              </div>
            </div>
          </div>
        )}
      </DetailDrawer>
    </div>
  );
}
