'use client';

import { useState } from 'react';
import { ScrollText, Shield, AlertTriangle, CheckCircle2, Sliders, Play, Code } from 'lucide-react';
import { PageHeader } from '@/components/ui/PageHeader';
import { MetricCard } from '@/components/ui/MetricCard';
import { FilterBar } from '@/components/ui/FilterBar';
import { DataTable } from '@/components/ui/DataTable';
import { StatusBadge } from '@/components/ui/StatusBadge';
import { DetailDrawer } from '@/components/ui/DetailDrawer';

interface PolicyItem {
  policy_id: string;
  name: string;
  description: string;
  enabled: boolean;
  priority: number;
  action: 'BLOCK' | 'HITL' | 'ALLOW' | 'MONITOR';
  triggers: string[];
  conditions: string[];
  matched_count_24h: number;
  last_triggered: string | null;
  tags: string[];
}

const DEMO_POLICIES: PolicyItem[] = [
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

export default function PoliciesPage() {
  const [search, setSearch] = useState('');
  const [actionFilter, setActionFilter] = useState('ALL');
  const [selectedPolicy, setSelectedPolicy] = useState<PolicyItem | null>(null);

  const blockCount = DEMO_POLICIES.filter(p => p.action === 'BLOCK').length;
  const hitlCount = DEMO_POLICIES.filter(p => p.action === 'HITL').length;
  const totalMatches = DEMO_POLICIES.reduce((s, p) => s + p.matched_count_24h, 0);

  const filtered = DEMO_POLICIES.filter(p => {
    const matchSearch =
      p.name.toLowerCase().includes(search.toLowerCase()) ||
      p.description.toLowerCase().includes(search.toLowerCase()) ||
      p.policy_id.toLowerCase().includes(search.toLowerCase());

    const matchAction = actionFilter === 'ALL' || p.action === actionFilter;

    return matchSearch && matchAction;
  });

  const columns = [
    {
      key: 'name',
      header: 'Policy Rule',
      render: (row: PolicyItem) => (
        <div className="flex items-center gap-2.5">
          <div className="w-7 h-7 rounded-md bg-slate-100 flex items-center justify-center text-slate-600 border border-slate-200">
            <ScrollText size={13} />
          </div>
          <div>
            <div className="font-semibold text-xs text-slate-900">{row.name}</div>
            <div className="text-[11px] font-mono text-slate-500">{row.policy_id}</div>
          </div>
        </div>
      ),
    },
    {
      key: 'action',
      header: 'Enforcement Action',
      width: '130px',
      render: (row: PolicyItem) => (
        <StatusBadge status={row.action} />
      ),
    },
    {
      key: 'priority',
      header: 'Priority',
      width: '90px',
      render: (row: PolicyItem) => (
        <span className="font-mono text-xs text-slate-600 font-semibold bg-slate-100 px-2 py-0.5 rounded border border-slate-200">
          P{row.priority}
        </span>
      ),
    },
    {
      key: 'triggers',
      header: 'Target Triggers',
      render: (row: PolicyItem) => (
        <div className="flex flex-wrap gap-1 max-w-xs">
          {row.triggers.map(t => (
            <span key={t} className="font-mono text-[11px] px-1.5 py-0.2 rounded bg-slate-100 text-slate-700 border border-slate-200">
              {t}
            </span>
          ))}
        </div>
      ),
    },
    {
      key: 'matched_count_24h',
      header: 'Matches (24h)',
      width: '120px',
      render: (row: PolicyItem) => (
        <span className="font-mono text-xs text-slate-700">{row.matched_count_24h}</span>
      ),
    },
    {
      key: 'enabled',
      header: 'State',
      width: '100px',
      render: (row: PolicyItem) => (
        <span className={`text-[11px] font-medium px-2 py-0.5 rounded border ${
          row.enabled ? 'bg-emerald-50 text-emerald-700 border-emerald-200' : 'bg-slate-100 text-slate-500 border-slate-200'
        }`}>
          {row.enabled ? 'Active' : 'Disabled'}
        </span>
      ),
    },
  ];

  return (
    <div className="p-8 space-y-6 max-w-7xl mx-auto">
      <PageHeader
        title="Security Policies"
        subtitle="Deterministic rules and invariants enforced automatically with zero AI hallucination"
        badge="Zero-Trust Engine"
      />

      {/* KPI Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <MetricCard label="Active Policies" value={DEMO_POLICIES.filter(p => p.enabled).length} />
        <MetricCard label="Block Rules" value={blockCount} status="BLOCK" />
        <MetricCard label="HITL Guardrails" value={hitlCount} status="HITL" />
        <MetricCard label="Trigger Matches (24h)" value={totalMatches} status="ALLOW" />
      </div>

      {/* Filter and Table */}
      <div className="bg-white border border-slate-200 rounded-lg p-5 shadow-xs space-y-4">
        <FilterBar
          searchQuery={search}
          onSearchChange={setSearch}
          searchPlaceholder="Search policies by name, ID, or trigger..."
          filters={[
            {
              key: 'action',
              label: 'Action',
              options: [
                { label: 'All Actions', value: 'ALL' },
                { label: 'Block', value: 'BLOCK' },
                { label: 'HITL', value: 'HITL' },
                { label: 'Allow', value: 'ALLOW' },
                { label: 'Monitor', value: 'MONITOR' },
              ],
              value: actionFilter,
              onChange: setActionFilter,
            },
          ]}
          activeCount={actionFilter !== 'ALL' || search ? 1 : 0}
          onReset={() => {
            setSearch('');
            setActionFilter('ALL');
          }}
        />

        <DataTable
          columns={columns}
          data={filtered}
          keyField="policy_id"
          onRowClick={(row) => setSelectedPolicy(row)}
          emptyMessage="No security policies matched your filter criteria."
        />
      </div>

      {/* Policy Detail Drawer */}
      <DetailDrawer
        isOpen={!!selectedPolicy}
        onClose={() => setSelectedPolicy(null)}
        title={selectedPolicy ? selectedPolicy.name : ''}
        subtitle={selectedPolicy ? `ID: ${selectedPolicy.policy_id} • Priority P${selectedPolicy.priority}` : ''}
        badge={selectedPolicy ? <StatusBadge status={selectedPolicy.action} /> : null}
      >
        {selectedPolicy && (
          <div className="space-y-6">
            {/* Description */}
            <div className="bg-slate-50 border border-slate-200 rounded-lg p-3.5 space-y-2">
              <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">Policy Intent</div>
              <p className="text-xs text-slate-800 leading-relaxed">{selectedPolicy.description}</p>
            </div>

            {/* Triggers */}
            <div>
              <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-500 mb-2">Attached Triggers</div>
              <div className="flex flex-wrap gap-1.5">
                {selectedPolicy.triggers.map(t => (
                  <span key={t} className="font-mono text-xs px-2 py-0.5 rounded bg-blue-50 text-blue-800 border border-blue-200 font-medium">
                    {t}
                  </span>
                ))}
              </div>
            </div>

            {/* Predicate Expressions */}
            <div>
              <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-500 mb-2">Predicate Expressions</div>
              <div className="space-y-1.5">
                {selectedPolicy.conditions.map((cond, i) => (
                  <div key={i} className="p-2.5 bg-slate-900 text-slate-100 rounded-md font-mono text-xs border border-slate-800 flex items-center gap-2">
                    <span className="text-slate-500">IF:</span>
                    <span className="text-sky-300">{cond}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Tags & Metadata */}
            <div>
              <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-500 mb-2">Tags</div>
              <div className="flex flex-wrap gap-1.5">
                {selectedPolicy.tags.map(tag => (
                  <span key={tag} className="text-xs px-2 py-0.5 rounded bg-slate-100 text-slate-700 border border-slate-200">
                    #{tag}
                  </span>
                ))}
              </div>
            </div>

            {/* Evaluation stats */}
            <div className="border-t border-slate-200 pt-4 grid grid-cols-2 gap-3 text-xs">
              <div className="p-3 bg-slate-50 border border-slate-200 rounded-lg text-center">
                <div className="text-[10px] text-slate-500 uppercase">Matches (24h)</div>
                <div className="text-base font-bold font-mono text-slate-800">{selectedPolicy.matched_count_24h}</div>
              </div>
              <div className="p-3 bg-slate-50 border border-slate-200 rounded-lg text-center">
                <div className="text-[10px] text-slate-500 uppercase">Last Fired</div>
                <div className="text-xs font-mono text-slate-700 mt-1">
                  {selectedPolicy.last_triggered ? new Date(selectedPolicy.last_triggered).toLocaleTimeString() : 'Never'}
                </div>
              </div>
            </div>
          </div>
        )}
      </DetailDrawer>
    </div>
  );
}
