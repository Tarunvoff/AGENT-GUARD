'use client';

import { useState } from 'react';
import { Share2, Shield, AlertTriangle, CheckCircle2, ArrowRight, ShieldAlert, Lock, Clock, Info, ExternalLink } from 'lucide-react';
import { PageHeader } from '@/components/ui/PageHeader';
import { MetricCard } from '@/components/ui/MetricCard';
import { FilterBar } from '@/components/ui/FilterBar';
import { DataTable } from '@/components/ui/DataTable';
import { StatusBadge } from '@/components/ui/StatusBadge';
import { DetailDrawer } from '@/components/ui/DetailDrawer';

interface DelegationChain {
  delegation_id: string;
  from_agent: string;
  to_agent: string;
  authority_granted: string[];
  authority_subset_of: string[];
  constraints: string[];
  valid: boolean;
  depth: number;
  created_at: string;
  expires_at: string | null;
  reason: string;
  violation?: string;
}

const DEMO_DELEGATIONS: DelegationChain[] = [
  {
    delegation_id: 'del_001',
    from_agent: 'orchestrator_v2',
    to_agent: 'data_agent',
    authority_granted: ['read_db', 'query_customers'],
    authority_subset_of: ['read_db', 'query_customers', 'write_db', 'delete_db'],
    constraints: ['read_only', 'no_pii_export'],
    valid: true,
    depth: 1,
    created_at: '2026-09-19T08:00:00Z',
    expires_at: '2026-09-19T18:00:00Z',
    reason: 'Delegated for Q3 analysis task',
  },
  {
    delegation_id: 'del_002',
    from_agent: 'data_agent',
    to_agent: 'report_agent',
    authority_granted: ['read_db', 'query_customers'],
    authority_subset_of: ['read_db', 'query_customers'],
    constraints: ['read_only', 'no_pii_export', 'report_scope_only'],
    valid: true,
    depth: 2,
    created_at: '2026-09-19T08:05:00Z',
    expires_at: '2026-09-19T18:00:00Z',
    reason: 'Sub-delegated for report compilation',
  },
  {
    delegation_id: 'del_003',
    from_agent: 'escalation_agent',
    to_agent: 'external_caller',
    authority_granted: ['read_db', 'query_customers', 'export_pii', 'send_email'],
    authority_subset_of: ['query_customers'],
    constraints: [],
    valid: false,
    depth: 1,
    created_at: '2026-09-19T10:30:00Z',
    expires_at: null,
    reason: 'Attempted privilege escalation for customer data export',
    violation: 'Requested authority [export_pii, send_email] exceeds delegator capability [query_customers]',
  },
  {
    delegation_id: 'del_004',
    from_agent: 'orchestrator_v2',
    to_agent: 'analyst_agent',
    authority_granted: ['read_file', 'generate_summary'],
    authority_subset_of: ['read_file', 'write_file', 'generate_summary', 'delete_file'],
    constraints: ['financial_data_only', 'no_write'],
    valid: true,
    depth: 1,
    created_at: '2026-09-19T07:55:00Z',
    expires_at: '2026-09-20T07:55:00Z',
    reason: 'Analysis of Q3 financial report files',
  },
  {
    delegation_id: 'del_005',
    from_agent: 'report_agent',
    to_agent: 'export_worker',
    authority_granted: ['write_s3', 'egress_network'],
    authority_subset_of: ['read_db', 'query_customers'],
    constraints: [],
    valid: false,
    depth: 3,
    created_at: '2026-09-19T11:15:00Z',
    expires_at: null,
    reason: 'Attempted egress delegation exceeding parent authority scope',
    violation: 'Scope escalation detected: write_s3 not in parent granted authority',
  },
];

export default function DelegationsPage() {
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [selectedDelegation, setSelectedDelegation] = useState<DelegationChain | null>(null);

  const violations = DEMO_DELEGATIONS.filter(d => !d.valid).length;
  const valid = DEMO_DELEGATIONS.filter(d => d.valid).length;
  const maxDepth = Math.max(...DEMO_DELEGATIONS.map(d => d.depth));

  const filtered = DEMO_DELEGATIONS.filter(d => {
    const matchSearch =
      d.delegation_id.toLowerCase().includes(search.toLowerCase()) ||
      d.from_agent.toLowerCase().includes(search.toLowerCase()) ||
      d.to_agent.toLowerCase().includes(search.toLowerCase()) ||
      d.reason.toLowerCase().includes(search.toLowerCase());

    const matchStatus =
      statusFilter === 'ALL' ||
      (statusFilter === 'VALID' && d.valid) ||
      (statusFilter === 'VIOLATION' && !d.valid);

    return matchSearch && matchStatus;
  });

  const columns = [
    {
      key: 'delegation_id',
      header: 'Delegation ID',
      width: '140px',
      render: (row: DelegationChain) => (
        <span className="font-mono text-xs font-semibold text-slate-800">{row.delegation_id}</span>
      ),
    },
    {
      key: 'chain',
      header: 'Delegation Path',
      render: (row: DelegationChain) => (
        <div className="flex items-center gap-1.5 text-xs">
          <span className="font-mono px-2 py-0.5 rounded bg-slate-100 text-slate-800 border border-slate-200">
            {row.from_agent}
          </span>
          <ArrowRight size={12} className="text-slate-400" />
          <span className="font-mono px-2 py-0.5 rounded bg-blue-50 text-blue-800 border border-blue-200 font-medium">
            {row.to_agent}
          </span>
        </div>
      ),
    },
    {
      key: 'authority_granted',
      header: 'Scope Granted',
      render: (row: DelegationChain) => (
        <div className="flex flex-wrap gap-1 max-w-xs">
          {row.authority_granted.map(a => {
            const isSubset = row.authority_subset_of.includes(a);
            return (
              <span
                key={a}
                className={`font-mono text-[11px] px-1.5 py-0.2 rounded border ${
                  isSubset
                    ? 'bg-slate-50 text-slate-700 border-slate-200'
                    : 'bg-red-50 text-red-700 border-red-200 font-semibold'
                }`}
              >
                {a}
              </span>
            );
          })}
        </div>
      ),
    },
    {
      key: 'depth',
      header: 'Depth',
      width: '80px',
      render: (row: DelegationChain) => (
        <span className={`text-xs font-mono px-2 py-0.5 rounded border ${
          row.depth >= 3 ? 'bg-amber-50 text-amber-800 border-amber-200' : 'bg-slate-100 text-slate-600 border-slate-200'
        }`}>
          d={row.depth}
        </span>
      ),
    },
    {
      key: 'valid',
      header: 'Status',
      width: '120px',
      render: (row: DelegationChain) => (
        <StatusBadge status={row.valid ? 'ALLOW' : 'BLOCK'} />
      ),
    },
    {
      key: 'created_at',
      header: 'Created',
      width: '150px',
      render: (row: DelegationChain) => (
        <span className="text-xs text-slate-500">{new Date(row.created_at).toLocaleDateString()}</span>
      ),
    },
  ];

  return (
    <div className="p-8 space-y-6 max-w-7xl mx-auto">
      <PageHeader
        title="Delegations"
        subtitle="Authority delegation chains and scope containment verification"
        badge="Zero-Trust Containment"
      />

      {/* Invariant Banner */}
      <div className="bg-blue-50/70 border border-blue-200 rounded-lg p-3.5 flex items-start gap-3">
        <Shield size={16} className="text-blue-600 mt-0.5 flex-shrink-0" />
        <div className="text-xs text-blue-900 leading-relaxed">
          <span className="font-semibold">Containment Invariant:</span> An agent cannot delegate authority it does not possess. Sub-delegations that exceed the root granted scope are deterministically rejected with zero AI inference.
        </div>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <MetricCard label="Total Delegations" value={DEMO_DELEGATIONS.length} />
        <MetricCard label="Valid Chains" value={valid} status="ALLOW" />
        <MetricCard label="Scope Violations" value={violations} status={violations > 0 ? 'BLOCK' : 'ALLOW'} />
        <MetricCard label="Max Chain Depth" value={`Lvl ${maxDepth}`} />
      </div>

      {/* Filter and Table */}
      <div className="bg-white border border-slate-200 rounded-lg p-5 shadow-xs space-y-4">
        <FilterBar
          searchQuery={search}
          onSearchChange={setSearch}
          searchPlaceholder="Search delegations by ID, agent, or reason..."
          filters={[
            {
              key: 'status',
              label: 'Status',
              options: [
                { label: 'All Statuses', value: 'ALL' },
                { label: 'Valid Only', value: 'VALID' },
                { label: 'Violations Only', value: 'VIOLATION' },
              ],
              value: statusFilter,
              onChange: setStatusFilter,
            },
          ]}
          activeCount={statusFilter !== 'ALL' || search ? 1 : 0}
          onReset={() => {
            setSearch('');
            setStatusFilter('ALL');
          }}
        />

        <DataTable
          columns={columns}
          data={filtered}
          keyField="delegation_id"
          onRowClick={(row) => setSelectedDelegation(row)}
          emptyMessage="No delegation records matched your filter criteria."
        />
      </div>

      {/* Detail Drawer */}
      <DetailDrawer
        isOpen={!!selectedDelegation}
        onClose={() => setSelectedDelegation(null)}
        title={selectedDelegation ? `Delegation: ${selectedDelegation.delegation_id}` : ''}
        subtitle={selectedDelegation ? `${selectedDelegation.from_agent} → ${selectedDelegation.to_agent}` : ''}
        badge={selectedDelegation ? <StatusBadge status={selectedDelegation.valid ? 'ALLOW' : 'BLOCK'} /> : null}
      >
        {selectedDelegation && (
          <div className="space-y-6">
            {/* Status overview */}
            <div className={`p-3.5 rounded-lg border text-xs ${
              selectedDelegation.valid
                ? 'bg-emerald-50 border-emerald-200 text-emerald-900'
                : 'bg-red-50 border-red-200 text-red-900'
            }`}>
              <div className="font-semibold mb-1 flex items-center gap-1.5">
                {selectedDelegation.valid ? <CheckCircle2 size={14} className="text-emerald-600" /> : <AlertTriangle size={14} className="text-red-600" />}
                {selectedDelegation.valid ? 'Containment Proof Verified' : 'Containment Invariant Violation Detected'}
              </div>
              <p>{selectedDelegation.reason}</p>
            </div>

            {selectedDelegation.violation && (
              <div className="p-3 bg-red-50/50 border border-red-200 rounded-lg">
                <div className="text-[11px] font-semibold uppercase tracking-wider text-red-700 mb-1">Violation Diagnostics</div>
                <div className="text-xs font-mono text-red-800">{selectedDelegation.violation}</div>
              </div>
            )}

            {/* Path visualization */}
            <div>
              <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-500 mb-2">Delegation Lineage</div>
              <div className="bg-slate-50 border border-slate-200 rounded-lg p-3 flex items-center justify-between">
                <div>
                  <div className="text-[10px] text-slate-500 uppercase font-mono">Delegator</div>
                  <div className="font-mono text-sm font-semibold text-slate-800">{selectedDelegation.from_agent}</div>
                </div>
                <div className="text-center px-3">
                  <span className="text-[10px] font-mono text-slate-500 block">depth {selectedDelegation.depth}</span>
                  <ArrowRight size={16} className="text-slate-400 mx-auto" />
                </div>
                <div>
                  <div className="text-[10px] text-slate-500 uppercase font-mono">Delegatee</div>
                  <div className="font-mono text-sm font-semibold text-blue-700">{selectedDelegation.to_agent}</div>
                </div>
              </div>
            </div>

            {/* Scope Comparison */}
            <div>
              <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-500 mb-2">Granted vs Delegator Scope</div>
              <div className="space-y-3">
                <div className="bg-white border border-slate-200 rounded-lg p-3">
                  <div className="text-[10px] text-slate-500 uppercase font-medium mb-1.5">Authority Requested & Granted</div>
                  <div className="flex flex-wrap gap-1.5">
                    {selectedDelegation.authority_granted.map(a => {
                      const isSubset = selectedDelegation.authority_subset_of.includes(a);
                      return (
                        <span
                          key={a}
                          className={`font-mono text-xs px-2 py-0.5 rounded border ${
                            isSubset
                              ? 'bg-emerald-50 text-emerald-800 border-emerald-200'
                              : 'bg-red-50 text-red-800 border-red-300 font-bold'
                          }`}
                        >
                          {a} {isSubset ? '✓' : '✗ [Out of scope]'}
                        </span>
                      );
                    })}
                  </div>
                </div>

                <div className="bg-white border border-slate-200 rounded-lg p-3">
                  <div className="text-[10px] text-slate-500 uppercase font-medium mb-1.5">Delegator Baseline Authority</div>
                  <div className="flex flex-wrap gap-1.5">
                    {selectedDelegation.authority_subset_of.map(a => (
                      <span key={a} className="font-mono text-xs px-2 py-0.5 rounded bg-slate-100 text-slate-700 border border-slate-200">
                        {a}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            </div>

            {/* Constraints */}
            <div>
              <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-500 mb-2">Attached Constraints</div>
              {selectedDelegation.constraints.length > 0 ? (
                <div className="flex flex-wrap gap-1.5">
                  {selectedDelegation.constraints.map(c => (
                    <span key={c} className="font-mono text-xs px-2 py-0.5 rounded bg-amber-50 text-amber-800 border border-amber-200">
                      {c}
                    </span>
                  ))}
                </div>
              ) : (
                <span className="text-xs text-slate-500 italic">No constraints attached</span>
              )}
            </div>

            {/* Temporal metadata */}
            <div className="border-t border-slate-200 pt-4 space-y-2 text-xs text-slate-600">
              <div className="flex justify-between">
                <span className="text-slate-500">Created At</span>
                <span className="font-mono">{new Date(selectedDelegation.created_at).toUTCString()}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-500">Expires At</span>
                <span className="font-mono">{selectedDelegation.expires_at ? new Date(selectedDelegation.expires_at).toUTCString() : 'Never (Manual Revocation Required)'}</span>
              </div>
            </div>
          </div>
        )}
      </DetailDrawer>
    </div>
  );
}
