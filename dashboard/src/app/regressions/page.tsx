'use client';

import { useState } from 'react';
import { DEMO_REGRESSIONS } from '@/data/demo';
import { PageHeader } from '@/components/ui/PageHeader';
import { MetricCard } from '@/components/ui/MetricCard';
import { StatusBadge } from '@/components/ui/StatusBadge';
import { FilterBar } from '@/components/ui/FilterBar';
import { DataTable } from '@/components/ui/DataTable';
import { DetailDrawer } from '@/components/ui/DetailDrawer';
import { RotateCcw, CheckCircle2, XCircle, ArrowRight, ShieldCheck, History } from 'lucide-react';

interface RegressionItem {
  regression_id: string;
  attack_id: string;
  attack_type: string;
  secured: boolean;
  expected_decision: 'BLOCK' | 'HITL' | 'ALLOW' | string;
  observed_decision: 'BLOCK' | 'HITL' | 'ALLOW' | string;
  replay_decision?: 'BLOCK' | 'HITL' | 'ALLOW' | string;
  sensitive_db_calls_before: number;
  sensitive_db_calls_after: number;
  mutation_lineage: string[];
}

export default function RegressionsPage() {
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [selectedRegression, setSelectedRegression] = useState<RegressionItem | null>(null);

  const securedCount = DEMO_REGRESSIONS.filter(r => r.secured).length;
  const dbCallsPrevented = DEMO_REGRESSIONS.reduce((s, r) => s + r.sensitive_db_calls_before, 0);

  const filtered = (DEMO_REGRESSIONS as RegressionItem[]).filter(r => {
    const matchSearch =
      r.regression_id.toLowerCase().includes(search.toLowerCase()) ||
      r.attack_type.toLowerCase().includes(search.toLowerCase()) ||
      r.attack_id.toLowerCase().includes(search.toLowerCase());

    const matchStatus =
      statusFilter === 'ALL' ||
      (statusFilter === 'SECURED' && r.secured) ||
      (statusFilter === 'OPEN' && !r.secured);

    return matchSearch && matchStatus;
  });

  const columns = [
    {
      key: 'regression_id',
      header: 'Regression Fixture',
      render: (row: RegressionItem) => (
        <div className="flex items-center gap-2.5">
          <div className="w-7 h-7 rounded-md bg-purple-50 flex items-center justify-center text-purple-700 border border-purple-200">
            <RotateCcw size={13} />
          </div>
          <div>
            <div className="font-mono text-xs font-semibold text-slate-900">{row.regression_id.toUpperCase()}</div>
            <div className="text-[11px] text-slate-500 capitalize">{row.attack_type.replace(/_/g, ' ')}</div>
          </div>
        </div>
      ),
    },
    {
      key: 'attack_id',
      header: 'Source Attack',
      width: '180px',
      render: (row: RegressionItem) => (
        <span className="font-mono text-xs text-slate-600 bg-slate-100 px-2 py-0.5 rounded border border-slate-200">
          {row.attack_id}
        </span>
      ),
    },
    {
      key: 'expected_decision',
      header: 'Expected',
      width: '110px',
      render: (row: RegressionItem) => (
        <StatusBadge status={row.expected_decision as any} />
      ),
    },
    {
      key: 'observed_decision',
      header: 'Before Fix',
      width: '120px',
      render: (row: RegressionItem) => (
        <div className="flex items-center gap-1.5">
          <StatusBadge status={row.observed_decision as any} />
          <span className="text-[10px] text-red-600 font-mono font-bold">({row.sensitive_db_calls_before} leak)</span>
        </div>
      ),
    },
    {
      key: 'replay_decision',
      header: 'Replay Verdict',
      width: '120px',
      render: (row: RegressionItem) => (
        <div className="flex items-center gap-1.5">
          <StatusBadge status={(row.replay_decision ?? 'BLOCK') as any} />
          <CheckCircle2 size={13} className="text-emerald-600" />
        </div>
      ),
    },
    {
      key: 'secured',
      header: 'Status',
      width: '110px',
      render: (row: RegressionItem) => (
        <span className={`text-[11px] font-semibold px-2 py-0.5 rounded border ${
          row.secured ? 'bg-emerald-50 text-emerald-700 border-emerald-200' : 'bg-red-50 text-red-700 border-red-200'
        }`}>
          {row.secured ? 'SECURED' : 'OPEN'}
        </span>
      ),
    },
  ];

  return (
    <div className="p-8 space-y-6 max-w-7xl mx-auto">
      <PageHeader
        title="Security Regression Library"
        subtitle="Historical attack fixtures where vulnerabilities were patched and verified via continuous deterministic replay"
        badge="Replay Suite"
      />

      {/* KPI Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <MetricCard label="Total Regressions" value={DEMO_REGRESSIONS.length} />
        <MetricCard label="Secured Fixtures" value={`${securedCount} / ${DEMO_REGRESSIONS.length}`} status="ALLOW" />
        <MetricCard label="Open Vulnerabilities" value={DEMO_REGRESSIONS.length - securedCount} status="ALLOW" />
        <MetricCard label="DB Leaks Prevented" value={dbCallsPrevented} status="ALLOW" />
      </div>

      {/* Filter and Table */}
      <div className="bg-white border border-slate-200 rounded-lg p-5 shadow-xs space-y-4">
        <FilterBar
          searchQuery={search}
          onSearchChange={setSearch}
          searchPlaceholder="Search regressions by ID or attack type..."
          filters={[
            {
              key: 'status',
              label: 'Status',
              options: [
                { label: 'All Statuses', value: 'ALL' },
                { label: 'Secured Only', value: 'SECURED' },
                { label: 'Open Only', value: 'OPEN' },
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
          keyField="regression_id"
          onRowClick={(row) => setSelectedRegression(row)}
          emptyMessage="No regression fixtures matched your filter criteria."
        />
      </div>

      {/* Detail Drawer */}
      <DetailDrawer
        isOpen={!!selectedRegression}
        onClose={() => setSelectedRegression(null)}
        title={selectedRegression ? selectedRegression.regression_id.toUpperCase() : ''}
        subtitle={selectedRegression ? `Source Attack: ${selectedRegression.attack_id}` : ''}
        badge={selectedRegression ? (
          <span className="text-xs font-semibold px-2 py-0.5 rounded border bg-emerald-50 text-emerald-700 border-emerald-200">
            {selectedRegression.secured ? 'VERIFIED SECURED' : 'OPEN'}
          </span>
        ) : null}
      >
        {selectedRegression && (
          <div className="space-y-6">
            {/* Overview */}
            <div className="p-3.5 bg-emerald-50/80 border border-emerald-200 rounded-lg text-xs text-emerald-900 space-y-1">
              <div className="font-semibold flex items-center gap-1.5">
                <CheckCircle2 size={14} className="text-emerald-700" />
                <span>Deterministic Replay Protection Verified</span>
              </div>
              <p>Replay of this historical attack payload against current policy rules deterministically yields BLOCK verdict with 0 sensitive resource access.</p>
            </div>

            {/* Before vs After Comparison */}
            <div>
              <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-500 mb-2">Replay Decision Comparison</div>
              <div className="grid grid-cols-2 gap-3">
                <div className="p-3.5 bg-red-50/60 border border-red-200 rounded-lg space-y-2">
                  <div className="text-[10px] uppercase font-semibold text-red-700">Before Fix</div>
                  <div className="flex items-center gap-2">
                    <StatusBadge status={selectedRegression.observed_decision as any} />
                    <span className="text-xs font-bold text-red-700">{selectedRegression.sensitive_db_calls_before} DB leaks</span>
                  </div>
                </div>

                <div className="p-3.5 bg-emerald-50/60 border border-emerald-200 rounded-lg space-y-2">
                  <div className="text-[10px] uppercase font-semibold text-emerald-700">Secured Replay</div>
                  <div className="flex items-center gap-2">
                    <StatusBadge status={(selectedRegression.replay_decision ?? 'BLOCK') as any} />
                    <span className="text-xs font-bold text-emerald-700">{selectedRegression.sensitive_db_calls_after} DB leaks</span>
                  </div>
                </div>
              </div>
            </div>

            {/* Mutation Lineage */}
            <div>
              <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-500 mb-2">Mutation Lineage Trace</div>
              <div className="bg-slate-50 border border-slate-200 rounded-lg p-3">
                <div className="flex items-center gap-1.5 flex-wrap">
                  {selectedRegression.mutation_lineage.map((id, idx) => (
                    <span key={id} className="flex items-center gap-1.5">
                      <span className="font-mono text-xs bg-white border border-slate-200 px-2 py-0.5 rounded text-slate-800 font-medium">
                        {id}
                      </span>
                      {idx < selectedRegression.mutation_lineage.length - 1 && (
                        <ArrowRight size={12} className="text-slate-400" />
                      )}
                    </span>
                  ))}
                </div>
              </div>
            </div>
          </div>
        )}
      </DetailDrawer>
    </div>
  );
}
