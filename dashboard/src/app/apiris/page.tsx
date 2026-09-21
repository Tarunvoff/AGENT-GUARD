'use client';

import { useState } from 'react';
import { Zap, AlertTriangle, CheckCircle2, Shield, Activity, Filter, BarChart2 } from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { PageHeader } from '@/components/ui/PageHeader';
import { MetricCard } from '@/components/ui/MetricCard';
import { StatusBadge } from '@/components/ui/StatusBadge';
import { FilterBar } from '@/components/ui/FilterBar';
import { DataTable } from '@/components/ui/DataTable';
import { DetailDrawer } from '@/components/ui/DetailDrawer';

const APIRIS_RISK_DISTRIBUTION = [
  { range: '0.0 - 0.2', count: 12, label: 'Safe' },
  { range: '0.2 - 0.4', count: 8, label: 'Low' },
  { range: '0.4 - 0.6', count: 5, label: 'Medium' },
  { range: '0.6 - 0.8', count: 3, label: 'High' },
  { range: '0.8 - 1.0', count: 4, label: 'Critical' },
];

interface ApirisSignal {
  signal_id: string;
  tool: string;
  signal_type: string;
  score: number;
  anomaly_flags: string[];
  timestamp: string;
  action_taken: 'BLOCK' | 'HITL' | 'ALLOW';
  description: string;
}

const APIRIS_SIGNALS: ApirisSignal[] = [
  {
    signal_id: 'sig_001',
    tool: 'external_mcp_tool',
    signal_type: 'INJECTION_PATTERN',
    score: 0.98,
    anomaly_flags: ['INSTRUCTION_OVERRIDE', 'EXFIL_KEYWORD', 'AUTHORITY_CLAIM'],
    timestamp: '2026-09-19T10:45:00Z',
    action_taken: 'BLOCK',
    description: 'Tool response contained instruction override patterns and data exfiltration keywords.',
  },
  {
    signal_id: 'sig_002',
    tool: 'upload_s3',
    signal_type: 'EGRESS_ANOMALY',
    score: 0.95,
    anomaly_flags: ['EXTERNAL_DESTINATION', 'PII_DETECTED', 'UNEXPECTED_VOLUME'],
    timestamp: '2026-09-19T09:11:45Z',
    action_taken: 'BLOCK',
    description: 'Unexpected large data transfer to external S3 bucket. PII tokens detected in payload.',
  },
  {
    signal_id: 'sig_003',
    tool: 'send_email',
    signal_type: 'EXFIL_ATTEMPT',
    score: 0.91,
    anomaly_flags: ['EXTERNAL_CHANNEL', 'PII_IN_BODY', 'UNSCHEDULED_CALL'],
    timestamp: '2026-09-19T10:30:00Z',
    action_taken: 'BLOCK',
    description: 'Email API called with customer PII in body to unverified recipient — exfiltration attempt.',
  },
  {
    signal_id: 'sig_004',
    tool: 'read_db',
    signal_type: 'ANOMALOUS_QUERY',
    score: 0.72,
    anomaly_flags: ['FULL_TABLE_SCAN', 'NO_WHERE_CLAUSE'],
    timestamp: '2026-09-19T09:11:00Z',
    action_taken: 'HITL',
    description: 'Database query selects all rows from customers table without restriction. High data exposure risk.',
  },
  {
    signal_id: 'sig_005',
    tool: 'read_file',
    signal_type: 'NORMAL',
    score: 0.12,
    anomaly_flags: [],
    timestamp: '2026-09-19T08:02:00Z',
    action_taken: 'ALLOW',
    description: 'Standard file read within allowed path scope. No anomalies detected.',
  },
];

export default function ApirisPage() {
  const [search, setSearch] = useState('');
  const [actionFilter, setActionFilter] = useState('ALL');
  const [selectedSignal, setSelectedSignal] = useState<ApirisSignal | null>(null);

  const criticalCount = APIRIS_SIGNALS.filter(s => s.score >= 0.8).length;
  const avgScore = (APIRIS_SIGNALS.reduce((s, a) => s + a.score, 0) / APIRIS_SIGNALS.length).toFixed(2);

  const filtered = APIRIS_SIGNALS.filter(s => {
    const matchSearch =
      s.signal_id.toLowerCase().includes(search.toLowerCase()) ||
      s.tool.toLowerCase().includes(search.toLowerCase()) ||
      s.description.toLowerCase().includes(search.toLowerCase()) ||
      s.signal_type.toLowerCase().includes(search.toLowerCase());

    const matchAction = actionFilter === 'ALL' || s.action_taken === actionFilter;

    return matchSearch && matchAction;
  });

  const columns = [
    {
      key: 'signal_id',
      header: 'Signal & Tool',
      render: (row: ApirisSignal) => (
        <div className="flex items-center gap-2.5">
          <div className="w-7 h-7 rounded bg-amber-50 flex items-center justify-center text-amber-700 border border-amber-200">
            <Zap size={13} />
          </div>
          <div>
            <div className="font-mono text-xs font-semibold text-slate-900">{row.tool}</div>
            <div className="font-mono text-[10px] text-slate-500">{row.signal_id}</div>
          </div>
        </div>
      ),
    },
    {
      key: 'signal_type',
      header: 'Signal Type',
      width: '180px',
      render: (row: ApirisSignal) => (
        <span className="text-xs font-mono text-slate-700 bg-slate-100 px-2 py-0.5 rounded border border-slate-200">
          {row.signal_type}
        </span>
      ),
    },
    {
      key: 'score',
      header: 'APIRIS Risk Index',
      width: '140px',
      render: (row: ApirisSignal) => (
        <div className="flex items-center gap-2">
          <div className="w-12 bg-slate-100 rounded-full h-1.5 overflow-hidden">
            <div
              className={`h-full ${row.score > 0.8 ? 'bg-red-500' : row.score > 0.5 ? 'bg-amber-500' : 'bg-emerald-500'}`}
              style={{ width: `${row.score * 100}%` }}
            />
          </div>
          <span className="font-mono text-xs font-semibold text-slate-800">{row.score.toFixed(2)}</span>
        </div>
      ),
    },
    {
      key: 'action_taken',
      header: 'Action Intercept',
      width: '130px',
      render: (row: ApirisSignal) => (
        <StatusBadge status={row.action_taken} />
      ),
    },
    {
      key: 'timestamp',
      header: 'Timestamp',
      width: '120px',
      render: (row: ApirisSignal) => (
        <span className="text-xs text-slate-500">{new Date(row.timestamp).toLocaleTimeString()}</span>
      ),
    },
  ];

  return (
    <div className="p-8 space-y-6 max-w-7xl mx-auto">
      <PageHeader
        title="APIRIS Risk Intelligence"
        subtitle="Real-time structural anomaly scoring, schema inspection, and payload risk quantification for all API and tool calls"
        badge="Payload Scoring"
      />

      {/* Architecture Pipeline Banner */}
      <div className="bg-blue-50/70 border border-blue-200 rounded-lg p-3.5 flex items-start gap-3">
        <Shield size={16} className="text-blue-600 mt-0.5 flex-shrink-0" />
        <div className="text-xs text-blue-900 leading-relaxed">
          <span className="font-semibold">APIRIS Pipeline:</span> Invocations with APIRIS score ≥ 0.80 trigger an immediate deterministic BLOCK. Scores between 0.50–0.79 route to HITL evaluation. Scores feed directly into runtime policy validation.
        </div>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <MetricCard label="Total Signals (24h)" value={APIRIS_SIGNALS.length} />
        <MetricCard label="Critical Risk (≥ 0.80)" value={criticalCount} status="BLOCK" />
        <MetricCard label="Mean Risk Score" value={avgScore} />
        <MetricCard label="Blocked Invocations" value={3} status="BLOCK" />
      </div>

      {/* Distribution Chart */}
      <div className="bg-white border border-slate-200 rounded-lg p-5 shadow-xs space-y-4">
        <div className="text-xs font-semibold uppercase tracking-wider text-slate-500">APIRIS Risk Score Distribution</div>
        <div className="h-52">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={APIRIS_RISK_DISTRIBUTION} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#f1f5f9" vertical={false} />
              <XAxis dataKey="range" stroke="#94a3b8" fontSize={11} />
              <YAxis stroke="#94a3b8" fontSize={11} />
              <Tooltip contentStyle={{ backgroundColor: '#ffffff', borderColor: '#e2e8f0', borderRadius: '6px', fontSize: '11px' }} />
              <Bar dataKey="count" fill="#2563eb" radius={[4, 4, 0, 0]} name="Invocations" />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Signals Table */}
      <div className="bg-white border border-slate-200 rounded-lg p-5 shadow-xs space-y-4">
        <FilterBar
          searchQuery={search}
          onSearchChange={setSearch}
          searchPlaceholder="Search APIRIS signals by tool, type, or description..."
          filters={[
            {
              key: 'action',
              label: 'Action',
              options: [
                { label: 'All Actions', value: 'ALL' },
                { label: 'Block', value: 'BLOCK' },
                { label: 'HITL', value: 'HITL' },
                { label: 'Allow', value: 'ALLOW' },
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
          keyField="signal_id"
          onRowClick={(row) => setSelectedSignal(row)}
          emptyMessage="No APIRIS signals matched your search criteria."
        />
      </div>

      {/* Signal Detail Drawer */}
      <DetailDrawer
        isOpen={!!selectedSignal}
        onClose={() => setSelectedSignal(null)}
        title={selectedSignal ? `Signal: ${selectedSignal.signal_id}` : ''}
        subtitle={selectedSignal ? `Tool: ${selectedSignal.tool} • Risk Score: ${selectedSignal.score.toFixed(2)}` : ''}
        badge={selectedSignal ? <StatusBadge status={selectedSignal.action_taken} /> : null}
      >
        {selectedSignal && (
          <div className="space-y-6">
            <div className="p-3.5 bg-slate-50 border border-slate-200 rounded-lg space-y-1.5">
              <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">Anomaly Diagnostics</div>
              <p className="text-xs text-slate-800 leading-relaxed">{selectedSignal.description}</p>
            </div>

            {/* Anomaly Flags */}
            <div>
              <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-500 mb-2">Detected Anomaly Flags</div>
              {selectedSignal.anomaly_flags.length > 0 ? (
                <div className="flex flex-wrap gap-1.5">
                  {selectedSignal.anomaly_flags.map(flag => (
                    <span key={flag} className="font-mono text-xs px-2 py-0.5 rounded bg-red-50 text-red-800 border border-red-200 font-semibold">
                      ⚠ {flag}
                    </span>
                  ))}
                </div>
              ) : (
                <span className="text-xs text-slate-500 italic">No anomaly flags triggered</span>
              )}
            </div>

            <div className="border-t border-slate-200 pt-4 text-xs text-slate-600 flex justify-between">
              <span className="text-slate-500">Evaluated Timestamp</span>
              <span className="font-mono">{new Date(selectedSignal.timestamp).toUTCString()}</span>
            </div>
          </div>
        )}
      </DetailDrawer>
    </div>
  );
}
