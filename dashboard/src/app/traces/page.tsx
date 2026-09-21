'use client';

import { useState } from 'react';
import { Search, GitBranch, ArrowRight, Clock, Shield, AlertTriangle, CheckCircle2, Layers } from 'lucide-react';
import { PageHeader } from '@/components/ui/PageHeader';
import { MetricCard } from '@/components/ui/MetricCard';
import { StatusBadge } from '@/components/ui/StatusBadge';
import { FilterBar } from '@/components/ui/FilterBar';
import { DataTable } from '@/components/ui/DataTable';
import { DetailDrawer } from '@/components/ui/DetailDrawer';

interface SpanItem {
  span_id: string;
  name: string;
  duration_ms: number;
  taint: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  decision: 'ALLOW' | 'BLOCK' | 'HITL';
  flags?: string[];
}

interface TraceItem {
  trace_id: string;
  name: string;
  agent_id: string;
  task_id: string;
  started_at: string;
  duration_ms: number;
  decision: 'ALLOW' | 'BLOCK' | 'HITL';
  spans: SpanItem[];
  causal_explanation: string;
}

const DEMO_TRACES: TraceItem[] = [
  {
    trace_id: 'trc_pinj_001',
    name: 'Prompt Injection → Data Exfil Attempt',
    agent_id: 'orchestrator_v2',
    task_id: 'task_002',
    started_at: '2026-09-19T09:11:00Z',
    duration_ms: 847,
    decision: 'BLOCK',
    spans: [
      { span_id: 'sp_001', name: 'receive_user_message', duration_ms: 12, taint: 'LOW', decision: 'ALLOW' },
      { span_id: 'sp_002', name: 'call_external_mcp_tool', duration_ms: 234, taint: 'CRITICAL', decision: 'BLOCK', flags: ['PROMPT_INJECTION'] },
      { span_id: 'sp_003', name: 'attempt_upload_s3', duration_ms: 0, taint: 'CRITICAL', decision: 'BLOCK', flags: ['BLOCKED_BY_POLICY'] },
    ],
    causal_explanation: 'External MCP tool injected malicious instruction. Orchestrator attempted to upload PII to external S3. Both tool call and upload were deterministically blocked.',
  },
  {
    trace_id: 'trc_auth_esc_001',
    name: 'Authority Escalation Attempt',
    agent_id: 'escalation_agent',
    task_id: 'task_004',
    started_at: '2026-09-19T10:30:00Z',
    duration_ms: 312,
    decision: 'BLOCK',
    spans: [
      { span_id: 'sp_011', name: 'receive_task', duration_ms: 8, taint: 'LOW', decision: 'ALLOW' },
      { span_id: 'sp_012', name: 'delegation_check', duration_ms: 45, taint: 'LOW', decision: 'BLOCK', flags: ['AUTHORITY_EXCEEDED'] },
      { span_id: 'sp_013', name: 'attempt_send_email', duration_ms: 0, taint: 'HIGH', decision: 'BLOCK', flags: ['BLOCKED_BY_POLICY'] },
    ],
    causal_explanation: 'Agent requested email_api and export_pii capabilities beyond its delegated authority. Delegation containment check failed.',
  },
  {
    trace_id: 'trc_q3_analysis',
    name: 'Q3 Financial Analysis (Clean)',
    agent_id: 'orchestrator_v2',
    task_id: 'task_001',
    started_at: '2026-09-19T08:00:00Z',
    duration_ms: 3320,
    decision: 'ALLOW',
    spans: [
      { span_id: 'sp_021', name: 'read_file:q3_financials', duration_ms: 45, taint: 'LOW', decision: 'ALLOW' },
      { span_id: 'sp_022', name: 'delegate_to:analyst_agent', duration_ms: 12, taint: 'LOW', decision: 'ALLOW' },
      { span_id: 'sp_023', name: 'generate_summary', duration_ms: 2800, taint: 'LOW', decision: 'ALLOW' },
      { span_id: 'sp_024', name: 'write_report', duration_ms: 120, taint: 'LOW', decision: 'ALLOW' },
    ],
    causal_explanation: 'Clean task execution within delegated authority. All tools permitted. No taint propagation.',
  },
];

export default function TracesPage() {
  const [search, setSearch] = useState('');
  const [decisionFilter, setDecisionFilter] = useState('ALL');
  const [selectedTrace, setSelectedTrace] = useState<TraceItem | null>(null);

  const blockedCount = DEMO_TRACES.filter(t => t.decision === 'BLOCK').length;
  const allowCount = DEMO_TRACES.filter(t => t.decision === 'ALLOW').length;

  const filtered = DEMO_TRACES.filter(t => {
    const matchSearch =
      t.name.toLowerCase().includes(search.toLowerCase()) ||
      t.agent_id.toLowerCase().includes(search.toLowerCase()) ||
      t.trace_id.toLowerCase().includes(search.toLowerCase()) ||
      t.task_id.toLowerCase().includes(search.toLowerCase());

    const matchDec = decisionFilter === 'ALL' || t.decision === decisionFilter;

    return matchSearch && matchDec;
  });

  const columns = [
    {
      key: 'name',
      header: 'Trace Name & ID',
      render: (row: TraceItem) => (
        <div className="flex items-center gap-2.5">
          <div className="w-7 h-7 rounded bg-slate-100 flex items-center justify-center text-slate-600 border border-slate-200">
            <GitBranch size={13} />
          </div>
          <div>
            <div className="font-semibold text-xs text-slate-900">{row.name}</div>
            <div className="font-mono text-[10px] text-slate-500">{row.trace_id}</div>
          </div>
        </div>
      ),
    },
    {
      key: 'agent_id',
      header: 'Acting Agent',
      width: '160px',
      render: (row: TraceItem) => (
        <span className="font-mono text-xs text-blue-700 bg-blue-50 px-2 py-0.5 rounded border border-blue-200">
          {row.agent_id}
        </span>
      ),
    },
    {
      key: 'spans',
      header: 'Spans Timeline',
      render: (row: TraceItem) => (
        <div className="flex items-center gap-1">
          {row.spans.map(span => (
            <div
              key={span.span_id}
              title={`${span.name} (${span.decision})`}
              className={`h-2 rounded-xs transition-all ${
                span.decision === 'BLOCK' ? 'bg-red-500 w-6' : span.decision === 'HITL' ? 'bg-amber-500 w-6' : 'bg-emerald-500 w-4'
              }`}
            />
          ))}
          <span className="font-mono text-[10px] text-slate-500 ml-1.5">{row.spans.length} spans</span>
        </div>
      ),
    },
    {
      key: 'duration_ms',
      header: 'Duration',
      width: '110px',
      render: (row: TraceItem) => (
        <span className="font-mono text-xs text-slate-600">{row.duration_ms} ms</span>
      ),
    },
    {
      key: 'decision',
      header: 'Verdict',
      width: '120px',
      render: (row: TraceItem) => (
        <StatusBadge status={row.decision} />
      ),
    },
  ];

  return (
    <div className="p-8 space-y-6 max-w-7xl mx-auto">
      <PageHeader
        title="Execution Traces"
        subtitle="End-to-end causal execution traces with span-level decision evidence and taint timelines"
        badge="Trace Explorer"
      />

      {/* KPI Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <MetricCard label="Total Traces" value={DEMO_TRACES.length} />
        <MetricCard label="Blocked Invocations" value={blockedCount} status="BLOCK" />
        <MetricCard label="Clean Executions" value={allowCount} status="ALLOW" />
        <MetricCard label="Mean Latency" value="1.42 ms" />
      </div>

      {/* Filter and Table */}
      <div className="bg-white border border-slate-200 rounded-lg p-5 shadow-xs space-y-4">
        <FilterBar
          searchQuery={search}
          onSearchChange={setSearch}
          searchPlaceholder="Search traces by name, ID, or agent..."
          filters={[
            {
              key: 'decision',
              label: 'Verdict',
              options: [
                { label: 'All Verdicts', value: 'ALL' },
                { label: 'Block', value: 'BLOCK' },
                { label: 'Allow', value: 'ALLOW' },
                { label: 'HITL', value: 'HITL' },
              ],
              value: decisionFilter,
              onChange: setDecisionFilter,
            },
          ]}
          activeCount={decisionFilter !== 'ALL' || search ? 1 : 0}
          onReset={() => {
            setSearch('');
            setDecisionFilter('ALL');
          }}
        />

        <DataTable
          columns={columns}
          data={filtered}
          keyField="trace_id"
          onRowClick={(row) => setSelectedTrace(row)}
          emptyMessage="No traces matched your filter criteria."
        />
      </div>

      {/* Detail Drawer */}
      <DetailDrawer
        isOpen={!!selectedTrace}
        onClose={() => setSelectedTrace(null)}
        title={selectedTrace ? selectedTrace.name : ''}
        subtitle={selectedTrace ? `Trace ID: ${selectedTrace.trace_id} • Agent: ${selectedTrace.agent_id}` : ''}
        badge={selectedTrace ? <StatusBadge status={selectedTrace.decision} /> : null}
      >
        {selectedTrace && (
          <div className="space-y-6">
            {/* Causal Explanation */}
            <div className="p-3.5 bg-slate-50 border border-slate-200 rounded-lg space-y-1.5">
              <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">Causal Explanation</div>
              <p className="text-xs text-slate-800 leading-relaxed">{selectedTrace.causal_explanation}</p>
            </div>

            {/* Spans List */}
            <div>
              <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-500 mb-2">Execution Spans Sequence</div>
              <div className="space-y-2">
                {selectedTrace.spans.map((span, idx) => (
                  <div key={span.span_id} className="p-3 bg-white border border-slate-200 rounded-lg flex items-center justify-between text-xs">
                    <div className="flex items-center gap-2.5">
                      <span className="font-mono text-[10px] text-slate-400">#{idx + 1}</span>
                      <div>
                        <div className="font-mono font-semibold text-slate-900">{span.name}</div>
                        <div className="text-[10px] text-slate-500 font-mono">{span.duration_ms} ms • Taint: {span.taint}</div>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      {span.flags?.map(f => (
                        <span key={f} className="text-[10px] px-1.5 py-0.5 rounded bg-red-50 text-red-700 border border-red-200 font-mono">
                          {f}
                        </span>
                      ))}
                      <StatusBadge status={span.decision} />
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
      </DetailDrawer>
    </div>
  );
}
