'use client';

import { useState } from 'react';
import { Search, GitBranch, ArrowRight, Clock, Cpu, Shield, AlertTriangle, ChevronDown, ChevronRight } from 'lucide-react';
import { DecisionBadge, TaintBadge } from '@/components/ui/security';
import Link from 'next/link';

const DEMO_TRACES = [
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
    causal_explanation: 'External MCP tool injected malicious instruction. Orchestrator attempted to upload PII to external S3. Both tool call and upload were blocked.',
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
    causal_explanation: 'Agent requested email_api and export_pii capabilities beyond its delegated authority. Delegation check failed — authority containment enforced.',
  },
  {
    trace_id: 'trc_q3_analysis',
    name: 'Q3 Financial Analysis (Clean)',
    agent_id: 'orchestrator_v2',
    task_id: 'task_001',
    started_at: '2026-09-19T08:00:00Z',
    duration_ms: 332000,
    decision: 'ALLOW',
    spans: [
      { span_id: 'sp_021', name: 'read_file:q3_financials', duration_ms: 45, taint: 'LOW', decision: 'ALLOW' },
      { span_id: 'sp_022', name: 'delegate_to:analyst_agent', duration_ms: 12, taint: 'LOW', decision: 'ALLOW' },
      { span_id: 'sp_023', name: 'generate_summary', duration_ms: 2800, taint: 'LOW', decision: 'ALLOW' },
      { span_id: 'sp_024', name: 'write_report', duration_ms: 120, taint: 'LOW', decision: 'ALLOW' },
    ],
    causal_explanation: 'Clean task execution within delegated authority. All tools permitted. No taint propagation. Report written to internal storage only.',
  },
];

const SPAN_COLORS: Record<string, string> = {
  ALLOW: 'bg-emerald-500',
  BLOCK: 'bg-red-500',
  HITL: 'bg-amber-500',
};

export default function TracesPage() {
  const [search, setSearch] = useState('');
  const [selectedTrace, setSelectedTrace] = useState<typeof DEMO_TRACES[0] | null>(null);
  const [decisionFilter, setDecisionFilter] = useState('all');

  const filtered = DEMO_TRACES.filter(t => {
    const matchSearch = t.name.toLowerCase().includes(search.toLowerCase()) || t.agent_id.includes(search);
    const matchDec = decisionFilter === 'all' || t.decision === decisionFilter;
    return matchSearch && matchDec;
  });

  return (
    <div className="p-6 space-y-5 min-h-screen bg-[#090d16]">
      <div>
        <h1 className="text-xl font-bold text-white flex items-center gap-2">
          <Search size={18} className="text-sky-400" />
          Trace Explorer
        </h1>
        <p className="text-sm text-zinc-500 mt-1">End-to-end causal execution traces with span-level decision evidence</p>
      </div>

      {/* Search + Filter */}
      <div className="flex gap-3 items-center">
        <div className="relative flex-1 max-w-sm">
          <Search size={13} className="absolute left-3 top-1/2 -translate-y-1/2 text-zinc-500" />
          <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search traces, agents..."
            className="w-full pl-8 pr-3 py-2 bg-zinc-800/60 border border-zinc-700/50 rounded-lg text-sm text-zinc-200 placeholder:text-zinc-600 focus:outline-none focus:border-sky-500/50"
          />
        </div>
        {['all', 'ALLOW', 'BLOCK', 'HITL'].map(f => (
          <button key={f} onClick={() => setDecisionFilter(f)}
            className={`px-2.5 py-1 text-[11px] rounded font-medium uppercase tracking-wider transition-colors ${
              decisionFilter === f ? 'bg-sky-500/15 border border-sky-500/30 text-sky-300' : 'text-zinc-500 hover:text-zinc-300'
            }`}>
            {f}
          </button>
        ))}
      </div>

      <div className="grid grid-cols-5 gap-4">
        {/* Trace List */}
        <div className="col-span-2 space-y-2">
          {filtered.map(trace => (
            <div
              key={trace.trace_id}
              onClick={() => setSelectedTrace(trace)}
              className={`rounded-xl border p-3 cursor-pointer transition-all ${
                selectedTrace?.trace_id === trace.trace_id
                  ? 'border-sky-500/40 bg-sky-500/5'
                  : trace.decision === 'BLOCK'
                  ? 'border-red-500/30 bg-red-500/5 hover:border-red-500/50'
                  : 'border-zinc-800/50 bg-zinc-900/30 hover:border-zinc-700/50'
              }`}
            >
              <div className="flex items-start gap-2">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1 flex-wrap">
                    <span className="font-mono text-[10px] text-zinc-500">{trace.trace_id}</span>
                    <DecisionBadge decision={trace.decision as any} />
                  </div>
                  <div className="text-sm text-zinc-200 font-medium mb-1 leading-snug">{trace.name}</div>
                  <div className="flex items-center gap-2 text-[10px] text-zinc-500">
                    <span className="font-mono">{trace.agent_id}</span>
                    <span>•</span>
                    <span>{trace.spans.length} spans</span>
                    <span>•</span>
                    <span>{trace.duration_ms > 1000 ? `${(trace.duration_ms / 1000).toFixed(1)}s` : `${trace.duration_ms}ms`}</span>
                  </div>
                </div>
              </div>

              {/* Span timeline bar */}
              <div className="flex gap-0.5 mt-2 h-1.5 rounded overflow-hidden">
                {trace.spans.map(span => (
                  <div
                    key={span.span_id}
                    className={`${SPAN_COLORS[span.decision] || 'bg-zinc-600'} rounded-sm`}
                    style={{ flex: Math.max(span.duration_ms, 10) }}
                    title={`${span.name}: ${span.decision}`}
                  />
                ))}
              </div>
            </div>
          ))}
        </div>

        {/* Trace Detail */}
        <div className="col-span-3 rounded-xl border border-zinc-800/50 bg-zinc-900/30">
          {selectedTrace ? (
            <div className="p-4 space-y-4">
              <div>
                <div className="flex items-center gap-2 mb-1">
                  <DecisionBadge decision={selectedTrace.decision as any} />
                  <span className="font-mono text-[11px] text-zinc-500">{selectedTrace.trace_id}</span>
                </div>
                <h2 className="text-base font-semibold text-zinc-100">{selectedTrace.name}</h2>
                <p className="text-xs text-zinc-500 mt-1">Agent: {selectedTrace.agent_id} • Task: {selectedTrace.task_id}</p>
              </div>

              {/* Causal explanation */}
              <div className="rounded-lg bg-sky-500/5 border border-sky-500/20 p-3">
                <div className="text-[10px] uppercase tracking-wider text-sky-400 mb-1.5">Causal Explanation</div>
                <p className="text-xs text-zinc-300">{selectedTrace.causal_explanation}</p>
              </div>

              {/* Spans */}
              <div>
                <div className="text-[10px] uppercase tracking-wider text-zinc-500 mb-2">Execution Spans</div>
                <div className="space-y-2">
                  {selectedTrace.spans.map((span, i) => (
                    <div key={span.span_id} className={`rounded-lg border p-3 ${
                      span.decision === 'BLOCK' ? 'border-red-500/30 bg-red-500/5' : 'border-zinc-800/50 bg-zinc-900/20'
                    }`}>
                      <div className="flex items-center gap-2">
                        <span className="text-[10px] text-zinc-600 font-mono">{i + 1}</span>
                        <div className={`w-2 h-2 rounded-full ${SPAN_COLORS[span.decision] || 'bg-zinc-600'}`} />
                        <span className="font-mono text-xs text-zinc-300">{span.name}</span>
                        <div className="flex-1" />
                        <DecisionBadge decision={span.decision as any} />
                        <span className="text-[10px] text-zinc-600 font-mono">{span.duration_ms}ms</span>
                      </div>
                      {span.flags && (
                        <div className="flex gap-1.5 mt-1.5 flex-wrap">
                          {span.flags.map(f => (
                            <span key={f} className="text-[10px] px-1.5 py-0.5 rounded bg-red-500/10 border border-red-500/20 text-red-400">{f}</span>
                          ))}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>

              <div className="flex gap-3 pt-2">
                <Link href="/forensics" className="flex items-center gap-1 text-[11px] text-sky-400 hover:text-sky-300 transition-colors">
                  Full Forensics <ArrowRight size={11} />
                </Link>
                <Link href="/attack-graph" className="flex items-center gap-1 text-[11px] text-indigo-400 hover:text-indigo-300 transition-colors">
                  Attack Graph <ArrowRight size={11} />
                </Link>
              </div>
            </div>
          ) : (
            <div className="flex flex-col items-center justify-center h-64 text-zinc-600 text-sm">
              <GitBranch size={28} className="mb-2 opacity-30" />
              Select a trace to inspect
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
