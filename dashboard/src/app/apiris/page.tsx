'use client';

import { Zap, AlertTriangle, CheckCircle2, TrendingUp, Activity, Shield, ExternalLink } from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, ScatterChart, Scatter, ZAxis } from 'recharts';

const APIRIS_RISK_DISTRIBUTION = [
  { range: '0.0-0.2', count: 12, label: 'Safe' },
  { range: '0.2-0.4', count: 8, label: 'Low' },
  { range: '0.4-0.6', count: 5, label: 'Medium' },
  { range: '0.6-0.8', count: 3, label: 'High' },
  { range: '0.8-1.0', count: 4, label: 'Critical' },
];

const APIRIS_SIGNALS = [
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

const SCORE_COLOR = (s: number) => s > 0.8 ? 'text-red-400' : s > 0.6 ? 'text-orange-400' : s > 0.4 ? 'text-amber-400' : 'text-emerald-400';
const SCORE_BG = (s: number) => s > 0.8 ? 'bg-red-500' : s > 0.6 ? 'bg-orange-500' : s > 0.4 ? 'bg-amber-500' : 'bg-emerald-500';

export default function ApirisPage() {
  return (
    <div className="p-6 space-y-5 min-h-screen bg-[#090d16]">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-white flex items-center gap-2">
            <Zap size={18} className="text-yellow-400" />
            APIRIS
          </h1>
          <p className="text-sm text-zinc-500 mt-1">
            API Risk Intelligence System — real-time anomaly detection on all tool and API calls
          </p>
        </div>
        <div className="rounded-lg bg-yellow-500/10 border border-yellow-500/20 px-3 py-1.5 text-xs text-yellow-400 flex items-center gap-1.5">
          <Activity size={11} className="animate-pulse" />
          ANALYZING
        </div>
      </div>

      {/* Architecture note */}
      <div className="rounded-xl border border-sky-500/20 bg-sky-500/5 p-3 flex items-start gap-2">
        <Shield size={14} className="text-sky-400 mt-0.5 flex-shrink-0" />
        <div className="text-xs text-sky-300">
          <span className="font-semibold">APIRIS Pipeline:</span> Every tool/API call is scored before execution.
          Scores ≥ 0.8 trigger immediate BLOCK. Scores 0.5–0.8 escalate to AI Secura for intent analysis.
          All scores feed deterministic PolicyEvaluator.
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-4 gap-3">
        <div className="rounded-xl border border-yellow-500/20 bg-yellow-500/5 p-4 text-center">
          <div className="text-[10px] text-zinc-500 uppercase tracking-wider mb-1">Calls Analyzed</div>
          <div className="text-2xl font-bold font-mono text-yellow-400">47</div>
        </div>
        <div className="rounded-xl border border-red-500/20 bg-red-500/5 p-4 text-center">
          <div className="text-[10px] text-zinc-500 uppercase tracking-wider mb-1">Critical Signals</div>
          <div className="text-2xl font-bold font-mono text-red-400">3</div>
        </div>
        <div className="rounded-xl border border-amber-500/20 bg-amber-500/5 p-4 text-center">
          <div className="text-[10px] text-zinc-500 uppercase tracking-wider mb-1">Avg Score</div>
          <div className="text-2xl font-bold font-mono text-amber-400">0.47</div>
        </div>
        <div className="rounded-xl border border-emerald-500/20 bg-emerald-500/5 p-4 text-center">
          <div className="text-[10px] text-zinc-500 uppercase tracking-wider mb-1">APIRIS Unavailable</div>
          <div className="text-2xl font-bold font-mono text-emerald-400">0</div>
        </div>
      </div>

      {/* Risk Distribution */}
      <div className="rounded-xl border border-zinc-800/50 bg-zinc-900/30 p-4">
        <div className="text-[10px] uppercase tracking-wider text-zinc-500 mb-3">Risk Score Distribution</div>
        <ResponsiveContainer width="100%" height={160}>
          <BarChart data={APIRIS_RISK_DISTRIBUTION} margin={{ top: 0, right: 0, bottom: 0, left: -20 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" />
            <XAxis dataKey="range" stroke="#374151" tick={{ fill: '#6b7280', fontSize: 10 }} />
            <YAxis stroke="#374151" tick={{ fill: '#6b7280', fontSize: 10 }} />
            <Tooltip contentStyle={{ background: '#0c1119', border: '1px solid #1f2937', borderRadius: 8, fontSize: 11 }} />
            <Bar dataKey="count" fill="#60a5fa" radius={[4, 4, 0, 0]}
              label={false}
              // Color by risk range
              isAnimationActive={false}
            />
          </BarChart>
        </ResponsiveContainer>
      </div>

      {/* Signals */}
      <div>
        <div className="text-[10px] uppercase tracking-wider text-zinc-500 mb-3">Recent APIRIS Signals</div>
        <div className="space-y-3">
          {APIRIS_SIGNALS.map(sig => (
            <div key={sig.signal_id} className={`rounded-xl border p-4 ${sig.score > 0.8 ? 'border-red-500/30 bg-red-500/5' : sig.score > 0.5 ? 'border-amber-500/20 bg-amber-500/5' : 'border-zinc-800/50 bg-zinc-900/30'}`}>
              <div className="flex items-start gap-3">
                <Zap size={15} className={`${SCORE_COLOR(sig.score)} mt-0.5 flex-shrink-0`} />
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1 flex-wrap">
                    <span className="font-mono text-xs text-zinc-300">{sig.tool}</span>
                    <span className="text-[10px] text-zinc-500 bg-zinc-800/60 px-1.5 py-0.5 rounded">{sig.signal_type}</span>
                    <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded border ${
                      sig.action_taken === 'BLOCK' ? 'text-red-400 border-red-500/30 bg-red-500/10' :
                      sig.action_taken === 'HITL' ? 'text-amber-400 border-amber-500/20 bg-amber-500/10' :
                      'text-emerald-400 border-emerald-500/20 bg-emerald-500/10'
                    }`}>{sig.action_taken}</span>
                  </div>
                  <p className="text-xs text-zinc-500 mb-2">{sig.description}</p>

                  {/* Risk score bar */}
                  <div className="flex items-center gap-2 mb-2">
                    <span className="text-[10px] text-zinc-600">Risk</span>
                    <div className="flex-1 h-1.5 bg-zinc-800 rounded-full overflow-hidden">
                      <div className={`h-full rounded-full ${SCORE_BG(sig.score)}`} style={{ width: `${sig.score * 100}%` }} />
                    </div>
                    <span className={`text-[11px] font-mono font-bold ${SCORE_COLOR(sig.score)}`}>{sig.score.toFixed(2)}</span>
                  </div>

                  {sig.anomaly_flags.length > 0 && (
                    <div className="flex gap-1.5 flex-wrap">
                      {sig.anomaly_flags.map(f => (
                        <span key={f} className="text-[10px] px-1.5 py-0.5 rounded bg-red-500/10 border border-red-500/20 text-red-400 font-mono">{f}</span>
                      ))}
                    </div>
                  )}
                  <div className="text-[10px] text-zinc-600 font-mono mt-1.5">{new Date(sig.timestamp).toLocaleTimeString()}</div>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
