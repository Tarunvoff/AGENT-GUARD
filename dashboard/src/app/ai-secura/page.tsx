'use client';

import { Brain, Shield, AlertTriangle, CheckCircle2, TrendingUp, Zap, Activity } from 'lucide-react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, RadarChart, PolarGrid, PolarAngleAxis, Radar } from 'recharts';

const THREAT_TIMELINE = [
  { time: '08:00', threat: 0.12, confidence: 0.95 },
  { time: '09:00', threat: 0.31, confidence: 0.87 },
  { time: '09:11', threat: 0.89, confidence: 0.92 },
  { time: '09:30', threat: 0.45, confidence: 0.88 },
  { time: '10:00', threat: 0.21, confidence: 0.94 },
  { time: '10:30', threat: 0.82, confidence: 0.91 },
  { time: '10:45', threat: 0.97, confidence: 0.96 },
  { time: '11:00', threat: 0.18, confidence: 0.97 },
];

const THREAT_DIMENSIONS = [
  { dimension: 'Prompt Injection', score: 87 },
  { dimension: 'Data Exfil', score: 73 },
  { dimension: 'Auth Escalation', score: 91 },
  { dimension: 'Tool Poisoning', score: 65 },
  { dimension: 'Taint Propagation', score: 78 },
  { dimension: 'Intent Mismatch', score: 84 },
];

const RECENT_AI_ANALYSES = [
  {
    id: 'ai_001',
    event_id: 'evt_pinj_001',
    timestamp: '2026-09-19T10:45:00Z',
    intent_aligned: false,
    threat_severity: 0.97,
    threat_category: 'prompt_injection',
    confidence: 0.96,
    reasoning: 'Detected adversarial instruction in MCP tool response. Original task intent (financial analysis) diverged from detected action intent (data exfiltration). High confidence manipulation pattern.',
    policy_overridden: false,
    final_decision: 'BLOCK',
  },
  {
    id: 'ai_002',
    event_id: 'evt_auth_001',
    timestamp: '2026-09-19T10:30:00Z',
    intent_aligned: false,
    threat_severity: 0.82,
    threat_category: 'authority_escalation',
    confidence: 0.91,
    reasoning: 'Agent requested capabilities significantly exceeding delegated authority scope. Pattern consistent with privilege escalation attempt. Delegation graph analysis confirms violation.',
    policy_overridden: false,
    final_decision: 'BLOCK',
  },
  {
    id: 'ai_003',
    event_id: 'evt_q3_001',
    timestamp: '2026-09-19T08:05:00Z',
    intent_aligned: true,
    threat_severity: 0.08,
    threat_category: null,
    confidence: 0.98,
    reasoning: 'Task intent (Q3 financial analysis) aligns with all tool calls made. No taint propagation detected. Authority within delegated bounds.',
    policy_overridden: false,
    final_decision: 'ALLOW',
  },
];

export default function AiSecuraPage() {
  return (
    <div className="p-6 space-y-5 min-h-screen bg-[#090d16]">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-white flex items-center gap-2">
            <Brain size={18} className="text-purple-400" />
            AI Secura
          </h1>
          <p className="text-sm text-zinc-500 mt-1">
            AI-powered threat reasoning — advises enforcement. Deterministic policy always has final authority.
          </p>
        </div>
        <div className="rounded-lg bg-purple-500/10 border border-purple-500/20 px-3 py-1.5 text-xs text-purple-400 flex items-center gap-1.5">
          <Activity size={11} className="animate-pulse" />
          LOCAL MODEL ACTIVE
        </div>
      </div>

      {/* Key Principle */}
      <div className="rounded-xl border border-amber-500/20 bg-amber-500/5 p-3 flex items-start gap-2">
        <AlertTriangle size={14} className="text-amber-400 mt-0.5 flex-shrink-0" />
        <div className="text-xs text-amber-300">
          <span className="font-semibold">AI Reasons — Policy Enforces:</span> AI Secura provides intent alignment analysis, threat severity scoring, and threat categorization.
          The <span className="font-semibold">deterministic PolicyEvaluator</span> makes the final ALLOW/HITL/BLOCK decision. AI output cannot override policy.
          If AI is unavailable, the system fail-safe blocks tainted actions.
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-4 gap-3">
        <div className="rounded-xl border border-purple-500/20 bg-purple-500/5 p-4 text-center">
          <div className="text-[10px] text-zinc-500 uppercase tracking-wider mb-1">Analyses (24h)</div>
          <div className="text-2xl font-bold font-mono text-purple-400">47</div>
        </div>
        <div className="rounded-xl border border-red-500/20 bg-red-500/5 p-4 text-center">
          <div className="text-[10px] text-zinc-500 uppercase tracking-wider mb-1">High Threat</div>
          <div className="text-2xl font-bold font-mono text-red-400">4</div>
        </div>
        <div className="rounded-xl border border-emerald-500/20 bg-emerald-500/5 p-4 text-center">
          <div className="text-[10px] text-zinc-500 uppercase tracking-wider mb-1">Avg Confidence</div>
          <div className="text-2xl font-bold font-mono text-emerald-400">93.4%</div>
        </div>
        <div className="rounded-xl border border-sky-500/20 bg-sky-500/5 p-4 text-center">
          <div className="text-[10px] text-zinc-500 uppercase tracking-wider mb-1">Intent Aligned</div>
          <div className="text-2xl font-bold font-mono text-sky-400">43 / 47</div>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-4">
        {/* Threat Timeline */}
        <div className="rounded-xl border border-zinc-800/50 bg-zinc-900/30 p-4">
          <div className="text-[10px] uppercase tracking-wider text-zinc-500 mb-3">Threat Severity Timeline (Today)</div>
          <ResponsiveContainer width="100%" height={180}>
            <AreaChart data={THREAT_TIMELINE} margin={{ top: 5, right: 5, bottom: 0, left: -20 }}>
              <defs>
                <linearGradient id="threatGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#ef4444" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" />
              <XAxis dataKey="time" stroke="#374151" tick={{ fill: '#6b7280', fontSize: 10 }} />
              <YAxis stroke="#374151" tick={{ fill: '#6b7280', fontSize: 10 }} domain={[0, 1]} />
              <Tooltip contentStyle={{ background: '#0c1119', border: '1px solid #1f2937', borderRadius: 8, fontSize: 11 }} />
              <Area type="monotone" dataKey="threat" stroke="#ef4444" fill="url(#threatGrad)" strokeWidth={2} dot={{ fill: '#ef4444', r: 3 }} />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        {/* Threat Dimensions */}
        <div className="rounded-xl border border-zinc-800/50 bg-zinc-900/30 p-4">
          <div className="text-[10px] uppercase tracking-wider text-zinc-500 mb-3">Threat Category Scores</div>
          <div className="space-y-2">
            {THREAT_DIMENSIONS.map(d => (
              <div key={d.dimension} className="flex items-center gap-3">
                <span className="text-[11px] text-zinc-400 w-32 truncate">{d.dimension}</span>
                <div className="flex-1 h-1.5 bg-zinc-800 rounded-full overflow-hidden">
                  <div
                    className={`h-full rounded-full ${d.score > 80 ? 'bg-red-500' : d.score > 60 ? 'bg-amber-500' : 'bg-emerald-500'}`}
                    style={{ width: `${d.score}%` }}
                  />
                </div>
                <span className={`text-[11px] font-mono font-bold w-8 text-right ${d.score > 80 ? 'text-red-400' : d.score > 60 ? 'text-amber-400' : 'text-emerald-400'}`}>
                  {d.score}
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Recent Analyses */}
      <div>
        <div className="text-[10px] uppercase tracking-wider text-zinc-500 mb-3">Recent AI Analyses</div>
        <div className="space-y-3">
          {RECENT_AI_ANALYSES.map(a => (
            <div key={a.id} className={`rounded-xl border p-4 ${a.intent_aligned ? 'border-zinc-800/50 bg-zinc-900/30' : 'border-red-500/30 bg-red-500/5'}`}>
              <div className="flex items-start gap-3">
                {a.intent_aligned
                  ? <CheckCircle2 size={15} className="text-emerald-400 mt-0.5 flex-shrink-0" />
                  : <AlertTriangle size={15} className="text-red-400 mt-0.5 flex-shrink-0" />
                }
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1 flex-wrap">
                    <span className="font-mono text-[10px] text-zinc-500">{a.event_id}</span>
                    {a.threat_category && (
                      <span className="text-[10px] text-red-400 bg-red-500/10 border border-red-500/20 px-1.5 py-0.5 rounded">{a.threat_category}</span>
                    )}
                    <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded border ${
                      a.final_decision === 'BLOCK' ? 'text-red-400 border-red-500/30 bg-red-500/10' : 'text-emerald-400 border-emerald-500/20 bg-emerald-500/10'
                    }`}>{a.final_decision}</span>
                  </div>
                  <p className="text-xs text-zinc-400 mb-2">{a.reasoning}</p>
                  <div className="flex items-center gap-4 text-[10px] text-zinc-600">
                    <span>Threat: <span className={a.threat_severity > 0.5 ? 'text-red-400 font-bold' : 'text-emerald-400'}>{(a.threat_severity * 100).toFixed(0)}%</span></span>
                    <span>Confidence: <span className="text-zinc-300">{(a.confidence * 100).toFixed(0)}%</span></span>
                    <span className="font-mono">{new Date(a.timestamp).toLocaleTimeString()}</span>
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
