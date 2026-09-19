'use client';

import { FlaskConical, Shield, Swords, Target, CheckCircle2, AlertTriangle, Play, RotateCcw, ArrowRight } from 'lucide-react';
import { DEMO_CAMPAIGNS } from '@/data/demo';
import Link from 'next/link';

const STRATEGIES = [
  { name: 'Prompt Injection', code: 'IPI', tested: 25, blocked: 25, bypasses: 0 },
  { name: 'Authority Escalation', code: 'AUTH_ESC', tested: 15, blocked: 15, bypasses: 0 },
  { name: 'Tool Poisoning', code: 'TOOL_POISON', tested: 10, blocked: 10, bypasses: 0 },
  { name: 'Taint Propagation', code: 'TAINT', tested: 12, blocked: 12, bypasses: 0 },
  { name: 'Delegation Escalation', code: 'DELEG_ESC', tested: 8, blocked: 8, bypasses: 0 },
];

export default function OffensivePage() {
  return (
    <div className="p-6 space-y-5 min-h-screen bg-[#090d16]">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-white flex items-center gap-2">
            <FlaskConical size={18} className="text-orange-400" />
            Offensive Validation
          </h1>
          <p className="text-sm text-zinc-500 mt-1">
            Phase 4/5 Adaptive Offensive Security — automated red-teaming of the AgentGuard runtime
          </p>
        </div>
        <div className="flex items-center gap-2">
          <div className="rounded-lg bg-emerald-500/10 border border-emerald-500/20 px-3 py-1.5 text-xs text-emerald-400 flex items-center gap-1.5">
            <Shield size={11} />
            LOCAL_ONLY · No external targets
          </div>
        </div>
      </div>

      {/* Phase 5 Headline */}
      <div className="grid grid-cols-5 gap-3">
        {[
          { label: 'Total Variants', value: '70', color: 'text-zinc-200', border: 'border-zinc-700/30', bg: 'bg-zinc-800/40' },
          { label: 'Blocked', value: '70/70', color: 'text-emerald-400', border: 'border-emerald-500/20', bg: 'bg-emerald-500/5' },
          { label: 'Bypasses Found', value: '0', color: 'text-emerald-400', border: 'border-emerald-500/20', bg: 'bg-emerald-500/5' },
          { label: 'Prevention Rate', value: '100%', color: 'text-emerald-400', border: 'border-emerald-500/20', bg: 'bg-emerald-500/5' },
          { label: 'Mutation Depth', value: '3', color: 'text-sky-400', border: 'border-sky-500/20', bg: 'bg-sky-500/5' },
        ].map(s => (
          <div key={s.label} className={`rounded-xl border ${s.border} ${s.bg} p-4 text-center`}>
            <div className="text-[10px] text-zinc-500 uppercase tracking-wider mb-1">{s.label}</div>
            <div className={`text-2xl font-bold font-mono ${s.color}`}>{s.value}</div>
          </div>
        ))}
      </div>

      {/* Attack Strategies */}
      <div className="rounded-xl border border-zinc-800/50 bg-zinc-900/30 p-4">
        <div className="text-[10px] uppercase tracking-wider text-zinc-500 mb-3">Attack Strategies Validated</div>
        <div className="space-y-2">
          {STRATEGIES.map(s => (
            <div key={s.code} className="flex items-center gap-3">
              <span className="font-mono text-[10px] text-zinc-500 w-20">{s.code}</span>
              <span className="text-xs text-zinc-300 flex-1">{s.name}</span>
              <span className="text-[10px] text-zinc-500">{s.tested} tested</span>
              <div className="w-24 h-1.5 bg-zinc-800 rounded-full overflow-hidden">
                <div className="h-full bg-emerald-500 rounded-full" style={{ width: `${(s.blocked / s.tested) * 100}%` }} />
              </div>
              <span className="text-[10px] text-emerald-400 font-bold w-16 text-right">{s.blocked}/{s.tested} blocked</span>
              {s.bypasses === 0
                ? <CheckCircle2 size={12} className="text-emerald-400 flex-shrink-0" />
                : <AlertTriangle size={12} className="text-red-400 flex-shrink-0" />
              }
            </div>
          ))}
        </div>
      </div>

      {/* CLI Commands */}
      <div className="rounded-xl border border-zinc-800/50 bg-black/40 p-4">
        <div className="text-[10px] uppercase tracking-wider text-zinc-500 mb-3">CLI — Run Adaptive Campaign</div>
        <div className="space-y-2 font-mono text-[11px]">
          {[
            ['# Run adaptive campaign', 'text-zinc-600'],
            ['python -m agentguard attack adaptive --limit 5 --max-depth 3 --seed 20260919', 'text-emerald-400'],
            ['', ''],
            ['# View mutation lineage', 'text-zinc-600'],
            ['python -m agentguard attack lineage atk_phase5_bypass_probe', 'text-sky-400'],
            ['', ''],
            ['# Explain a specific decision', 'text-zinc-600'],
            ['python -m agentguard attack explain atk_pinj_001', 'text-purple-400'],
            ['', ''],
            ['# View regression library', 'text-zinc-600'],
            ['python -m agentguard attack regressions', 'text-amber-400'],
          ].map(([cmd, color], i) => (
            <div key={i} className={color}>{cmd}</div>
          ))}
        </div>
      </div>

      {/* Quick nav */}
      <div className="grid grid-cols-2 gap-3">
        <Link href="/campaigns" className="flex items-center justify-between rounded-xl border border-red-500/20 bg-red-500/5 p-4 hover:border-red-500/40 transition-colors group">
          <div>
            <div className="text-xs font-semibold text-red-400 mb-1">Attack Campaigns</div>
            <div className="text-[10px] text-zinc-500">Full campaign results with mutation trees</div>
          </div>
          <ArrowRight size={14} className="text-red-400 group-hover:translate-x-1 transition-transform" />
        </Link>
        <Link href="/regressions" className="flex items-center justify-between rounded-xl border border-purple-500/20 bg-purple-500/5 p-4 hover:border-purple-500/40 transition-colors group">
          <div>
            <div className="text-xs font-semibold text-purple-400 mb-1">Regression Library</div>
            <div className="text-[10px] text-zinc-500">Before/after bypass verification fixtures</div>
          </div>
          <ArrowRight size={14} className="text-purple-400 group-hover:translate-x-1 transition-transform" />
        </Link>
      </div>
    </div>
  );
}
