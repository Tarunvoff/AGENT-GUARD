'use client';

import { DEMO_REGRESSIONS } from '@/data/demo';
import { DecisionBadge, SectionHeader, EmptyState } from '@/components/ui/security';
import { RotateCcw, CheckCircle2, XCircle, ArrowRight } from 'lucide-react';
import Link from 'next/link';

export default function RegressionsPage() {
  return (
    <div className="p-6 space-y-5 min-h-screen bg-[#090d16]">
      <div>
        <h1 className="text-xl font-bold text-white flex items-center gap-2">
          <RotateCcw size={18} className="text-purple-400" />
          Regression Library
        </h1>
        <p className="text-sm text-zinc-500 mt-1">
          Attack scenarios where bypass was observed. Each is archived as a regression fixture and replayed to verify the fix.
        </p>
      </div>

      {/* Summary */}
      <div className="grid grid-cols-3 gap-3">
        <div className="rounded-xl border border-zinc-800/50 bg-zinc-900/40 p-3 text-center">
          <div className="text-[10px] text-zinc-500 uppercase tracking-wider mb-1">Total Regressions</div>
          <div className="text-2xl font-bold font-mono text-purple-400">{DEMO_REGRESSIONS.length}</div>
        </div>
        <div className="rounded-xl border border-emerald-500/20 bg-emerald-500/5 p-3 text-center">
          <div className="text-[10px] text-zinc-500 uppercase tracking-wider mb-1">Secured</div>
          <div className="text-2xl font-bold font-mono text-emerald-400">
            {DEMO_REGRESSIONS.filter(r => r.secured).length} / {DEMO_REGRESSIONS.length}
          </div>
        </div>
        <div className="rounded-xl border border-zinc-800/50 bg-zinc-900/40 p-3 text-center">
          <div className="text-[10px] text-zinc-500 uppercase tracking-wider mb-1">Sensitive DB (before)</div>
          <div className="text-2xl font-bold font-mono text-red-400">
            {DEMO_REGRESSIONS.reduce((s, r) => s + r.sensitive_db_calls_before, 0)}
          </div>
        </div>
      </div>

      {/* Regression list */}
      <div className="space-y-3">
        {DEMO_REGRESSIONS.map(reg => (
          <div key={reg.regression_id}
            className="rounded-xl border border-zinc-800/50 bg-zinc-900/40 p-5">
            <div className="flex items-start justify-between mb-3">
              <div>
                <div className="flex items-center gap-2 mb-1">
                  <span className="font-mono text-sm font-bold text-purple-400">{reg.regression_id.toUpperCase()}</span>
                  <span className={`text-[10px] px-1.5 py-0.5 rounded border font-bold ${
                    reg.secured
                      ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-400'
                      : 'border-red-500/30 bg-red-500/10 text-red-400'
                  }`}>
                    {reg.secured ? 'SECURED' : 'OPEN'}
                  </span>
                </div>
                <div className="text-xs text-zinc-400">{reg.attack_type.replace(/_/g, ' ')}</div>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-[10px] text-zinc-600">Attack: {reg.attack_id}</span>
              </div>
            </div>

            {/* Before / After grid */}
            <div className="grid grid-cols-3 gap-3 text-xs">
              <div className="rounded-lg bg-zinc-900/60 border border-zinc-800/60 p-3">
                <div className="text-[9px] text-zinc-600 uppercase tracking-wider mb-2">Expected Decision</div>
                <DecisionBadge decision={reg.expected_decision} size="md" />
              </div>
              <div className="rounded-lg bg-red-500/5 border border-red-500/20 p-3">
                <div className="text-[9px] text-zinc-600 uppercase tracking-wider mb-2">Observed (Before Fix)</div>
                <DecisionBadge decision={reg.observed_decision} size="md" />
                <div className="text-[10px] text-red-400 mt-1.5 font-semibold">
                  sensitive_db_calls: {reg.sensitive_db_calls_before}
                </div>
              </div>
              <div className="rounded-lg bg-emerald-500/5 border border-emerald-500/20 p-3">
                <div className="text-[9px] text-zinc-600 uppercase tracking-wider mb-2">Secured Replay</div>
                <DecisionBadge decision={reg.replay_decision ?? 'BLOCK'} size="md" />
                <div className="text-[10px] text-emerald-400 mt-1.5 font-semibold">
                  sensitive_db_calls: {reg.sensitive_db_calls_after}
                </div>
              </div>
            </div>

            {/* Mutation lineage */}
            <div className="mt-3 pt-3 border-t border-zinc-800/40">
              <div className="text-[10px] text-zinc-600 mb-1.5 uppercase tracking-wider">Mutation Lineage</div>
              <div className="flex items-center gap-1 flex-wrap">
                {reg.mutation_lineage.map((id, i) => (
                  <span key={id} className="flex items-center gap-1">
                    <span className="text-[10px] font-mono bg-zinc-800/60 px-2 py-0.5 rounded text-zinc-400">{id}</span>
                    {i < reg.mutation_lineage.length - 1 && <ArrowRight size={9} className="text-zinc-700" />}
                  </span>
                ))}
              </div>
            </div>

            <div className="flex items-center gap-3 mt-3">
              <Link href="/campaigns" className="text-[11px] text-sky-400 hover:text-sky-300 flex items-center gap-1">
                View campaign <ArrowRight size={10} />
              </Link>
              <Link href="/forensics" className="text-[11px] text-sky-400 hover:text-sky-300 flex items-center gap-1">
                Forensic report <ArrowRight size={10} />
              </Link>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
