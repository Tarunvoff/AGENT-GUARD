'use client';

import { FlaskConical, Shield, Swords, Target, CheckCircle2, AlertTriangle, ArrowRight, Code, Terminal } from 'lucide-react';
import { PageHeader } from '@/components/ui/PageHeader';
import { MetricCard } from '@/components/ui/MetricCard';
import { StatusBadge } from '@/components/ui/StatusBadge';
import Link from 'next/link';

const STRATEGIES = [
  { name: 'Indirect Prompt Injection', code: 'IPI', tested: 25, blocked: 25, bypasses: 0 },
  { name: 'Authority Escalation', code: 'AUTH_ESC', tested: 15, blocked: 15, bypasses: 0 },
  { name: 'Tool Poisoning', code: 'TOOL_POISON', tested: 10, blocked: 10, bypasses: 0 },
  { name: 'Taint Leak Propagation', code: 'TAINT', tested: 12, blocked: 12, bypasses: 0 },
  { name: 'Delegation Escalation', code: 'DELEG_ESC', tested: 8, blocked: 8, bypasses: 0 },
];

export default function OffensivePage() {
  return (
    <div className="p-8 space-y-6 max-w-7xl mx-auto">
      <PageHeader
        title="Offensive Validation Suite"
        subtitle="Automated adversarial simulation and continuous red-teaming against the AgentGuard runtime"
        badge="Offensive Engine"
        actions={
          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-emerald-50 border border-emerald-200 text-xs text-emerald-800 font-medium">
            <Shield size={13} className="text-emerald-600" />
            <span>Target Mode: LOCAL_SANDBOX</span>
          </div>
        }
      />

      {/* KPI Headline */}
      <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
        <MetricCard label="Total Variants" value="70" />
        <MetricCard label="Total Blocked" value="70 / 70" status="ALLOW" />
        <MetricCard label="Bypasses Found" value="0" status="ALLOW" />
        <MetricCard label="Prevention Rate" value="100%" status="ALLOW" />
        <MetricCard label="Max Mutation Depth" value="Lvl 3" />
      </div>

      {/* Strategy Coverage Table / List */}
      <div className="bg-white border border-slate-200 rounded-lg p-5 shadow-xs space-y-4">
        <div className="text-xs font-semibold uppercase tracking-wider text-slate-500">Attack Strategy Coverage & Verification</div>
        <div className="divide-y divide-slate-100">
          {STRATEGIES.map(s => (
            <div key={s.code} className="py-3 flex items-center justify-between gap-4 text-xs">
              <div className="flex items-center gap-3 min-w-[200px]">
                <span className="font-mono text-[11px] font-semibold text-slate-600 bg-slate-100 px-2 py-0.5 rounded border border-slate-200">
                  {s.code}
                </span>
                <span className="font-medium text-slate-900">{s.name}</span>
              </div>

              <div className="flex items-center gap-4 flex-1 max-w-xs">
                <div className="w-full bg-slate-100 rounded-full h-1.5 overflow-hidden">
                  <div
                    className="h-full bg-emerald-500 rounded-full"
                    style={{ width: `${(s.blocked / s.tested) * 100}%` }}
                  />
                </div>
                <span className="font-mono text-slate-500 text-[11px] whitespace-nowrap">
                  {s.tested} variants
                </span>
              </div>

              <div className="flex items-center gap-3">
                <span className="font-mono font-semibold text-emerald-700 bg-emerald-50 px-2 py-0.5 rounded border border-emerald-200">
                  {s.blocked}/{s.tested} Blocked
                </span>
                <CheckCircle2 size={15} className="text-emerald-600" />
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* CLI Reference Block */}
      <div className="bg-white border border-slate-200 rounded-lg p-5 shadow-xs space-y-3">
        <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-slate-500">
          <Terminal size={14} className="text-slate-600" />
          <span>CLI — Trigger Local Validation Suites</span>
        </div>
        <div className="bg-slate-900 text-slate-100 rounded-lg p-4 font-mono text-xs space-y-2 border border-slate-800">
          <div className="text-slate-500"># Run adaptive campaign against local agent targets</div>
          <div className="text-emerald-400">python -m agentguard attack adaptive --limit 5 --max-depth 3 --seed 20260919</div>
          <div className="text-slate-500 pt-2"># View full mutation lineage graph</div>
          <div className="text-sky-400">python -m agentguard attack lineage atk_phase5_bypass_probe</div>
          <div className="text-slate-500 pt-2"># Execute historical regression replay suite</div>
          <div className="text-amber-300">python -m agentguard attack regressions</div>
        </div>
      </div>

      {/* Quick Navigation Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Link
          href="/campaigns"
          className="p-4 bg-white border border-slate-200 rounded-lg shadow-xs hover:border-blue-300 transition-colors flex items-center justify-between"
        >
          <div>
            <div className="text-xs font-semibold text-slate-900 mb-0.5">View Validation Campaigns</div>
            <div className="text-[11px] text-slate-500">Inspect individual campaign results, latency percentiles, and graphs</div>
          </div>
          <ArrowRight size={16} className="text-slate-400" />
        </Link>
        <Link
          href="/regressions"
          className="p-4 bg-white border border-slate-200 rounded-lg shadow-xs hover:border-blue-300 transition-colors flex items-center justify-between"
        >
          <div>
            <div className="text-xs font-semibold text-slate-900 mb-0.5">Explore Regression Library</div>
            <div className="text-[11px] text-slate-500">Review historical security patches and verified regression fixtures</div>
          </div>
          <ArrowRight size={16} className="text-slate-400" />
        </Link>
      </div>
    </div>
  );
}
