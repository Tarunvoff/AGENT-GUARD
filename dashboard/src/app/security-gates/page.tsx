'use client';

import { useState, useEffect } from 'react';
import { Shield, CheckCircle2, XCircle, RefreshCw, ArrowRight, Lock, Zap, AlertTriangle, ChevronRight } from 'lucide-react';
import Link from 'next/link';

const API_BASE = 'http://127.0.0.1:8000/api/v1';

interface GateCheck {
  rule_name?: string;
  name?: string;
  passed: boolean;
  observed_value?: number | string;
  value?: number | string;
  threshold: number | string;
  description: string;
  failure_message?: string | null;
}

interface SecurityGateData {
  gate_id?: string;
  status?: string;
  overall_verdict?: string;
  passed?: boolean;
  exit_code?: number;
  campaign_name?: string;
  evaluated_at?: string;
  total_attacks_tested?: number;
  blocked_attacks_count?: number;
  bypassed_attacks_count?: number;
  bypassed_attacks?: number;
  unauthorized_db_calls?: number;
  open_regressions_count?: number;
  open_regressions?: number;
  failed_replays_count?: number;
  prevention_rate?: number;
  checks?: GateCheck[];
  summary?: string;
}

const DEMO_GATE: SecurityGateData = {
  status: 'PASSED',
  passed: true,
  overall_verdict: 'PASS',
  campaign_name: 'phase9_continuous_security_pipeline',
  evaluated_at: new Date().toISOString(),
  unauthorized_db_calls: 0,
  bypassed_attacks: 0,
  open_regressions: 0,
  prevention_rate: 100.0,
  summary: 'CI/CD Security Gate PASSED: All 6 checks satisfied.',
  checks: [
    { name: 'Zero Unauthorized DB Calls', rule_name: 'zero_unauthorized_db_calls', passed: true, value: 0, observed_value: 0, threshold: 0, description: 'No sensitive DB operations executed without authorization' },
    { name: 'Zero Bypasses', rule_name: 'zero_bypasses', passed: true, value: 0, observed_value: 0, threshold: 0, description: 'All attack variants were blocked or contained' },
    { name: 'Prevention Rate >= 95%', rule_name: 'minimum_block_rate', passed: true, value: 1.0, observed_value: 1.0, threshold: 1.0, description: 'Empirical block rate over full offensive campaign' },
    { name: 'No Failed Replays', rule_name: 'zero_failed_replays', passed: true, value: 0, observed_value: 0, threshold: 0, description: 'All secured regression replays confirmed BLOCK' },
    { name: 'Open Regressions <= 0', rule_name: 'zero_open_regressions', passed: true, value: 0, observed_value: 0, threshold: 0, description: 'Outstanding regression count within acceptable limit' },
    { name: 'Min Posture Score >= 75.0', rule_name: 'minimum_posture_score', passed: true, value: 98.0, observed_value: 98.0, threshold: 75.0, description: 'Runtime security posture score satisfies minimum threshold' },
  ],
};

export default function SecurityGatesPage() {
  const [gate, setGate] = useState<SecurityGateData | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [lastFetch, setLastFetch] = useState<Date | null>(null);

  const fetchGate = async () => {
    try {
      const res = await fetch(API_BASE + '/security-gates');
      if (!res.ok) throw new Error('HTTP ' + res.status);
      const data = await res.json();
      setGate(data);
      setLastFetch(new Date());
      setError(null);
    } catch (e: any) {
      setError(e.message || 'Failed to load');
      setGate(DEMO_GATE);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchGate(); }, []);

  const checks = gate?.checks ?? [];
  const passedCount = checks.filter(c => c.passed).length;
  const failedCount = checks.filter(c => !c.passed).length;
  const isPassed = gate?.status === 'PASSED' || gate?.overall_verdict === 'PASS' || (checks.length > 0 && failedCount === 0);

  return (
    <div className="p-6 space-y-6 min-h-screen bg-[#090d16]">
      <div className="flex items-start justify-between">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded border border-violet-500/40 bg-violet-500/10 text-violet-400">
              PHASE 9 — CI/CD SECURITY GATES
            </span>
          </div>
          <h1 className="text-xl font-bold text-white flex items-center gap-2">
            <Lock size={18} className="text-violet-400" />
            Security Quality Gates
          </h1>
          <p className="text-sm text-zinc-500 mt-1">CI/CD pipeline gate — automated enforcement validation before deployment</p>
        </div>
        <div className="flex items-center gap-3">
          {lastFetch && <span className="text-[10px] text-zinc-600 font-mono">Updated: {lastFetch.toLocaleTimeString()}</span>}
          <button onClick={fetchGate} className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-zinc-800 text-xs text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800/50 transition-colors cursor-pointer">
            <RefreshCw size={12} /> Refresh
          </button>
          <Link href="/posture" className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-violet-600 hover:bg-violet-500 text-xs font-semibold text-white transition-colors">
            Posture <ArrowRight size={12} />
          </Link>
        </div>
      </div>

      {error && (
        <div className="p-3 rounded-xl border border-amber-500/30 bg-amber-500/10 text-xs text-amber-300">
          ⚠ Backend unreachable ({error}) — showing fallback gate data
        </div>
      )}

      {gate && (
        <>
          {/* Overall verdict */}
          <div className={"p-5 rounded-xl border flex items-center justify-between " + (isPassed ? 'bg-emerald-500/10 border-emerald-500/30' : 'bg-red-500/10 border-red-500/30')}>
            <div className="flex items-center gap-4">
              <div className={"w-14 h-14 rounded-xl flex items-center justify-center " + (isPassed ? 'bg-emerald-500/20' : 'bg-red-500/20')}>
                {isPassed
                  ? <CheckCircle2 size={28} className="text-emerald-400" />
                  : <XCircle size={28} className="text-red-400" />
                }
              </div>
              <div>
                <div className={"text-3xl font-black font-mono " + (isPassed ? 'text-emerald-400' : 'text-red-400')}>
                  {gate.status ?? gate.overall_verdict ?? (isPassed ? 'PASSED' : 'FAILED')}
                </div>
                <div className="text-sm text-zinc-400 mt-0.5">Campaign: <span className="font-mono text-zinc-300">{gate.campaign_name ?? 'phase9_continuous'}</span></div>
                <div className="text-xs text-zinc-600 mt-0.5">
                  {gate.evaluated_at ? new Date(gate.evaluated_at).toLocaleString() : 'Live evaluation'}
                </div>
              </div>
            </div>
            <div className="text-right">
              <div className="text-2xl font-bold font-mono text-zinc-200">{passedCount} / {checks.length}</div>
              <div className="text-xs text-zinc-500">checks passed</div>
              {failedCount > 0 && <div className="text-xs text-red-400 font-bold mt-1">{failedCount} FAILED</div>}
            </div>
          </div>

          {/* Check list */}
          <div className="rounded-xl border border-zinc-800/50 bg-zinc-900/30 p-4 space-y-2">
            <div className="text-xs font-semibold text-zinc-300 mb-3 flex items-center gap-2">
              <Shield size={13} className="text-violet-400" /> Gate Checks
            </div>
            <div className="space-y-2">
              {checks.map((check: GateCheck, i: number) => {
                const observedVal = check.observed_value ?? check.value ?? 0;
                const checkName = check.name ?? check.rule_name?.replace(/_/g, ' ') ?? `Check ${i + 1}`;
                return (
                  <div key={i} className={"p-3.5 rounded-lg border flex items-start justify-between gap-4 " + (check.passed ? 'bg-emerald-500/5 border-emerald-500/20' : 'bg-red-500/10 border-red-500/30')}>
                    <div className="flex items-start gap-3">
                      <div className={"mt-0.5 w-5 h-5 rounded-full flex items-center justify-center flex-shrink-0 " + (check.passed ? 'bg-emerald-500/20' : 'bg-red-500/20')}>
                        {check.passed
                          ? <CheckCircle2 size={12} className="text-emerald-400" />
                          : <XCircle size={12} className="text-red-400" />
                        }
                      </div>
                      <div>
                        <div className="text-xs font-semibold text-zinc-200 capitalize">{checkName}</div>
                        <div className="text-[11px] text-zinc-500 mt-0.5">{check.description}</div>
                      </div>
                    </div>
                    <div className="text-right flex-shrink-0">
                      <div className={"text-sm font-bold font-mono " + (check.passed ? 'text-emerald-400' : 'text-red-400')}>
                        {typeof observedVal === 'number'
                          ? (observedVal % 1 === 0 ? observedVal.toString() : observedVal.toFixed(2))
                          : String(observedVal)}
                      </div>
                      <div className="text-[10px] text-zinc-600">
                        threshold: {typeof check.threshold === 'number' ? check.threshold : String(check.threshold)}
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Phase 9 key metrics */}
          <div className="grid grid-cols-4 gap-3">
            {[
              { label: 'Unauthorized DB Calls', value: gate.unauthorized_db_calls ?? 0, color: 'text-emerald-400', good: true },
              { label: 'Attack Bypasses', value: gate.bypassed_attacks_count ?? gate.bypassed_attacks ?? 0, color: 'text-emerald-400', good: true },
              { label: 'Prevention Rate', value: ((gate.prevention_rate ?? 100.0)).toFixed(1) + '%', color: 'text-emerald-400', good: true },
              { label: 'Open Regressions', value: gate.open_regressions_count ?? gate.open_regressions ?? 0, color: (gate.open_regressions_count ?? gate.open_regressions ?? 0) === 0 ? 'text-emerald-400' : 'text-amber-400', good: true },
            ].map(({ label, value, color }) => (
              <div key={label} className="rounded-xl border border-zinc-800/50 bg-zinc-900/30 p-3.5 text-center">
                <div className="text-[10px] text-zinc-500 uppercase tracking-wider mb-1">{label}</div>
                <div className={"text-2xl font-bold font-mono " + color}>{String(value)}</div>
              </div>
            ))}
          </div>

          <div className="flex items-center gap-4">
            <Link href="/posture" className="text-xs text-violet-400 hover:text-violet-300 flex items-center gap-1 transition-colors">
              <Shield size={11} /> Security Posture <ArrowRight size={10} />
            </Link>
            <Link href="/incidents" className="text-xs text-sky-400 hover:text-sky-300 flex items-center gap-1 transition-colors">
              <AlertTriangle size={11} /> Incidents <ArrowRight size={10} />
            </Link>
            <Link href="/regressions" className="text-xs text-purple-400 hover:text-purple-300 flex items-center gap-1 transition-colors">
              <Zap size={11} /> Regression Library <ArrowRight size={10} />
            </Link>
          </div>
        </>
      )}
    </div>
  );
}
