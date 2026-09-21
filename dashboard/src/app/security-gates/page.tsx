'use client';

import { useState, useEffect } from 'react';
import { Shield, CheckCircle2, XCircle, RefreshCw, AlertTriangle, Terminal, GitBranch } from 'lucide-react';
import { PageHeader } from '@/components/ui/PageHeader';
import { MetricCard } from '@/components/ui/MetricCard';
import { StatusBadge } from '@/components/ui/StatusBadge';
import { DataTable } from '@/components/ui/DataTable';

const API_BASE = '/api/v1';

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
    { name: 'Prevention Rate >= 95%', rule_name: 'minimum_block_rate', passed: true, value: '100%', observed_value: '100%', threshold: '95%', description: 'Empirical block rate over full offensive campaign' },
    { name: 'No Failed Replays', rule_name: 'zero_failed_replays', passed: true, value: 0, observed_value: 0, threshold: 0, description: 'All secured regression replays confirmed BLOCK' },
    { name: 'Open Regressions <= 0', rule_name: 'zero_open_regressions', passed: true, value: 0, observed_value: 0, threshold: 0, description: 'Outstanding regression count within acceptable limit' },
    { name: 'Min Posture Score >= 75.0', rule_name: 'minimum_posture_score', passed: true, value: '98.0', observed_value: '98.0', threshold: '75.0', description: 'Runtime security posture score satisfies minimum threshold' },
  ],
};

export default function SecurityGatesPage() {
  const [gate, setGate] = useState<SecurityGateData>(DEMO_GATE);
  const [loading, setLoading] = useState<boolean>(false);

  const fetchGate = async () => {
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/security-gates`);
      if (res.ok) {
        const data = await res.json();
        setGate(data);
      }
    } catch {
      // Demo gate used
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchGate();
  }, []);

  const checks = gate.checks ?? DEMO_GATE.checks ?? [];
  const passedCount = checks.filter(c => c.passed).length;
  const failedCount = checks.filter(c => !c.passed).length;
  const isPassed = failedCount === 0;

  const columns = [
    {
      key: 'name',
      header: 'Gate Rule Criteria',
      render: (row: GateCheck) => (
        <div className="flex items-center gap-2.5">
          {row.passed ? (
            <CheckCircle2 size={16} className="text-emerald-600 flex-shrink-0" />
          ) : (
            <XCircle size={16} className="text-red-600 flex-shrink-0" />
          )}
          <div>
            <div className="font-semibold text-xs text-slate-900">{row.name || row.rule_name}</div>
            <div className="text-[11px] text-slate-500">{row.description}</div>
          </div>
        </div>
      ),
    },
    {
      key: 'observed_value',
      header: 'Observed Value',
      width: '140px',
      render: (row: GateCheck) => (
        <span className="font-mono text-xs font-semibold text-slate-800">
          {String(row.observed_value ?? row.value ?? '0')}
        </span>
      ),
    },
    {
      key: 'threshold',
      header: 'Pass Threshold',
      width: '140px',
      render: (row: GateCheck) => (
        <span className="font-mono text-xs text-slate-500">
          {String(row.threshold)}
        </span>
      ),
    },
    {
      key: 'passed',
      header: 'Verdict',
      width: '120px',
      render: (row: GateCheck) => (
        <StatusBadge status={row.passed ? 'ALLOW' : 'BLOCK'} />
      ),
    },
  ];

  return (
    <div className="p-8 space-y-6 max-w-7xl mx-auto">
      <PageHeader
        title="CI/CD Security Gates"
        subtitle="Automated release gating criteria evaluating bypasses, regression fixture replays, and posture baselines"
        badge="CI/CD Enforcement"
        actions={
          <button
            onClick={fetchGate}
            disabled={loading}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-white border border-slate-200 rounded-md text-xs font-medium text-slate-700 hover:bg-slate-50 transition-colors shadow-2xs"
          >
            <RefreshCw size={13} className={loading ? 'animate-spin' : ''} />
            <span>Evaluate Gate</span>
          </button>
        }
      />

      {/* Release Decision Callout */}
      <div className={`p-4 rounded-lg border flex items-start justify-between ${
        isPassed ? 'bg-emerald-50/80 border-emerald-200' : 'bg-red-50/80 border-red-200'
      }`}>
        <div className="flex items-start gap-3">
          {isPassed ? (
            <CheckCircle2 size={18} className="text-emerald-700 mt-0.5" />
          ) : (
            <AlertTriangle size={18} className="text-red-700 mt-0.5" />
          )}
          <div>
            <div className="text-xs font-semibold uppercase tracking-wider text-slate-700">
              CI/CD Pipeline Decision
            </div>
            <div className="text-base font-bold text-slate-900 mt-0.5">
              {isPassed ? 'RELEASE APPROVED — All Security Gate Criteria Satisfied' : 'RELEASE BLOCKED — Security Criteria Violated'}
            </div>
            <p className="text-xs text-slate-600 mt-1">
              Evaluated pipeline build against deterministic invariants. Exit code: <span className="font-mono">{isPassed ? '0 (SUCCESS)' : '1 (FAILURE)'}</span>
            </p>
          </div>
        </div>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <MetricCard label="Total Gate Checks" value={checks.length} />
        <MetricCard label="Passed Criteria" value={`${passedCount} / ${checks.length}`} status="ALLOW" />
        <MetricCard label="Failed Criteria" value={failedCount} status={failedCount > 0 ? 'BLOCK' : 'ALLOW'} />
        <MetricCard label="Prevention Rate" value={`${gate.prevention_rate ?? 100}%`} status="ALLOW" />
      </div>

      {/* Gate Criteria Table */}
      <div className="bg-white border border-slate-200 rounded-lg p-5 shadow-xs space-y-4">
        <div className="text-xs font-semibold uppercase tracking-wider text-slate-500">Criteria Evaluation Matrix</div>
        <DataTable
          columns={columns}
          data={checks}
          keyField="rule_name"
          emptyMessage="No gate criteria defined."
        />
      </div>

      {/* CLI Reference */}
      <div className="bg-white border border-slate-200 rounded-lg p-5 shadow-xs space-y-3">
        <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-slate-500">
          <Terminal size={14} className="text-slate-600" />
          <span>CI/CD Pipeline Integration (GitHub Actions / GitLab CI)</span>
        </div>
        <div className="bg-slate-900 text-slate-100 rounded-lg p-4 font-mono text-xs space-y-1.5 border border-slate-800">
          <div className="text-slate-500"># Step in deployment pipeline: fail build if gates do not pass</div>
          <div className="text-emerald-400">python -m agentguard security-gate --strict --json-output gate_result.json</div>
        </div>
      </div>
    </div>
  );
}
