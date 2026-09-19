'use client';

import { Grid, CheckCircle2, XCircle, Clock, Minus } from 'lucide-react';

const AGENTS = ['orchestrator_v2', 'data_agent', 'report_agent', 'analyst_agent', 'escalation_agent'];
const RESOURCES = ['customers_db', 'orders_db', 'financials_file', 's3_exports', 'email_api', 'audit_log'];

type AccessLevel = 'ALLOW' | 'BLOCK' | 'HITL' | 'NONE';

const ACCESS_MATRIX: Record<string, Record<string, AccessLevel>> = {
  orchestrator_v2: {
    customers_db: 'ALLOW', orders_db: 'ALLOW', financials_file: 'ALLOW',
    s3_exports: 'BLOCK', email_api: 'BLOCK', audit_log: 'ALLOW',
  },
  data_agent: {
    customers_db: 'HITL', orders_db: 'ALLOW', financials_file: 'BLOCK',
    s3_exports: 'BLOCK', email_api: 'BLOCK', audit_log: 'NONE',
  },
  report_agent: {
    customers_db: 'NONE', orders_db: 'ALLOW', financials_file: 'NONE',
    s3_exports: 'BLOCK', email_api: 'BLOCK', audit_log: 'ALLOW',
  },
  analyst_agent: {
    customers_db: 'NONE', orders_db: 'NONE', financials_file: 'ALLOW',
    s3_exports: 'BLOCK', email_api: 'BLOCK', audit_log: 'ALLOW',
  },
  escalation_agent: {
    customers_db: 'BLOCK', orders_db: 'NONE', financials_file: 'NONE',
    s3_exports: 'BLOCK', email_api: 'BLOCK', audit_log: 'NONE',
  },
};

const CELL_STYLES: Record<AccessLevel, string> = {
  ALLOW: 'bg-emerald-500/15 border-emerald-500/30 text-emerald-400',
  BLOCK: 'bg-red-500/10 border-red-500/20 text-red-400',
  HITL: 'bg-amber-500/10 border-amber-500/20 text-amber-400',
  NONE: 'bg-zinc-900/20 border-zinc-800/30 text-zinc-700',
};

const CELL_ICONS: Record<AccessLevel, React.ElementType> = {
  ALLOW: CheckCircle2,
  BLOCK: XCircle,
  HITL: Clock,
  NONE: Minus,
};

export default function AccessMatrixPage() {
  return (
    <div className="p-6 space-y-5 min-h-screen bg-[#090d16]">
      <div>
        <h1 className="text-xl font-bold text-white flex items-center gap-2">
          <Grid size={18} className="text-sky-400" />
          Access Matrix
        </h1>
        <p className="text-sm text-zinc-500 mt-1">
          Agent × Resource permission matrix enforced by deterministic PolicyEvaluator
        </p>
      </div>

      {/* Legend */}
      <div className="flex gap-4">
        {([['ALLOW', 'emerald'], ['HITL', 'amber'], ['BLOCK', 'red'], ['NONE', 'zinc']] as const).map(([label]) => {
          const style = CELL_STYLES[label as AccessLevel];
          const Icon = CELL_ICONS[label as AccessLevel];
          return (
            <div key={label} className={`flex items-center gap-1.5 text-xs px-2 py-1 rounded border ${style}`}>
              <Icon size={11} />
              {label}
            </div>
          );
        })}
      </div>

      {/* Matrix */}
      <div className="overflow-x-auto">
        <table className="w-full border-collapse">
          <thead>
            <tr>
              <th className="text-left text-[10px] uppercase tracking-wider text-zinc-500 pb-3 pr-4 min-w-[140px]">Agent ↓ / Resource →</th>
              {RESOURCES.map(r => (
                <th key={r} className="text-center pb-3 px-2 min-w-[100px]">
                  <span className="text-[10px] uppercase tracking-wider text-zinc-400 font-semibold block">
                    {r.replace('_', ' ')}
                  </span>
                </th>
              ))}
            </tr>
          </thead>
          <tbody className="space-y-2">
            {AGENTS.map(agent => (
              <tr key={agent} className="border-t border-zinc-800/30">
                <td className="py-2 pr-4">
                  <span className="font-mono text-xs text-zinc-300 bg-zinc-800/60 px-2 py-1 rounded">{agent}</span>
                </td>
                {RESOURCES.map(res => {
                  const level = ACCESS_MATRIX[agent]?.[res] ?? 'NONE';
                  const Icon = CELL_ICONS[level];
                  const style = CELL_STYLES[level];
                  return (
                    <td key={res} className="py-2 px-2">
                      <div className={`flex items-center justify-center gap-1 rounded-lg border py-1.5 ${style}`}>
                        <Icon size={12} />
                        <span className="text-[10px] font-semibold">{level}</span>
                      </div>
                    </td>
                  );
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Stats row */}
      <div className="grid grid-cols-3 gap-3 pt-2">
        <div className="rounded-xl border border-emerald-500/20 bg-emerald-500/5 p-3 text-center">
          <div className="text-[10px] text-zinc-500 uppercase tracking-wider mb-1">Allowed Pairs</div>
          <div className="text-xl font-bold font-mono text-emerald-400">
            {AGENTS.reduce((s, a) => s + RESOURCES.filter(r => ACCESS_MATRIX[a]?.[r] === 'ALLOW').length, 0)}
          </div>
        </div>
        <div className="rounded-xl border border-amber-500/20 bg-amber-500/5 p-3 text-center">
          <div className="text-[10px] text-zinc-500 uppercase tracking-wider mb-1">HITL Required</div>
          <div className="text-xl font-bold font-mono text-amber-400">
            {AGENTS.reduce((s, a) => s + RESOURCES.filter(r => ACCESS_MATRIX[a]?.[r] === 'HITL').length, 0)}
          </div>
        </div>
        <div className="rounded-xl border border-red-500/20 bg-red-500/5 p-3 text-center">
          <div className="text-[10px] text-zinc-500 uppercase tracking-wider mb-1">Blocked Pairs</div>
          <div className="text-xl font-bold font-mono text-red-400">
            {AGENTS.reduce((s, a) => s + RESOURCES.filter(r => ACCESS_MATRIX[a]?.[r] === 'BLOCK').length, 0)}
          </div>
        </div>
      </div>
    </div>
  );
}
