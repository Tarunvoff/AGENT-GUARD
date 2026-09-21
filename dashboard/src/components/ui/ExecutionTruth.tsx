import React from 'react';
import { Check, X, ShieldAlert } from 'lucide-react';

interface ExecutionTruthProps {
  intended?: boolean | null;
  requested?: boolean | null;
  allowed?: boolean | null;
  executed?: boolean | null;
  blockedAt?: string;
}

export function ExecutionTruth({
  intended = true,
  requested = true,
  allowed = false,
  executed = false,
  blockedAt = 'Deterministic Policy Gate',
}: ExecutionTruthProps) {
  const steps = [
    { label: 'INTENDED', state: intended },
    { label: 'REQUESTED', state: requested },
    { label: 'ALLOWED', state: allowed },
    { label: 'EXECUTED', state: executed },
  ];

  return (
    <div className="bg-slate-50 border border-slate-200 rounded-lg p-3">
      <div className="text-[10px] font-semibold uppercase tracking-wider text-slate-500 mb-2 flex items-center justify-between">
        <span>Execution Truth Pipeline</span>
        {!executed && allowed === false && (
          <span className="inline-flex items-center gap-1 text-red-700 font-semibold text-[10px]">
            <ShieldAlert size={11} /> Blocked at: {blockedAt}
          </span>
        )}
      </div>

      <div className="grid grid-cols-4 gap-2">
        {steps.map((step, idx) => {
          const isOk = step.state === true;
          const isBlocked = step.state === false;
          return (
            <div
              key={step.label}
              className={`p-2 rounded border text-center ${
                isOk
                  ? 'bg-emerald-50 border-emerald-200 text-emerald-800'
                  : isBlocked
                  ? 'bg-red-50 border-red-200 text-red-800'
                  : 'bg-slate-100 border-slate-200 text-slate-500'
              }`}
            >
              <div className="text-[10px] font-semibold tracking-wider mb-1">
                {step.label}
              </div>
              <div className="flex items-center justify-center gap-1 text-xs font-bold font-mono">
                {isOk ? (
                  <>
                    <Check size={12} className="text-emerald-700" /> YES
                  </>
                ) : isBlocked ? (
                  <>
                    <X size={12} className="text-red-700" /> NO
                  </>
                ) : (
                  '—'
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
