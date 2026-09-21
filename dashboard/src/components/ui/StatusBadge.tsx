import React from 'react';

export type EnforcementType = 'BLOCK' | 'ALLOW' | 'HITL' | 'MONITOR' | 'REVOKE' | 'QUARANTINE';
export type SeverityType = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
export type TrustType = 'HIGH' | 'MEDIUM' | 'LOW' | 'UNTRUSTED' | 'TRUSTED';
export type TaintType = 'TAINTED' | 'CLEAN' | 'UNTRUSTED' | 'UNKNOWN' | 'CRITICAL';

export function DecisionBadge({ decision, status }: { decision?: string; status?: string }) {
  const d = (decision || status || '').toUpperCase();
  if (d === 'BLOCK' || d === 'DENY' || d === 'BLOCKED') {
    return (
      <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[11px] font-semibold bg-red-50 text-red-700 border border-red-200">
        <span className="w-1.5 h-1.5 rounded-full bg-red-600" />
        BLOCK
      </span>
    );
  }
  if (d === 'ALLOW' || d === 'ALLOWED') {
    return (
      <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[11px] font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200">
        <span className="w-1.5 h-1.5 rounded-full bg-emerald-600" />
        ALLOW
      </span>
    );
  }
  if (d === 'HITL' || d === 'APPROVAL_REQUIRED') {
    return (
      <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[11px] font-semibold bg-amber-50 text-amber-700 border border-amber-200">
        <span className="w-1.5 h-1.5 rounded-full bg-amber-600" />
        HITL
      </span>
    );
  }
  if (d === 'MONITOR' || d === 'AUDIT') {
    return (
      <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[11px] font-semibold bg-blue-50 text-blue-700 border border-blue-200">
        <span className="w-1.5 h-1.5 rounded-full bg-blue-600" />
        MONITOR
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[11px] font-medium bg-slate-100 text-slate-700 border border-slate-200">
      {decision || status || 'UNKNOWN'}
    </span>
  );
}

export const StatusBadge = DecisionBadge;

export function SeverityBadge({ severity }: { severity?: string }) {
  const s = (severity || '').toUpperCase();
  if (s === 'CRITICAL') {
    return (
      <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[11px] font-semibold bg-red-50 text-red-700 border border-red-200">
        <span className="w-1.5 h-1.5 rounded-full bg-red-600" />
        CRITICAL
      </span>
    );
  }
  if (s === 'HIGH') {
    return (
      <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[11px] font-semibold bg-orange-50 text-orange-700 border border-orange-200">
        <span className="w-1.5 h-1.5 rounded-full bg-orange-600" />
        HIGH
      </span>
    );
  }
  if (s === 'MEDIUM') {
    return (
      <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[11px] font-semibold bg-amber-50 text-amber-700 border border-amber-200">
        <span className="w-1.5 h-1.5 rounded-full bg-amber-600" />
        MEDIUM
      </span>
    );
  }
  if (s === 'LOW') {
    return (
      <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[11px] font-medium bg-blue-50 text-blue-700 border border-blue-200">
        <span className="w-1.5 h-1.5 rounded-full bg-blue-600" />
        LOW
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[11px] font-medium bg-slate-100 text-slate-600 border border-slate-200">
      {severity || 'INFO'}
    </span>
  );
}

export function TrustBadge({ trust }: { trust?: string }) {
  const t = (trust || '').toUpperCase();
  if (t === 'HIGH' || t === 'TRUSTED') {
    return (
      <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[11px] font-medium bg-emerald-50 text-emerald-700 border border-emerald-200">
        <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
        {trust}
      </span>
    );
  }
  if (t === 'MEDIUM') {
    return (
      <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[11px] font-medium bg-blue-50 text-blue-700 border border-blue-200">
        <span className="w-1.5 h-1.5 rounded-full bg-blue-500" />
        MEDIUM
      </span>
    );
  }
  if (t === 'LOW' || t === 'UNTRUSTED') {
    return (
      <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[11px] font-medium bg-red-50 text-red-700 border border-red-200">
        <span className="w-1.5 h-1.5 rounded-full bg-red-500" />
        {trust}
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[11px] font-medium bg-slate-100 text-slate-700 border border-slate-200">
      {trust || 'UNKNOWN'}
    </span>
  );
}

export function TaintBadge({ taint }: { taint?: string }) {
  const t = (taint || '').toUpperCase();
  if (t === 'TAINTED' || t === 'CRITICAL') {
    return (
      <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[11px] font-semibold bg-red-50 text-red-700 border border-red-200">
        <span className="w-1.5 h-1.5 rounded-full bg-red-600" />
        TAINTED
      </span>
    );
  }
  if (t === 'CLEAN' || t === 'TRUSTED' || t === 'NONE') {
    return (
      <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[11px] font-medium bg-emerald-50 text-emerald-700 border border-emerald-200">
        <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
        CLEAN
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[11px] font-medium bg-amber-50 text-amber-700 border border-amber-200">
      <span className="w-1.5 h-1.5 rounded-full bg-amber-500" />
      {taint || 'UNASSESSED'}
    </span>
  );
}

export default StatusBadge;
