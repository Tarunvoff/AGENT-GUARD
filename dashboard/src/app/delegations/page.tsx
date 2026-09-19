'use client';

import { useState } from 'react';
import { Share2, ChevronDown, ChevronRight, Shield, AlertTriangle, CheckCircle2, Clock, ArrowRight } from 'lucide-react';
import { TrustBadge, DecisionBadge } from '@/components/ui/security';
import Link from 'next/link';

interface DelegationChain {
  delegation_id: string;
  from_agent: string;
  to_agent: string;
  authority_granted: string[];
  authority_subset_of: string[];
  constraints: string[];
  valid: boolean;
  depth: number;
  created_at: string;
  expires_at: string | null;
  reason: string;
  violation?: string;
}

const DEMO_DELEGATIONS: DelegationChain[] = [
  {
    delegation_id: 'del_001',
    from_agent: 'orchestrator_v2',
    to_agent: 'data_agent',
    authority_granted: ['read_db', 'query_customers'],
    authority_subset_of: ['read_db', 'query_customers', 'write_db', 'delete_db'],
    constraints: ['read_only', 'no_pii_export'],
    valid: true,
    depth: 1,
    created_at: '2026-09-19T08:00:00Z',
    expires_at: '2026-09-19T18:00:00Z',
    reason: 'Delegated for Q3 analysis task',
  },
  {
    delegation_id: 'del_002',
    from_agent: 'data_agent',
    to_agent: 'report_agent',
    authority_granted: ['read_db', 'query_customers'],
    authority_subset_of: ['read_db', 'query_customers'],
    constraints: ['read_only', 'no_pii_export', 'report_scope_only'],
    valid: true,
    depth: 2,
    created_at: '2026-09-19T08:05:00Z',
    expires_at: '2026-09-19T18:00:00Z',
    reason: 'Sub-delegated for report compilation',
  },
  {
    delegation_id: 'del_003',
    from_agent: 'escalation_agent',
    to_agent: 'external_caller',
    authority_granted: ['read_db', 'query_customers', 'export_pii', 'send_email'],
    authority_subset_of: ['query_customers'],
    constraints: [],
    valid: false,
    depth: 1,
    created_at: '2026-09-19T10:30:00Z',
    expires_at: null,
    reason: 'Attempted privilege escalation for customer data export',
    violation: 'Requested authority [export_pii, send_email] exceeds delegator capability [query_customers]',
  },
  {
    delegation_id: 'del_004',
    from_agent: 'orchestrator_v2',
    to_agent: 'analyst_agent',
    authority_granted: ['read_file', 'generate_summary'],
    authority_subset_of: ['read_file', 'write_file', 'generate_summary', 'delete_file'],
    constraints: ['financial_data_only', 'no_write'],
    valid: true,
    depth: 1,
    created_at: '2026-09-19T07:55:00Z',
    expires_at: '2026-09-20T07:55:00Z',
    reason: 'Analysis of Q3 financial report files',
  },
];

function DelegationCard({ del }: { del: DelegationChain }) {
  const [expanded, setExpanded] = useState(false);
  return (
    <div className={`rounded-xl border ${del.valid ? 'border-zinc-800/50 bg-zinc-900/30' : 'border-red-500/30 bg-red-500/5'} transition-colors hover:border-zinc-700/50`}>
      <div className="p-4">
        <div className="flex items-start gap-3">
          {del.valid
            ? <CheckCircle2 size={16} className="text-emerald-400 mt-0.5 flex-shrink-0" />
            : <AlertTriangle size={16} className="text-red-400 mt-0.5 flex-shrink-0" />
          }
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-1 flex-wrap">
              <span className="font-mono text-xs text-zinc-400">{del.delegation_id}</span>
              <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded border ${del.valid ? 'text-emerald-400 border-emerald-500/20 bg-emerald-500/10' : 'text-red-400 border-red-500/20 bg-red-500/10'}`}>
                {del.valid ? 'VALID' : 'VIOLATION'}
              </span>
              <span className="text-[10px] text-zinc-600 font-mono">depth {del.depth}</span>
            </div>

            {/* Chain visual */}
            <div className="flex items-center gap-2 text-sm mb-2">
              <span className="font-mono text-sky-300 bg-sky-500/10 px-2 py-0.5 rounded border border-sky-500/20">{del.from_agent}</span>
              <ArrowRight size={14} className="text-zinc-600" />
              <span className="font-mono text-indigo-300 bg-indigo-500/10 px-2 py-0.5 rounded border border-indigo-500/20">{del.to_agent}</span>
            </div>

            <p className="text-xs text-zinc-500 mb-2">{del.reason}</p>

            {del.violation && (
              <div className="text-[11px] text-red-400 bg-red-500/10 border border-red-500/20 rounded p-2 mb-2">
                ⚠ {del.violation}
              </div>
            )}

            <div className="flex items-center gap-3 text-xs text-zinc-600">
              <span>{new Date(del.created_at).toLocaleString()}</span>
              {del.expires_at && <span>expires {new Date(del.expires_at).toLocaleString()}</span>}
            </div>
          </div>

          <button onClick={() => setExpanded(!expanded)} className="text-zinc-600 hover:text-zinc-400 transition-colors flex-shrink-0">
            {expanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
          </button>
        </div>

        {expanded && (
          <div className="mt-3 pt-3 border-t border-zinc-800/50 grid grid-cols-2 gap-4">
            <div>
              <div className="text-[10px] uppercase tracking-wider text-zinc-500 mb-1.5">Authority Granted</div>
              <div className="flex flex-wrap gap-1">
                {del.authority_granted.map(a => (
                  <span key={a} className={`font-mono text-[10px] px-1.5 py-0.5 rounded ${
                    del.authority_subset_of.includes(a) ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' : 'bg-red-500/10 text-red-400 border border-red-500/20'
                  }`}>{a}</span>
                ))}
              </div>
            </div>
            <div>
              <div className="text-[10px] uppercase tracking-wider text-zinc-500 mb-1.5">Constraints</div>
              <div className="flex flex-wrap gap-1">
                {del.constraints.length > 0 ? del.constraints.map(c => (
                  <span key={c} className="font-mono text-[10px] px-1.5 py-0.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/20">{c}</span>
                )) : <span className="text-xs text-zinc-600">None</span>}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export default function DelegationsPage() {
  const violations = DEMO_DELEGATIONS.filter(d => !d.valid).length;
  const valid = DEMO_DELEGATIONS.filter(d => d.valid).length;

  return (
    <div className="p-6 space-y-5 min-h-screen bg-[#090d16]">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-white flex items-center gap-2">
            <Share2 size={18} className="text-indigo-400" />
            Delegations
          </h1>
          <p className="text-sm text-zinc-500 mt-1">
            Authority delegation chains — each agent can only grant authority it possesses
          </p>
        </div>
      </div>

      {/* Core Invariant Banner */}
      <div className="rounded-xl border border-indigo-500/20 bg-indigo-500/5 p-3 flex items-start gap-2">
        <Shield size={14} className="text-indigo-400 mt-0.5 flex-shrink-0" />
        <div className="text-xs text-indigo-300">
          <span className="font-semibold">Containment Invariant:</span> No agent can delegate authority it does not itself possess.
          Delegation depth ≥ 3 triggers automatic HITL review.
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-3 gap-3">
        <div className="rounded-xl border border-zinc-700/30 bg-zinc-800/40 p-4 text-center">
          <div className="text-[10px] text-zinc-500 uppercase tracking-wider mb-1">Total Delegations</div>
          <div className="text-2xl font-bold font-mono text-zinc-200">{DEMO_DELEGATIONS.length}</div>
        </div>
        <div className="rounded-xl border border-emerald-500/20 bg-emerald-500/5 p-4 text-center">
          <div className="text-[10px] text-zinc-500 uppercase tracking-wider mb-1">Valid Chains</div>
          <div className="text-2xl font-bold font-mono text-emerald-400">{valid}</div>
        </div>
        <div className="rounded-xl border border-red-500/20 bg-red-500/5 p-4 text-center">
          <div className="text-[10px] text-zinc-500 uppercase tracking-wider mb-1">Violations Caught</div>
          <div className="text-2xl font-bold font-mono text-red-400">{violations}</div>
        </div>
      </div>

      {/* Delegation Cards */}
      <div className="space-y-3">
        {DEMO_DELEGATIONS.map(del => (
          <DelegationCard key={del.delegation_id} del={del} />
        ))}
      </div>
    </div>
  );
}
