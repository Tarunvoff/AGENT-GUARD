'use client';

import { useState } from 'react';
import { Database, Search, Lock, AlertTriangle, CheckCircle2, Shield, Eye, Filter } from 'lucide-react';
import { TrustBadge, SensitivityBadge } from '@/components/ui/security';
import Link from 'next/link';

const DEMO_RESOURCES = [
  {
    resource_id: 'res_db_customers',
    name: 'customers',
    type: 'database_table',
    sensitivity: 'CRITICAL',
    description: 'PII: customer names, emails, addresses, billing info',
    access_count_24h: 47,
    blocked_attempts_24h: 3,
    agents_with_access: ['orchestrator_v2', 'data_agent'],
    requires_hitl: true,
    taint_level: 'HIGH',
  },
  {
    resource_id: 'res_db_orders',
    name: 'orders',
    type: 'database_table',
    sensitivity: 'HIGH',
    description: 'Order records, amounts, statuses — no direct PII',
    access_count_24h: 128,
    blocked_attempts_24h: 0,
    agents_with_access: ['orchestrator_v2', 'data_agent', 'report_agent', 'analyst_agent'],
    requires_hitl: false,
    taint_level: 'MEDIUM',
  },
  {
    resource_id: 'res_file_financials',
    name: '/data/reports/q3_financials.xlsx',
    type: 'file',
    sensitivity: 'HIGH',
    description: 'Q3 financial report — confidential internal document',
    access_count_24h: 5,
    blocked_attempts_24h: 0,
    agents_with_access: ['orchestrator_v2', 'analyst_agent'],
    requires_hitl: false,
    taint_level: 'MEDIUM',
  },
  {
    resource_id: 'res_s3_exports',
    name: 's3://company-exports/',
    type: 'cloud_storage',
    sensitivity: 'CRITICAL',
    description: 'External S3 export bucket — egress to external systems',
    access_count_24h: 0,
    blocked_attempts_24h: 2,
    agents_with_access: [],
    requires_hitl: true,
    taint_level: 'HIGH',
  },
  {
    resource_id: 'res_api_email',
    name: 'email_api',
    type: 'external_api',
    sensitivity: 'HIGH',
    description: 'Email sending API — external communications channel',
    access_count_24h: 0,
    blocked_attempts_24h: 1,
    agents_with_access: [],
    requires_hitl: true,
    taint_level: 'HIGH',
  },
  {
    resource_id: 'res_db_audit',
    name: 'audit_log',
    type: 'database_table',
    sensitivity: 'MEDIUM',
    description: 'Internal audit trail — read access for reporting',
    access_count_24h: 22,
    blocked_attempts_24h: 0,
    agents_with_access: ['report_agent', 'analyst_agent'],
    requires_hitl: false,
    taint_level: 'LOW',
  },
];

const SENSITIVITY_STYLES: Record<string, string> = {
  CRITICAL: 'text-red-400 bg-red-500/10 border-red-500/30',
  HIGH: 'text-orange-400 bg-orange-500/10 border-orange-500/30',
  MEDIUM: 'text-amber-400 bg-amber-500/10 border-amber-500/20',
  LOW: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20',
};

const TYPE_ICONS: Record<string, React.ElementType> = {
  database_table: Database,
  file: Shield,
  cloud_storage: Database,
  external_api: Filter,
};

export default function ResourcesPage() {
  const [search, setSearch] = useState('');
  const [sensitFilter, setSensitFilter] = useState('all');

  const filtered = DEMO_RESOURCES.filter(r => {
    const matchSearch = r.name.toLowerCase().includes(search.toLowerCase()) || r.description.toLowerCase().includes(search.toLowerCase());
    const matchSensit = sensitFilter === 'all' || r.sensitivity === sensitFilter;
    return matchSearch && matchSensit;
  });

  return (
    <div className="p-6 space-y-5 min-h-screen bg-[#090d16]">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-white flex items-center gap-2">
            <Database size={18} className="text-amber-400" />
            Resources
          </h1>
          <p className="text-sm text-zinc-500 mt-1">Sensitive resources with access control, taint levels, and access history</p>
        </div>
      </div>

      {/* Summary */}
      <div className="grid grid-cols-4 gap-3">
        <div className="rounded-xl border border-zinc-700/30 bg-zinc-800/40 p-3 text-center">
          <div className="text-[10px] text-zinc-500 uppercase tracking-wider mb-1">Resources</div>
          <div className="text-xl font-bold font-mono text-zinc-200">{DEMO_RESOURCES.length}</div>
        </div>
        <div className="rounded-xl border border-red-500/20 bg-red-500/5 p-3 text-center">
          <div className="text-[10px] text-zinc-500 uppercase tracking-wider mb-1">Critical</div>
          <div className="text-xl font-bold font-mono text-red-400">{DEMO_RESOURCES.filter(r => r.sensitivity === 'CRITICAL').length}</div>
        </div>
        <div className="rounded-xl border border-red-500/20 bg-red-500/5 p-3 text-center">
          <div className="text-[10px] text-zinc-500 uppercase tracking-wider mb-1">Blocked Attempts (24h)</div>
          <div className="text-xl font-bold font-mono text-red-400">{DEMO_RESOURCES.reduce((s, r) => s + r.blocked_attempts_24h, 0)}</div>
        </div>
        <div className="rounded-xl border border-sky-500/20 bg-sky-500/5 p-3 text-center">
          <div className="text-[10px] text-zinc-500 uppercase tracking-wider mb-1">Access Events (24h)</div>
          <div className="text-xl font-bold font-mono text-sky-400">{DEMO_RESOURCES.reduce((s, r) => s + r.access_count_24h, 0)}</div>
        </div>
      </div>

      {/* Search + Filter */}
      <div className="flex gap-3 items-center">
        <div className="relative flex-1 max-w-xs">
          <Search size={13} className="absolute left-3 top-1/2 -translate-y-1/2 text-zinc-500" />
          <input
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Search resources..."
            className="w-full pl-8 pr-3 py-2 bg-zinc-800/60 border border-zinc-700/50 rounded-lg text-sm text-zinc-200 placeholder:text-zinc-600 focus:outline-none focus:border-sky-500/50"
          />
        </div>
        {['all', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(f => (
          <button key={f} onClick={() => setSensitFilter(f)}
            className={`px-2.5 py-1 text-[11px] rounded font-medium uppercase tracking-wider transition-colors ${
              sensitFilter === f ? 'bg-sky-500/15 border border-sky-500/30 text-sky-300' : 'text-zinc-500 hover:text-zinc-300'
            }`}>
            {f}
          </button>
        ))}
      </div>

      {/* Resource Cards */}
      <div className="space-y-3">
        {filtered.map(res => {
          const TypeIcon = TYPE_ICONS[res.type] || Database;
          const sensitStyle = SENSITIVITY_STYLES[res.sensitivity] || '';
          return (
            <div key={res.resource_id} className={`rounded-xl border ${res.blocked_attempts_24h > 0 ? 'border-red-500/30 bg-red-500/5' : 'border-zinc-800/50 bg-zinc-900/30'} p-4`}>
              <div className="flex items-start gap-3">
                <TypeIcon size={16} className="text-zinc-400 mt-0.5 flex-shrink-0" />
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1 flex-wrap">
                    <span className="font-mono text-sm text-zinc-100">{res.name}</span>
                    <span className={`text-[10px] font-semibold px-1.5 py-0.5 rounded border ${sensitStyle}`}>
                      {res.sensitivity}
                    </span>
                    <span className="text-[10px] text-zinc-600 bg-zinc-800/60 px-1.5 py-0.5 rounded">{res.type.replace('_', ' ')}</span>
                    {res.requires_hitl && (
                      <span className="text-[10px] text-amber-400 bg-amber-500/10 border border-amber-500/20 px-1.5 py-0.5 rounded">HITL Required</span>
                    )}
                  </div>
                  <p className="text-xs text-zinc-500 mb-2">{res.description}</p>
                  <div className="flex items-center gap-4 text-xs text-zinc-500">
                    <span className="flex items-center gap-1"><Eye size={11} /> {res.access_count_24h} accesses (24h)</span>
                    {res.blocked_attempts_24h > 0 && (
                      <span className="flex items-center gap-1 text-red-400"><AlertTriangle size={11} /> {res.blocked_attempts_24h} blocked</span>
                    )}
                    <span>Taint: <span className={res.taint_level === 'HIGH' ? 'text-red-400' : res.taint_level === 'MEDIUM' ? 'text-amber-400' : 'text-emerald-400'}>{res.taint_level}</span></span>
                  </div>
                  {res.agents_with_access.length > 0 && (
                    <div className="flex gap-1.5 mt-2 flex-wrap">
                      <span className="text-[10px] text-zinc-600">Agents:</span>
                      {res.agents_with_access.map(a => (
                        <span key={a} className="font-mono text-[10px] px-1.5 py-0.5 rounded bg-zinc-800/60 text-zinc-400">{a}</span>
                      ))}
                    </div>
                  )}
                  {res.agents_with_access.length === 0 && (
                    <div className="flex items-center gap-1 mt-1 text-[11px] text-emerald-400">
                      <Lock size={10} /> No agents have access
                    </div>
                  )}
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
