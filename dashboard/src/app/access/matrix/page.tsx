'use client';

import React, { useState, useMemo } from 'react';
import { PageHeader } from '@/components/ui/PageHeader';
import { FilterBar } from '@/components/ui/FilterBar';
import { Grid, CheckCircle2, XCircle, Clock, Minus, Lock, Shield, Info } from 'lucide-react';

interface ResourceInfo {
  id: string;
  name: string;
  sensitivity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
}

const RESOURCES: ResourceInfo[] = [
  { id: 'public_web', name: 'Public Search', sensitivity: 'LOW' },
  { id: 'internal_docs', name: 'Internal Docs', sensitivity: 'MEDIUM' },
  { id: 'finance_ledger', name: 'Financial Ledger', sensitivity: 'HIGH' },
  { id: 'customer_db', name: 'Customer DB (PII)', sensitivity: 'CRITICAL' },
  { id: 'secret_vault', name: 'Secrets Vault', sensitivity: 'CRITICAL' },
  { id: 'audit_log', name: 'Audit Store', sensitivity: 'HIGH' },
];

const AGENTS = [
  { id: 'orchestrator-001', name: 'Orchestrator', trust: 'HIGH' },
  { id: 'research-agent-001', name: 'Research Agent', trust: 'MEDIUM' },
  { id: 'analysis-agent-001', name: 'Analysis Agent', trust: 'HIGH' },
  { id: 'data-sync-002', name: 'Data Agent', trust: 'MEDIUM' },
  { id: 'external-mcp-bot', name: 'External MCP Bot', trust: 'UNTRUSTED' },
];

type PermissionType = 'ALLOW' | 'DENY' | 'CONDITIONAL' | 'NONE';

const PERMISSION_MATRIX: Record<string, Record<string, PermissionType>> = {
  'orchestrator-001': {
    public_web: 'ALLOW',
    internal_docs: 'ALLOW',
    finance_ledger: 'CONDITIONAL',
    customer_db: 'DENY',
    secret_vault: 'DENY',
    audit_log: 'ALLOW',
  },
  'research-agent-001': {
    public_web: 'ALLOW',
    internal_docs: 'ALLOW',
    finance_ledger: 'DENY',
    customer_db: 'DENY',
    secret_vault: 'DENY',
    audit_log: 'DENY',
  },
  'analysis-agent-001': {
    public_web: 'ALLOW',
    internal_docs: 'ALLOW',
    finance_ledger: 'ALLOW',
    customer_db: 'DENY',
    secret_vault: 'DENY',
    audit_log: 'ALLOW',
  },
  'data-sync-002': {
    public_web: 'DENY',
    internal_docs: 'ALLOW',
    finance_ledger: 'ALLOW',
    customer_db: 'CONDITIONAL',
    secret_vault: 'DENY',
    audit_log: 'DENY',
  },
  'external-mcp-bot': {
    public_web: 'ALLOW',
    internal_docs: 'DENY',
    finance_ledger: 'DENY',
    customer_db: 'DENY',
    secret_vault: 'DENY',
    audit_log: 'DENY',
  },
};

export default function AccessMatrixPage() {
  const [search, setSearch] = useState('');
  const [sensitivityFilter, setSensitivityFilter] = useState('ALL');

  const filteredResources = useMemo(() => {
    return RESOURCES.filter((res) => {
      if (search && !res.name.toLowerCase().includes(search.toLowerCase()) && !res.id.toLowerCase().includes(search.toLowerCase())) {
        return false;
      }
      if (sensitivityFilter !== 'ALL' && res.sensitivity !== sensitivityFilter) {
        return false;
      }
      return true;
    });
  }, [search, sensitivityFilter]);

  const renderCell = (agentId: string, resourceId: string) => {
    const perm = PERMISSION_MATRIX[agentId]?.[resourceId] || 'NONE';

    if (perm === 'ALLOW') {
      return (
        <span className="inline-flex items-center gap-1 font-mono font-bold text-[11px] text-emerald-800 bg-emerald-50 border border-emerald-200 px-2 py-0.5 rounded">
          <CheckCircle2 size={11} className="text-emerald-600" />
          ALLOW
        </span>
      );
    }
    if (perm === 'CONDITIONAL') {
      return (
        <span className="inline-flex items-center gap-1 font-mono font-bold text-[11px] text-amber-800 bg-amber-50 border border-amber-200 px-2 py-0.5 rounded" title="Requires Human-In-The-Loop Approval">
          <Clock size={11} className="text-amber-600" />
          HITL
        </span>
      );
    }
    if (perm === 'DENY') {
      return (
        <span className="inline-flex items-center gap-1 font-mono font-bold text-[11px] text-red-800 bg-red-50 border border-red-200 px-2 py-0.5 rounded">
          <XCircle size={11} className="text-red-600" />
          DENY
        </span>
      );
    }
    return <span className="text-slate-300 font-mono">—</span>;
  };

  return (
    <div className="max-w-[1600px] mx-auto">
      <PageHeader
        title="Access Matrix"
        description="Effective authority boundary matrix across all registered agents and protected enterprise sinks, evaluated strictly by the PolicyEvaluator."
        breadcrumbs={[
          { label: 'Operations', href: '/dashboard' },
          { label: 'Access Matrix' },
        ]}
      />

      <FilterBar
        searchQuery={search}
        onSearchChange={setSearch}
        searchPlaceholder="Filter resources…"
        dropdowns={[
          {
            name: 'sensitivity',
            label: 'Sensitivity',
            value: sensitivityFilter,
            onChange: setSensitivityFilter,
            options: [
              { label: 'All Sensitivities', value: 'ALL' },
              { label: 'CRITICAL', value: 'CRITICAL' },
              { label: 'HIGH', value: 'HIGH' },
              { label: 'MEDIUM', value: 'MEDIUM' },
              { label: 'LOW', value: 'LOW' },
            ],
          },
        ]}
        onReset={() => {
          setSearch('');
          setSensitivityFilter('ALL');
        }}
      />

      {/* Legend Banner */}
      <div className="bg-white border border-slate-200 rounded-lg p-3 mb-4 flex flex-wrap items-center justify-between gap-3 text-xs">
        <div className="flex items-center gap-4">
          <span className="text-slate-500 font-semibold uppercase text-[10px]">Permission Legend:</span>
          <span className="inline-flex items-center gap-1 text-emerald-800 font-medium">
            <CheckCircle2 size={12} className="text-emerald-600" /> ALLOW (Direct Authorized)
          </span>
          <span className="inline-flex items-center gap-1 text-amber-800 font-medium">
            <Clock size={12} className="text-amber-600" /> HITL (Human Approval Required)
          </span>
          <span className="inline-flex items-center gap-1 text-red-800 font-medium">
            <XCircle size={12} className="text-red-600" /> DENY (Deterministic Block)
          </span>
        </div>
        <div className="text-slate-400 font-mono text-[11px]">
          Invariant: Monotonic Containment Active
        </div>
      </div>

      {/* Matrix Table */}
      <div className="bg-white border border-slate-200 rounded-lg shadow-sm overflow-x-auto">
        <table className="w-full text-left border-collapse text-xs">
          <thead>
            <tr className="bg-slate-50 border-b border-slate-200">
              <th className="px-4 py-3 font-semibold text-slate-700 uppercase tracking-wider text-[11px] sticky left-0 bg-slate-50 border-r border-slate-200 min-w-[200px]">
                Agent Identity
              </th>
              {filteredResources.map((res) => (
                <th key={res.id} className="px-4 py-3 text-center min-w-[140px]">
                  <div className="font-semibold text-slate-800">{res.name}</div>
                  <div className="font-mono text-[10px] text-slate-400">{res.id}</div>
                  <span className={`inline-block mt-1 text-[9px] font-bold px-1.5 py-0.2 rounded ${
                    res.sensitivity === 'CRITICAL' ? 'bg-red-50 text-red-700 border border-red-200' :
                    res.sensitivity === 'HIGH' ? 'bg-orange-50 text-orange-700 border border-orange-200' :
                    res.sensitivity === 'MEDIUM' ? 'bg-amber-50 text-amber-700 border border-amber-200' :
                    'bg-blue-50 text-blue-700 border border-blue-200'
                  }`}>
                    {res.sensitivity}
                  </span>
                </th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100">
            {AGENTS.map((agent) => (
              <tr key={agent.id} className="hover:bg-slate-50/80 transition-colors">
                <td className="px-4 py-3 font-medium text-slate-900 sticky left-0 bg-white border-r border-slate-200">
                  <div className="font-semibold text-slate-800">{agent.name}</div>
                  <div className="font-mono text-[10px] text-slate-400">{agent.id}</div>
                </td>
                {filteredResources.map((res) => (
                  <td key={res.id} className="px-4 py-3 text-center">
                    {renderCell(agent.id, res.id)}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
