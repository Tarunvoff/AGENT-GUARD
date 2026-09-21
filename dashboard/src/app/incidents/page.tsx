'use client';

import React, { useState, useMemo } from 'react';
import { PageHeader } from '@/components/ui/PageHeader';
import { FilterBar } from '@/components/ui/FilterBar';
import { DataTable, Column } from '@/components/ui/DataTable';
import { SeverityBadge } from '@/components/ui/StatusBadge';
import { DetailDrawer } from '@/components/ui/DetailDrawer';
import { ExecutionTruth } from '@/components/ui/ExecutionTruth';
import { AlertTriangle, ShieldCheck, Clock, User, Layers, CheckCircle2, RotateCcw, Shield, ExternalLink } from 'lucide-react';

interface IncidentItem {
  id: string;
  name: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  agent: string;
  detection: string;
  state: 'DETECTED' | 'TRIAGED' | 'INVESTIGATING' | 'CONTAINED' | 'REMEDIATED' | 'VALIDATED' | 'CLOSED';
  started_at: string;
  updated_at: string;
  summary: string;
  attack_path: string[];
  evidence: string;
  remediation_actions: string[];
  regression_status: string;
}

const DEMO_INCIDENTS: IncidentItem[] = [
  {
    id: 'INC-1049',
    name: 'Authority Escalation & Privilege Expansion Attempt',
    severity: 'HIGH',
    agent: 'research-agent-001',
    detection: 'Monotonic Delegation Invariant',
    state: 'CONTAINED',
    started_at: '15:14:10',
    updated_at: '15:17:22',
    summary: 'Sub-agent research-agent-001 attempted to invoke customer_db.read without delegator authority grant.',
    attack_path: ['Orchestrator Grant (search-only)', 'Research Agent', 'Target Tool (customer_db.read)'],
    evidence: 'Intercepted ToolRequest req_8849b on trace trc_ae604. Agent missing required capability "pii_access".',
    remediation_actions: ['Authority quarantined', 'Monotonic boundary asserted', 'Security event emitted to SIEM'],
    regression_status: 'PASS (Automated replay fixture generated)',
  },
  {
    id: 'INC-1048',
    name: 'Indirect Prompt Injection via Untrusted MCP Server',
    severity: 'CRITICAL',
    agent: 'orchestrator-001',
    detection: 'Taint Sink Enforcement Gate',
    state: 'CLOSED',
    started_at: '14:22:05',
    updated_at: '14:45:00',
    summary: 'External MCP tool returned adversarial payload containing override directives targeting customer database.',
    attack_path: ['External MCP (mcp://search.io)', 'MCP Gateway (tagged TAINTED)', 'Orchestrator Ingestion', 'Sink Gate (BLOCKED)'],
    evidence: 'Matched MITRE ATLAS AML.T0051 signature in context payload ctx_005. 0 database calls executed.',
    remediation_actions: ['External MCP source quarantined', 'Taint propagation containment verified', 'Policy baseline validated'],
    regression_status: 'PASS (Zero bypasses on 42 replays)',
  },
  {
    id: 'INC-1047',
    name: 'Taint Lineage Sanitization Anomaly',
    severity: 'MEDIUM',
    agent: 'analysis-agent-001',
    detection: 'Context Sanitization Tracker',
    state: 'CLOSED',
    started_at: '11:05:30',
    updated_at: '11:30:15',
    summary: 'Context payload passed through custom parser without expected schema validation hash.',
    attack_path: ['Internal Feed', 'Custom Parser', 'Analysis Agent'],
    evidence: 'Sanitization record missing cryptographic signature.',
    remediation_actions: ['Schema validation rule updated', 'Audit record signed'],
    regression_status: 'PASS',
  },
];

export default function IncidentsPage() {
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [stateFilter, setStateFilter] = useState('ALL');
  const [selectedIncident, setSelectedIncident] = useState<IncidentItem | null>(DEMO_INCIDENTS[0]);
  const [isDrawerOpen, setIsDrawerOpen] = useState(false);

  const filteredData = useMemo(() => {
    return DEMO_INCIDENTS.filter((item) => {
      if (search) {
        const q = search.toLowerCase();
        const match =
          item.id.toLowerCase().includes(q) ||
          item.name.toLowerCase().includes(q) ||
          item.agent.toLowerCase().includes(q) ||
          item.detection.toLowerCase().includes(q);
        if (!match) return false;
      }
      if (severityFilter !== 'ALL' && item.severity !== severityFilter) return false;
      if (stateFilter !== 'ALL' && item.state !== stateFilter) return false;
      return true;
    });
  }, [search, severityFilter, stateFilter]);

  const columns: Column<IncidentItem>[] = [
    {
      key: 'id',
      header: 'Incident ID',
      mono: true,
      width: '120px',
      render: (row) => (
        <span className="font-semibold text-slate-900 hover:text-sky-700 underline decoration-slate-300">
          {row.id}
        </span>
      ),
    },
    {
      key: 'severity',
      header: 'Severity',
      width: '110px',
      render: (row) => <SeverityBadge severity={row.severity} />,
    },
    {
      key: 'name',
      header: 'Incident Title',
      render: (row) => <span className="font-semibold text-slate-900">{row.name}</span>,
    },
    {
      key: 'agent',
      header: 'Offending Agent',
      render: (row) => (
        <span className="font-mono text-[11px] text-slate-700 bg-slate-100 px-1.5 py-0.5 rounded">
          {row.agent}
        </span>
      ),
    },
    {
      key: 'detection',
      header: 'Detection Rule',
      render: (row) => <span className="text-slate-600 font-medium">{row.detection}</span>,
    },
    {
      key: 'state',
      header: 'Lifecycle State',
      width: '130px',
      render: (row) => (
        <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
          row.state === 'CLOSED'
            ? 'bg-emerald-50 text-emerald-800 border border-emerald-200'
            : row.state === 'CONTAINED'
            ? 'bg-blue-50 text-blue-800 border border-blue-200'
            : 'bg-amber-50 text-amber-800 border border-amber-200'
        }`}>
          {row.state}
        </span>
      ),
    },
    {
      key: 'started_at',
      header: 'Started',
      mono: true,
      width: '90px',
      render: (row) => <span className="text-slate-500">{row.started_at}</span>,
    },
    {
      key: 'updated_at',
      header: 'Updated',
      mono: true,
      align: 'right',
      width: '90px',
      render: (row) => <span className="text-slate-400">{row.updated_at}</span>,
    },
  ];

  return (
    <div className="max-w-[1600px] mx-auto">
      <PageHeader
        title="Security Incidents"
        description="7-stage deterministic incident lifecycle state machine (DETECTED → TRIAGED → INVESTIGATING → CONTAINED → REMEDIATED → VALIDATED → CLOSED) with immutable evidence logs."
        breadcrumbs={[
          { label: 'Investigation', href: '/dashboard' },
          { label: 'Incidents' },
        ]}
      />

      <FilterBar
        searchQuery={search}
        onSearchChange={setSearch}
        searchPlaceholder="Search incidents…"
        totalCount={DEMO_INCIDENTS.length}
        activeCount={filteredData.length}
        onReset={() => {
          setSearch('');
          setSeverityFilter('ALL');
          setStateFilter('ALL');
        }}
        dropdowns={[
          {
            name: 'severity',
            label: 'Severity',
            value: severityFilter,
            onChange: setSeverityFilter,
            options: [
              { label: 'All Severities', value: 'ALL' },
              { label: 'CRITICAL', value: 'CRITICAL' },
              { label: 'HIGH', value: 'HIGH' },
              { label: 'MEDIUM', value: 'MEDIUM' },
            ],
          },
          {
            name: 'state',
            label: 'Lifecycle State',
            value: stateFilter,
            onChange: setStateFilter,
            options: [
              { label: 'All States', value: 'ALL' },
              { label: 'CONTAINED', value: 'CONTAINED' },
              { label: 'CLOSED', value: 'CLOSED' },
              { label: 'INVESTIGATING', value: 'INVESTIGATING' },
            ],
          },
        ]}
      />

      <DataTable
        columns={columns}
        data={filteredData}
        keyExtractor={(item) => item.id}
        onRowClick={(item) => {
          setSelectedIncident(item);
          setIsDrawerOpen(true);
        }}
        selectedKey={selectedIncident?.id}
      />

      {/* Incident Detail Drawer */}
      <DetailDrawer
        isOpen={isDrawerOpen}
        onClose={() => setIsDrawerOpen(false)}
        title={`Incident: ${selectedIncident?.id}`}
        subtitle={selectedIncident?.name}
        badge={selectedIncident && <SeverityBadge severity={selectedIncident.severity} />}
      >
        {selectedIncident && (
          <div className="space-y-5 text-xs">
            {/* 7-State Lifecycle Progression */}
            <div>
              <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block mb-2">
                Incident State Machine Status
              </span>
              <div className="p-3 bg-slate-50 border border-slate-200 rounded-lg flex items-center justify-between text-[11px] font-semibold">
                <span className="text-slate-600">Current Phase:</span>
                <span className="px-2 py-0.5 rounded bg-blue-50 text-blue-800 border border-blue-200 font-mono">
                  {selectedIncident.state}
                </span>
              </div>
            </div>

            {/* Summary */}
            <div>
              <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block mb-1">
                Executive Summary
              </span>
              <p className="text-slate-700 leading-relaxed bg-white p-3 border border-slate-200 rounded-lg">
                {selectedIncident.summary}
              </p>
            </div>

            {/* Attack Path */}
            <div>
              <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block mb-1.5">
                Causal Attack Path
              </span>
              <div className="bg-slate-50 border border-slate-200 rounded-lg p-3 space-y-1.5 font-mono text-[11px]">
                {selectedIncident.attack_path.map((hop, idx) => (
                  <div key={idx} className="flex items-center gap-2">
                    <span className="w-4 h-4 rounded-full bg-slate-200 text-slate-700 flex items-center justify-center text-[9px] font-bold">
                      {idx + 1}
                    </span>
                    <span>{hop}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Forensic Evidence */}
            <div>
              <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block mb-1">
                Forensic Evidence
              </span>
              <pre className="p-3 bg-slate-900 text-slate-100 rounded-lg text-[11px] font-mono whitespace-pre-wrap leading-relaxed">
                {selectedIncident.evidence}
              </pre>
            </div>

            {/* Automated Remediation Actions */}
            <div>
              <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block mb-1.5">
                Automated Response Actions Taken
              </span>
              <div className="space-y-1">
                {selectedIncident.remediation_actions.map((act, idx) => (
                  <div key={idx} className="flex items-center gap-2 p-2 rounded bg-emerald-50 text-emerald-900 border border-emerald-200 text-[11px]">
                    <CheckCircle2 size={13} className="text-emerald-700 flex-shrink-0" />
                    <span>{act}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Regression Status */}
            <div>
              <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block mb-1">
                Offensive Regression Status
              </span>
              <div className="p-2.5 rounded bg-slate-50 border border-slate-200 font-mono text-slate-800 text-[11px] flex items-center gap-2">
                <RotateCcw size={12} className="text-slate-500" />
                <span>{selectedIncident.regression_status}</span>
              </div>
            </div>
          </div>
        )}
      </DetailDrawer>
    </div>
  );
}
