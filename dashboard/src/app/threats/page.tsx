'use client';

import React, { useState } from 'react';
import { PageHeader } from '@/components/ui/PageHeader';
import { MetricCard } from '@/components/ui/MetricCard';
import { DataTable, Column } from '@/components/ui/DataTable';
import { SeverityBadge } from '@/components/ui/StatusBadge';
import { DetailDrawer } from '@/components/ui/DetailDrawer';
import { 
  ShieldAlert, Shield, Users, Network, Lock, 
  Layers, CheckCircle2, ArrowRight, Eye, RefreshCw 
} from 'lucide-react';

interface ThreatItem {
  threat_id: string;
  name: string;
  category: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  actors: string[];
  boundaries: string[];
  controls: string[];
  residual_score: number;
  residual_risk: string;
  effectiveness: 'PREVENTS' | 'DETECTS' | 'REDUCES' | 'MONITORS';
}

const DEMO_THREATS: ThreatItem[] = [
  {
    threat_id: 'thr_indirect_prompt_injection',
    name: 'Indirect Prompt Injection via Untrusted Context',
    category: 'INDIRECT_PROMPT_INJECTION',
    severity: 'CRITICAL',
    actors: ['External Attacker', 'Malicious MCP Server'],
    boundaries: ['External → Internal Boundary'],
    controls: ['Context Taint Tracking', 'Taint Sink Enforcement Gate', 'HTTP/MCP Interceptor'],
    residual_score: 1.2,
    residual_risk: 'LOW (100% Policy Interception)',
    effectiveness: 'PREVENTS',
  },
  {
    threat_id: 'thr_delegation_escalation',
    name: 'Multi-Hop Delegation Authority Escalation',
    category: 'PRIVILEGE_ESCALATION',
    severity: 'HIGH',
    actors: ['Compromised Internal Agent'],
    boundaries: ['Agent → Sub-Agent Boundary'],
    controls: ['Monotonic Authority Invariant Guard', 'Capability Scope Reducer'],
    residual_score: 1.0,
    residual_risk: 'LOW (Strict Sub-Set Enforcement)',
    effectiveness: 'PREVENTS',
  },
  {
    threat_id: 'thr_pii_exfiltration',
    name: 'Customer PII Data Exfiltration to External Sink',
    category: 'DATA_EXFILTRATION',
    severity: 'CRITICAL',
    actors: ['Compromised Agent', 'Malicious User'],
    boundaries: ['Internal Agent → Cloud API Boundary'],
    controls: ['Deterministic Sink Policy', 'Automated Secret Redactor'],
    residual_score: 1.5,
    residual_risk: 'LOW (Zero Sink Bypasses)',
    effectiveness: 'PREVENTS',
  },
  {
    threat_id: 'thr_rag_poisoning',
    name: 'RAG Knowledge Base & Document Store Poisoning',
    category: 'RAG_POISONING',
    severity: 'HIGH',
    actors: ['External Attacker', 'Poisoned Document Provider'],
    boundaries: ['Data Retrieval Boundary'],
    controls: ['Provenance Lineage Tagging', 'Cryptographic Context Hashing'],
    residual_score: 2.8,
    residual_risk: 'MEDIUM (Requires Strict Source Verification)',
    effectiveness: 'REDUCES',
  },
];

const ASSETS_LIST = [
  { id: 'ast_creds', name: 'API Keys & Credentials', sensitivity: 'CRITICAL', owner: 'platform', protection: 'Secret Redaction + Monotonic Bounds' },
  { id: 'ast_customer_db', name: 'Customer Database (PII)', sensitivity: 'CRITICAL', owner: 'data-team', protection: 'Deterministic Sink Gate' },
  { id: 'ast_sys_prompts', name: 'System Prompts & Personas', sensitivity: 'HIGH', owner: 'platform', protection: 'Context Provenance Isolation' },
  { id: 'ast_internal_docs', name: 'Internal Code & Documents', sensitivity: 'HIGH', owner: 'engineering', protection: 'MCP Gateway Taint Marking' },
];

export default function ThreatModelPage() {
  const [activeTab, setActiveTab] = useState<'threats' | 'assets' | 'boundaries'>('threats');
  const [selectedThreat, setSelectedThreat] = useState<ThreatItem | null>(DEMO_THREATS[0]);
  const [isDrawerOpen, setIsDrawerOpen] = useState(false);
  const [showGraph, setShowGraph] = useState(false);

  const threatColumns: Column<ThreatItem>[] = [
    {
      key: 'threat_id',
      header: 'Threat ID',
      mono: true,
      width: '180px',
      render: (row) => (
        <span className="font-semibold text-slate-900 hover:text-sky-700 underline decoration-slate-300">
          {row.threat_id}
        </span>
      ),
    },
    { key: 'severity', header: 'Severity', width: '100px', render: (row) => <SeverityBadge severity={row.severity} /> },
    { key: 'name', header: 'Threat Description', render: (row) => <span className="font-semibold text-slate-900">{row.name}</span> },
    {
      key: 'effectiveness',
      header: 'Control Effectiveness',
      width: '140px',
      render: (row) => (
        <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-50 text-emerald-800 border border-emerald-200">
          {row.effectiveness}
        </span>
      ),
    },
    {
      key: 'residual_score',
      header: 'Residual Risk',
      align: 'right',
      width: '120px',
      render: (row) => (
        <span className="font-mono font-bold text-slate-800">
          {row.residual_score.toFixed(1)} / 10.0
        </span>
      ),
    },
  ];

  return (
    <div className="max-w-[1600px] mx-auto space-y-6">
      <PageHeader
        title="Threat Model & Security Controls"
        description="Formal threat modeling subsystem aligned with MITRE ATLAS and STRIDE. Identifies critical assets, threat actors, trust boundaries, and residual risk scores."
        breadcrumbs={[
          { label: 'Security', href: '/dashboard' },
          { label: 'Threat Model' },
        ]}
        actions={
          <button
            onClick={() => setShowGraph(!showGraph)}
            className="px-3 py-1.5 text-xs font-semibold bg-white border border-slate-300 rounded-md text-slate-700 hover:bg-slate-50 transition-colors flex items-center gap-1.5 shadow-xs cursor-pointer"
          >
            <Eye size={13} className="text-slate-500" />
            <span>{showGraph ? 'Hide Attack Graph' : 'View Attack Graph'}</span>
          </button>
        }
      />

      {/* KPI Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <MetricCard label="Identified Threats" value="10" subtext="100% Control Coverage" status="healthy" icon={ShieldAlert} />
        <MetricCard label="Critical Assets" value="8" subtext="All Sinks Enforced" status="healthy" icon={Lock} />
        <MetricCard label="Trust Boundaries" value="7" subtext="In-Line Interception" status="healthy" icon={Layers} />
        <MetricCard label="Mean Residual Risk" value="2.8 / 10" subtext="Grade: LOW (Controlled)" status="healthy" icon={Shield} />
      </div>

      {/* Attack Graph (Lazy-rendered on demand) */}
      {showGraph && (
        <div className="bg-white border border-slate-200 rounded-lg p-5 shadow-sm space-y-3">
          <div className="flex items-center justify-between border-b border-slate-100 pb-2">
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-500 flex items-center gap-1.5">
              <Network size={14} className="text-sky-600" />
              <span>Multi-Agent Attack Path & Control Boundary Graph</span>
            </h3>
            <span className="text-[10px] text-slate-400 font-mono">Rendered on demand (Memory Optimized)</span>
          </div>
          <div className="p-4 bg-slate-900 text-slate-100 rounded-lg font-mono text-xs overflow-x-auto leading-relaxed border border-slate-800">
            {`[ External Attacker ] 
       │ (Prompt Injection / AML.T0051)
       ▼
[ External MCP Server ] ──────────► [ MCP Gateway Interceptor (Taint Marked: CRITICAL) ]
                                                   │
                                                   ▼
                                     [ Orchestrator Agent (Untrusted Context) ]
                                                   │
                                                   ▼ (Delegation Scope Check: PASS)
                                     [ Research Agent (Missing PII Scope) ]
                                                   │
                                                   ▼
                                     [ Deterministic Sink Policy Gate ]
                                                   │
                                                   ├───► [ BLOCKED: Zero DB Execution ]
                                                   └───► [ Emit Incident: INC-1049 ]`}
          </div>
        </div>
      )}

      {/* Navigation Tabs */}
      <div className="border-b border-slate-200 flex gap-4 text-xs font-semibold">
        <button
          onClick={() => setActiveTab('threats')}
          className={`pb-2.5 border-b-2 transition-colors cursor-pointer ${
            activeTab === 'threats'
              ? 'border-sky-600 text-sky-800'
              : 'border-transparent text-slate-500 hover:text-slate-800'
          }`}
        >
          Threat Catalog ({DEMO_THREATS.length})
        </button>
        <button
          onClick={() => setActiveTab('assets')}
          className={`pb-2.5 border-b-2 transition-colors cursor-pointer ${
            activeTab === 'assets'
              ? 'border-sky-600 text-sky-800'
              : 'border-transparent text-slate-500 hover:text-slate-800'
          }`}
        >
          Critical Assets ({ASSETS_LIST.length})
        </button>
      </div>

      {/* Content based on Tab */}
      {activeTab === 'threats' ? (
        <DataTable
          columns={threatColumns}
          data={DEMO_THREATS}
          keyExtractor={(item) => item.threat_id}
          onRowClick={(item) => {
            setSelectedThreat(item);
            setIsDrawerOpen(true);
          }}
          selectedKey={selectedThreat?.threat_id}
        />
      ) : (
        <div className="bg-white border border-slate-200 rounded-lg shadow-sm overflow-hidden">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="bg-slate-50 border-b border-slate-200">
                <th className="px-4 py-2.5 font-semibold text-slate-600 uppercase tracking-wider text-[10px]">Asset ID</th>
                <th className="px-4 py-2.5 font-semibold text-slate-600 uppercase tracking-wider text-[10px]">Name</th>
                <th className="px-4 py-2.5 font-semibold text-slate-600 uppercase tracking-wider text-[10px]">Sensitivity</th>
                <th className="px-4 py-2.5 font-semibold text-slate-600 uppercase tracking-wider text-[10px]">Owner</th>
                <th className="px-4 py-2.5 font-semibold text-slate-600 uppercase tracking-wider text-[10px]">Enforced Protection</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {ASSETS_LIST.map((ast) => (
                <tr key={ast.id} className="hover:bg-slate-50">
                  <td className="px-4 py-3 font-mono font-semibold text-slate-900">{ast.id}</td>
                  <td className="px-4 py-3 font-medium text-slate-800">{ast.name}</td>
                  <td className="px-4 py-3"><SeverityBadge severity={ast.sensitivity} /></td>
                  <td className="px-4 py-3 font-mono text-slate-600">{ast.owner}</td>
                  <td className="px-4 py-3 text-slate-700 font-medium">{ast.protection}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Threat Detail Drawer */}
      <DetailDrawer
        isOpen={isDrawerOpen}
        onClose={() => setIsDrawerOpen(false)}
        title={`Threat: ${selectedThreat?.name}`}
        subtitle={selectedThreat?.threat_id}
        badge={selectedThreat && <SeverityBadge severity={selectedThreat.severity} />}
      >
        {selectedThreat && (
          <div className="space-y-5 text-xs">
            <div className="grid grid-cols-2 gap-3 p-3 bg-slate-50 border border-slate-200 rounded-lg">
              <div>
                <span className="text-[10px] uppercase font-bold text-slate-400 block">CATEGORY</span>
                <span className="font-mono text-slate-900">{selectedThreat.category}</span>
              </div>
              <div>
                <span className="text-[10px] uppercase font-bold text-slate-400 block">CONTROL EFFECTIVENESS</span>
                <span className="font-semibold text-emerald-800">{selectedThreat.effectiveness}</span>
              </div>
            </div>

            <div>
              <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block mb-1.5">
                Threat Actors & Entry Points
              </span>
              <div className="flex flex-wrap gap-1.5">
                {selectedThreat.actors.map((act) => (
                  <span key={act} className="px-2 py-1 bg-slate-100 border border-slate-200 text-slate-800 rounded font-medium">
                    {act}
                  </span>
                ))}
              </div>
            </div>

            <div>
              <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block mb-1.5">
                Mapped ActShield Enforcement Controls
              </span>
              <div className="space-y-1.5">
                {selectedThreat.controls.map((ctrl) => (
                  <div key={ctrl} className="p-2 rounded bg-emerald-50 border border-emerald-200 text-emerald-900 flex items-center gap-2">
                    <CheckCircle2 size={13} className="text-emerald-700 flex-shrink-0" />
                    <span className="font-medium">{ctrl}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
      </DetailDrawer>
    </div>
  );
}
