'use client';

import { useState } from 'react';
import { DEMO_AGENTS } from '@/data/demo';
import { PageHeader } from '@/components/ui/PageHeader';
import { MetricCard } from '@/components/ui/MetricCard';
import { StatusBadge } from '@/components/ui/StatusBadge';
import { ExecutionTruth } from '@/components/ui/ExecutionTruth';
import { DataTable } from '@/components/ui/DataTable';
import {
  Brain, Shield, AlertTriangle, CheckCircle2, XCircle, ArrowRight,
  ChevronRight, Lock, Database, Search, FileText, Layers, RefreshCw
} from 'lucide-react';
import Link from 'next/link';

type ForensicTab = 'why-blocked' | 'agents' | 'resources' | 'authority' | 'access';

interface ForensicExplanationData {
  event_id: string;
  timestamp: string;
  tool_name: string;
  agent_id: string;
  agent_trust: string;
  context_trust: string;
  resource_name: string;
  resource_sensitivity: string;
}

const FORENSIC_EXP: ForensicExplanationData = {
  event_id: 'evt_pinj_001',
  timestamp: '2026-09-19T10:45:00Z',
  tool_name: 'upload_s3',
  agent_id: 'orchestrator_v2',
  agent_trust: 'HIGH',
  context_trust: 'UNTRUSTED',
  resource_name: 's3://company-exports/customers.csv',
  resource_sensitivity: 'CRITICAL',
};

export default function ForensicsPage() {
  const [tab, setTab] = useState<ForensicTab>('why-blocked');
  const exp = FORENSIC_EXP;

  return (
    <div className="p-8 space-y-6 max-w-7xl mx-auto">
      <PageHeader
        title="Forensic Investigation"
        subtitle="Evidence-backed, deterministic causal analysis. Zero AI hallucination in enforcement explanations"
        badge="Deterministic Forensics"
      />

      {/* Tabs */}
      <div className="flex border-b border-slate-200 gap-6 text-sm font-medium">
        {[
          { id: 'why-blocked', label: 'Why Was This Blocked?' },
          { id: 'agents', label: 'Agent Forensics' },
          { id: 'resources', label: 'Resource Blast Radius' },
          { id: 'authority', label: 'Authority Lineage' },
          { id: 'access', label: 'Access Log Audit' },
        ].map(({ id, label }) => (
          <button
            key={id}
            onClick={() => setTab(id as ForensicTab)}
            className={`pb-3 border-b-2 transition-colors ${
              tab === id
                ? 'border-blue-600 text-blue-600 font-semibold'
                : 'border-transparent text-slate-500 hover:text-slate-800'
            }`}
          >
            {label}
          </button>
        ))}
      </div>

      {/* Tab content */}
      {tab === 'why-blocked' && <WhyBlockedTab exp={exp} />}
      {tab === 'agents' && <AgentForensicsTab />}
      {tab === 'resources' && <ResourceForensicsTab />}
      {tab === 'authority' && <AuthorityForensicsTab />}
      {tab === 'access' && <AccessForensicsTab />}
    </div>
  );
}

// ─── Why Was This Blocked? ────────────────────────────────────────────────

function WhyBlockedTab({ exp }: { exp: ForensicExplanationData }) {
  return (
    <div className="space-y-6">
      {/* Root Incident Banner */}
      <div className="bg-red-50/80 border border-red-200 rounded-lg p-5">
        <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-red-700 mb-1.5">
          <AlertTriangle size={15} />
          <span>Deterministic Block Root Cause Verdict</span>
        </div>
        <div className="text-base font-bold text-slate-900">
          Action <span className="font-mono text-red-700">{exp.tool_name}</span> attempted by agent <span className="font-mono text-blue-700">{exp.agent_id}</span> was rejected.
        </div>
        <div className="text-xs text-slate-600 mt-1">
          Evaluation Timestamp: <span className="font-mono">{new Date(exp.timestamp).toUTCString()}</span> • Event ID: <span className="font-mono">{exp.event_id}</span>
        </div>
      </div>

      {/* 4-Point Execution Truth */}
      <div className="bg-white border border-slate-200 rounded-lg p-5 shadow-xs">
        <div className="text-xs font-semibold uppercase tracking-wider text-slate-500 mb-4">4-Point Execution State Verification</div>
        <ExecutionTruth
          intended={true}
          requested={true}
          allowed={false}
          executed={false}
          blockedAt="Deterministic Rule: pol_no_pii_export"
        />
      </div>

      {/* Key Forensic Attributes */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="p-4 bg-white border border-slate-200 rounded-lg shadow-xs">
          <div className="text-[10px] uppercase font-semibold text-slate-500 mb-1">Attempted Action</div>
          <div className="font-mono text-sm font-bold text-red-700">{exp.tool_name}</div>
          <div className="text-[11px] text-slate-500 mt-0.5">High-risk external egress</div>
        </div>
        <div className="p-4 bg-white border border-slate-200 rounded-lg shadow-xs">
          <div className="text-[10px] uppercase font-semibold text-slate-500 mb-1">Acting Principal</div>
          <div className="font-mono text-sm font-bold text-slate-800">{exp.agent_id}</div>
          <div className="text-[11px] text-slate-500 mt-0.5">Trust Level: {exp.agent_trust}</div>
        </div>
        <div className="p-4 bg-white border border-slate-200 rounded-lg shadow-xs">
          <div className="text-[10px] uppercase font-semibold text-slate-500 mb-1">Context Origin</div>
          <div className="font-mono text-sm font-bold text-red-700">UNTRUSTED</div>
          <div className="text-[11px] text-slate-500 mt-0.5">Taint Source: External MCP</div>
        </div>
        <div className="p-4 bg-white border border-slate-200 rounded-lg shadow-xs">
          <div className="text-[10px] uppercase font-semibold text-slate-500 mb-1">Target Sink</div>
          <div className="font-mono text-sm font-bold text-slate-800">{exp.resource_name ?? 's3_exports'}</div>
          <div className="text-[11px] text-slate-500 mt-0.5">Sensitivity: {exp.resource_sensitivity}</div>
        </div>
      </div>

      {/* Step-by-Step Causal Evidence Chain */}
      <div className="bg-white border border-slate-200 rounded-lg p-5 shadow-xs space-y-4">
        <div className="text-xs font-semibold uppercase tracking-wider text-slate-500">Causal Evidence Sequence</div>
        <div className="space-y-3">
          {[
            {
              step: 1,
              title: 'Context Ingestion from Untrusted Source',
              detail: 'Agent received instruction payload from external untrusted MCP server containing suspected prompt injection pattern.',
              status: 'TAINT DETECTED',
              badgeColor: 'bg-amber-50 text-amber-800 border-amber-200',
            },
            {
              step: 2,
              title: 'Taint Propagation into Agent State',
              detail: 'Execution runtime marked agent active memory as tainted with HIGH sensitivity level.',
              status: 'STATE TAINTED',
              badgeColor: 'bg-amber-50 text-amber-800 border-amber-200',
            },
            {
              step: 3,
              title: 'Egress Tool Invocation Request',
              detail: 'Agent attempted invocation of upload_s3 to transmit sensitive database records to an external cloud bucket.',
              status: 'SINK REACHED',
              badgeColor: 'bg-blue-50 text-blue-800 border-blue-200',
            },
            {
              step: 4,
              title: 'Deterministic Policy Enforcement Interception',
              detail: 'Rule "pol_no_pii_export" evaluated true: Tainted agent blocked from invoking egress tools. Request aborted prior to network execution.',
              status: 'BLOCKED',
              badgeColor: 'bg-red-50 text-red-800 border-red-200 font-bold',
            },
          ].map((item) => (
            <div key={item.step} className="p-4 bg-slate-50 border border-slate-200 rounded-lg flex items-start gap-4">
              <div className="w-6 h-6 rounded-full bg-slate-200 text-slate-700 flex items-center justify-center font-mono text-xs font-bold flex-shrink-0 mt-0.5">
                {item.step}
              </div>
              <div className="flex-1">
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-xs text-slate-900">{item.title}</span>
                  <span className={`text-[10px] px-2 py-0.5 rounded border font-mono ${item.badgeColor}`}>
                    {item.status}
                  </span>
                </div>
                <p className="text-xs text-slate-600 mt-1 leading-relaxed">{item.detail}</p>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ─── Agent Forensics ──────────────────────────────────────────────────────

function AgentForensicsTab() {
  return (
    <div className="space-y-4">
      <div className="bg-white border border-slate-200 rounded-lg p-5 shadow-xs">
        <div className="text-xs font-semibold uppercase tracking-wider text-slate-500 mb-4">Agent Trust Profiles & Capability Sets</div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {DEMO_AGENTS.map((agent) => (
            <div key={agent.agent_id} className="p-4 bg-slate-50 border border-slate-200 rounded-lg space-y-3">
              <div className="flex items-center justify-between">
                <div>
                  <div className="font-mono font-semibold text-xs text-slate-900">{agent.agent_id}</div>
                  <div className="text-[11px] text-slate-500">{agent.name}</div>
                </div>
                <StatusBadge status={agent.status === 'blocked' ? 'BLOCK' : 'ALLOW'} />
              </div>
              <div className="text-xs text-slate-600">
                <div className="flex justify-between py-1 border-b border-slate-200">
                  <span className="text-slate-500">Trust Level</span>
                  <span className="font-mono font-medium">{agent.trust_level}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-200">
                  <span className="text-slate-500">Capabilities</span>
                  <span className="font-mono">{agent.capabilities.length} granted</span>
                </div>
                <div className="flex justify-between py-1">
                  <span className="text-slate-500">Risk Level</span>
                  <span className={`font-mono font-bold ${agent.risk_level === 'CRITICAL' ? 'text-red-600' : 'text-slate-700'}`}>
                    {agent.risk_level || 'LOW'}
                  </span>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ─── Resource Forensics ───────────────────────────────────────────────────

function ResourceForensicsTab() {
  return (
    <div className="space-y-4">
      <div className="bg-white border border-slate-200 rounded-lg p-5 shadow-xs">
        <div className="text-xs font-semibold uppercase tracking-wider text-slate-500 mb-4">Resource Blast Radius Analysis</div>
        <div className="space-y-3">
          {[
            { name: 'customers', type: 'Database (PII)', blast: 'CRITICAL', reach: '2 Agents', risk: 'HIGH' },
            { name: 'orders', type: 'Database (Orders)', blast: 'MEDIUM', reach: '4 Agents', risk: 'LOW' },
            { name: 's3://company-exports/', type: 'Cloud Storage', blast: 'CRITICAL', reach: '0 Agents (Quarantine)', risk: 'ZERO-TRUST' },
          ].map((r) => (
            <div key={r.name} className="p-4 bg-slate-50 border border-slate-200 rounded-lg flex items-center justify-between text-xs">
              <div>
                <div className="font-mono font-bold text-slate-900">{r.name}</div>
                <div className="text-slate-500">{r.type}</div>
              </div>
              <div className="flex items-center gap-4">
                <span className="font-mono text-slate-600">{r.reach}</span>
                <span className="px-2 py-0.5 rounded border bg-red-50 text-red-700 border-red-200 font-semibold font-mono">
                  {r.blast} BLAST
                </span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ─── Authority Forensics ──────────────────────────────────────────────────

function AuthorityForensicsTab() {
  return (
    <div className="space-y-4">
      <div className="bg-white border border-slate-200 rounded-lg p-5 shadow-xs">
        <div className="text-xs font-semibold uppercase tracking-wider text-slate-500 mb-4">Authority Proofs & Nonce Verification</div>
        <p className="text-xs text-slate-600 leading-relaxed">
          Every agent action must present an unforgeable, cryptographically signed delegation token containing root provenance nonces.
        </p>
      </div>
    </div>
  );
}

// ─── Access Forensics ─────────────────────────────────────────────────────

function AccessForensicsTab() {
  return (
    <div className="space-y-4">
      <div className="bg-white border border-slate-200 rounded-lg p-5 shadow-xs">
        <div className="text-xs font-semibold uppercase tracking-wider text-slate-500 mb-4">Audit Access Log Events</div>
        <div className="space-y-2">
          {[
            { time: '10:30:14 UTC', actor: 'escalation_agent', action: 'write_s3', target: 's3://company-exports', decision: 'BLOCK' },
            { time: '10:28:45 UTC', actor: 'data_agent', action: 'read_db', target: 'orders', decision: 'ALLOW' },
            { time: '10:15:02 UTC', actor: 'orchestrator_v2', action: 'generate_summary', target: 'internal_llm', decision: 'ALLOW' },
          ].map((item, i) => (
            <div key={i} className="p-3 bg-slate-50 border border-slate-200 rounded-lg flex items-center justify-between text-xs font-mono">
              <span className="text-slate-500">{item.time}</span>
              <span className="text-slate-900 font-semibold">{item.actor}</span>
              <span className="text-blue-700">{item.action}</span>
              <span className="text-slate-600">{item.target}</span>
              <StatusBadge status={item.decision as 'ALLOW' | 'BLOCK'} />
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
