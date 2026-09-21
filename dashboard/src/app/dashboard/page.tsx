'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import { PageHeader } from '@/components/ui/PageHeader';
import { MetricCard } from '@/components/ui/MetricCard';
import { DataTable, Column } from '@/components/ui/DataTable';
import { DecisionBadge, SeverityBadge, TrustBadge } from '@/components/ui/StatusBadge';
import { DetailDrawer } from '@/components/ui/DetailDrawer';
import { ExecutionTruth } from '@/components/ui/ExecutionTruth';
import { 
  ShieldCheck, ShieldAlert, Users, AlertTriangle, 
  RotateCcw, Activity, ArrowUpRight, CheckCircle2, 
  ExternalLink, Zap, Lock, RefreshCw, Compass
} from 'lucide-react';
import { 
  AreaChart, Area, BarChart, Bar, XAxis, YAxis, CartesianGrid, 
  Tooltip, ResponsiveContainer 
} from 'recharts';

interface ActivityRecord {
  id: string;
  time: string;
  agent: string;
  action: string;
  resource: string;
  risk: string;
  decision: string;
  executed: boolean;
}

interface IncidentRecord {
  id: string;
  name: string;
  severity: string;
  agent: string;
  detection: string;
  state: string;
  time: string;
}

const DEMO_ACTIVITIES: ActivityRecord[] = [
  { id: 'evt_001', time: '15:32:10', agent: 'research-agent-001', action: 'customer_db.read', resource: 'customer_pii_vault', risk: 'CRITICAL', decision: 'BLOCK', executed: false },
  { id: 'evt_002', time: '15:31:45', agent: 'analysis-agent-001', action: 'report.generate', resource: 'internal_reports', risk: 'LOW', decision: 'ALLOW', executed: true },
  { id: 'evt_003', time: '15:30:12', agent: 'orchestrator-001', action: 'delegate.scope', resource: 'task_graph', risk: 'LOW', decision: 'ALLOW', executed: true },
  { id: 'evt_004', time: '15:28:55', agent: 'external-mcp-bot', action: 'http_post', resource: 'external_webhook', risk: 'HIGH', decision: 'BLOCK', executed: false },
  { id: 'evt_005', time: '15:26:30', agent: 'data-sync-002', action: 'db.query', resource: 'financial_ledger', risk: 'MEDIUM', decision: 'ALLOW', executed: true },
  { id: 'evt_006', time: '15:24:18', agent: 'research-agent-001', action: 'web_search', resource: 'public_web', risk: 'LOW', decision: 'ALLOW', executed: true },
];

const DEMO_INCIDENTS: IncidentRecord[] = [
  { id: 'INC-1049', name: 'Authority Escalation Attempt', severity: 'HIGH', agent: 'research-agent-001', detection: 'Monotonic Invariant Rule', state: 'CONTAINED', time: '15:14' },
  { id: 'INC-1048', name: 'Tainted MCP Prompt Injection', severity: 'CRITICAL', agent: 'orchestrator-001', detection: 'Taint Sink Boundary', state: 'CLOSED', time: '14:22' },
];

const TIME_SERIES_DATA = [
  { time: '10:00', allow: 45, block: 2, hitl: 0 },
  { time: '11:00', allow: 62, block: 4, hitl: 1 },
  { time: '12:00', allow: 78, block: 1, hitl: 0 },
  { time: '13:00', allow: 94, block: 5, hitl: 2 },
  { time: '14:00', allow: 110, block: 3, hitl: 0 },
  { time: '15:00', allow: 85, block: 2, hitl: 1 },
];

export default function CommandCenterPage() {
  const [selectedEvent, setSelectedEvent] = useState<ActivityRecord | null>(null);
  const [isDrawerOpen, setIsDrawerOpen] = useState(false);

  const activityColumns: Column<ActivityRecord>[] = [
    { key: 'time', header: 'Time', mono: true, width: '90px' },
    {
      key: 'agent',
      header: 'Agent',
      render: (row) => (
        <span className="font-mono text-[11px] font-medium text-slate-800 bg-slate-100 px-1.5 py-0.5 rounded">
          {row.agent}
        </span>
      ),
    },
    { key: 'action', header: 'Action', mono: true, render: (row) => <span className="font-semibold text-slate-900">{row.action}</span> },
    { key: 'resource', header: 'Protected Resource', mono: true, render: (row) => <span className="text-slate-500">{row.resource}</span> },
    { key: 'risk', header: 'Risk', width: '100px', render: (row) => <SeverityBadge severity={row.risk} /> },
    { key: 'decision', header: 'Decision', width: '90px', render: (row) => <DecisionBadge decision={row.decision} /> },
    {
      key: 'executed',
      header: 'Execution Status',
      align: 'right',
      render: (row) => (
        <span className={`font-mono text-[10px] font-bold px-2 py-0.5 rounded ${row.executed ? 'text-emerald-700 bg-emerald-50 border border-emerald-200' : 'text-slate-500 bg-slate-100 border border-slate-200'}`}>
          {row.executed ? 'EXECUTED' : 'NOT EXECUTED'}
        </span>
      ),
    },
  ];

  const handleRowClick = (event: ActivityRecord) => {
    setSelectedEvent(event);
    setIsDrawerOpen(true);
  };

  return (
    <div className="max-w-[1600px] mx-auto space-y-6">
      <PageHeader
        title="Security Command Center"
        description="Continuous runtime security control plane, telemetry metrics, and deterministic policy enforcement across all autonomous agents."
        actions={
          <div className="flex items-center gap-2">
            <Link
              href="/security-gates"
              className="px-3 py-1.5 text-xs font-semibold bg-emerald-50 text-emerald-800 border border-emerald-200 rounded-md hover:bg-emerald-100 transition-colors flex items-center gap-1.5"
            >
              <CheckCircle2 size={13} className="text-emerald-600" />
              <span>CI/CD Quality Gate: PASS</span>
            </Link>
          </div>
        }
      />

      {/* Top Banner: Security Posture Scorecard */}
      <div className="bg-white border border-slate-200 rounded-lg p-5 shadow-sm flex flex-col md:flex-row md:items-center justify-between gap-5 border-l-4 border-l-emerald-500">
        <div className="flex items-start gap-4">
          <div className="w-12 h-12 rounded-lg bg-emerald-50 text-emerald-600 border border-emerald-200 flex items-center justify-center flex-shrink-0 font-bold text-xl">
            A
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-lg font-bold text-slate-900 tracking-tight">
                Security Posture: 98.0 / 100
              </h2>
              <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-50 text-emerald-800 border border-emerald-200">
                HEALTHY
              </span>
            </div>
            <p className="text-xs text-slate-500 mt-0.5">
              Deterministic runtime policies active. 0 unauthorized executions across 472 intercepted tool invocations.
            </p>
          </div>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs border-t md:border-t-0 md:border-l border-slate-200 pt-3 md:pt-0 md:pl-5">
          <div>
            <span className="text-[10px] text-slate-400 font-bold uppercase block">Threat Prevention</span>
            <span className="font-mono font-bold text-slate-900">100.0%</span>
          </div>
          <div>
            <span className="text-[10px] text-slate-400 font-bold uppercase block">Delegation Hygiene</span>
            <span className="font-mono font-bold text-slate-900">100.0%</span>
          </div>
          <div>
            <span className="text-[10px] text-slate-400 font-bold uppercase block">Taint Containment</span>
            <span className="font-mono font-bold text-slate-900">100.0%</span>
          </div>
          <div>
            <span className="text-[10px] text-slate-400 font-bold uppercase block">Offensive Immunity</span>
            <span className="font-mono font-bold text-slate-900">100.0%</span>
          </div>
        </div>
      </div>

      {/* KPI Grid (6 Compact Enterprise Metric Cards) */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        <MetricCard label="Active Agents" value="4" subtext="All Contained" status="healthy" icon={Users} />
        <MetricCard label="Active Incidents" value="0" subtext="0 Critical / High" status="healthy" icon={AlertTriangle} />
        <MetricCard label="Blocked Actions" value="17" subtext="100% Policy Block" status="neutral" icon={ShieldAlert} />
        <MetricCard label="Drift Alerts" value="0" subtext="Entropy Normal" status="healthy" icon={Compass} />
        <MetricCard label="Open Regressions" value="0" subtext="42 Replays Passing" status="healthy" icon={RotateCcw} />
        <MetricCard label="Unauthorized DB Calls" value="0" subtext="Zero Sink Bypasses" status="healthy" icon={Lock} />
      </div>

      {/* Main Grid: Activity Table & Side Panels */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left 2 Cols: Real-Time Security Activity */}
        <div className="lg:col-span-2 space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-slate-900 tracking-tight flex items-center gap-2">
              <Activity size={16} className="text-slate-500" />
              <span>Real-Time Security Activity</span>
            </h3>
            <Link href="/activity" className="text-xs text-sky-700 hover:text-sky-900 font-medium flex items-center gap-1">
              <span>View all events</span>
              <ArrowUpRight size={12} />
            </Link>
          </div>

          <DataTable
            columns={activityColumns}
            data={DEMO_ACTIVITIES}
            keyExtractor={(item) => item.id}
            onRowClick={handleRowClick}
            pageSize={6}
          />
        </div>

        {/* Right 1 Col: Security Trends & Active Incidents */}
        <div className="space-y-6">
          {/* Security Decisions Chart */}
          <div className="bg-white border border-slate-200 rounded-lg p-4 shadow-sm">
            <div className="flex items-center justify-between mb-3">
              <h4 className="text-xs font-bold uppercase tracking-wider text-slate-500">
                Hourly Enforcement Trend
              </h4>
              <span className="text-[10px] text-slate-400 font-mono">Last 6 Hours</span>
            </div>
            <div className="h-44 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={TIME_SERIES_DATA} margin={{ top: 5, right: 5, left: -25, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#F1F5F9" />
                  <XAxis dataKey="time" tick={{ fontSize: 10, fill: '#64748B' }} axisLine={false} tickLine={false} />
                  <YAxis tick={{ fontSize: 10, fill: '#64748B' }} axisLine={false} tickLine={false} />
                  <Tooltip
                    contentStyle={{ backgroundColor: '#0F172A', border: 'none', borderRadius: '6px', fontSize: '11px', color: '#fff' }}
                  />
                  <Area type="monotone" dataKey="allow" stroke="#10B981" fill="#D1FAE5" fillOpacity={0.6} />
                  <Area type="monotone" dataKey="block" stroke="#EF4444" fill="#FEE2E2" fillOpacity={0.8} />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Active Incidents Overview */}
          <div className="bg-white border border-slate-200 rounded-lg p-4 shadow-sm space-y-3">
            <div className="flex items-center justify-between border-b border-slate-100 pb-2">
              <h4 className="text-xs font-bold uppercase tracking-wider text-slate-500 flex items-center gap-1.5">
                <AlertTriangle size={13} className="text-amber-500" />
                <span>Recent Incident Lifecycles</span>
              </h4>
              <Link href="/incidents" className="text-xs text-sky-700 hover:text-sky-900 font-medium">
                Manage
              </Link>
            </div>

            <div className="space-y-2">
              {DEMO_INCIDENTS.map((inc) => (
                <div key={inc.id} className="p-2.5 rounded border border-slate-100 hover:border-slate-300 transition-colors bg-slate-50/50">
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-mono font-bold text-slate-900">{inc.id}</span>
                    <SeverityBadge severity={inc.severity} />
                  </div>
                  <div className="text-xs font-semibold text-slate-800 mt-1">{inc.name}</div>
                  <div className="flex items-center justify-between text-[11px] text-slate-500 mt-1.5 pt-1.5 border-t border-slate-100">
                    <span className="font-mono">{inc.agent}</span>
                    <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-slate-200 text-slate-700">
                      {inc.state}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Forensic Drawer */}
      <DetailDrawer
        isOpen={isDrawerOpen}
        onClose={() => setIsDrawerOpen(false)}
        title={`Event Investigation: ${selectedEvent?.id}`}
        subtitle={`${selectedEvent?.time} • ${selectedEvent?.action}`}
        badge={selectedEvent && <DecisionBadge decision={selectedEvent.decision} />}
      >
        {selectedEvent && (
          <div className="space-y-4 text-xs">
            <ExecutionTruth
              intended={selectedEvent.decision === 'ALLOW'}
              requested={true}
              allowed={selectedEvent.decision === 'ALLOW'}
              executed={selectedEvent.executed}
              blockedAt={selectedEvent.decision === 'BLOCK' ? 'Deterministic Taint Sink Gate' : undefined}
            />

            <div className="p-3 bg-slate-50 border border-slate-200 rounded-lg space-y-2">
              <div>
                <span className="text-[10px] font-bold text-slate-400 uppercase block">AGENT</span>
                <span className="font-mono text-slate-900">{selectedEvent.agent}</span>
              </div>
              <div>
                <span className="text-[10px] font-bold text-slate-400 uppercase block">REQUESTED ACTION</span>
                <span className="font-mono font-semibold text-slate-900">{selectedEvent.action}</span>
              </div>
              <div>
                <span className="text-[10px] font-bold text-slate-400 uppercase block">TARGET RESOURCE</span>
                <span className="font-mono text-slate-700">{selectedEvent.resource}</span>
              </div>
            </div>
          </div>
        )}
      </DetailDrawer>
    </div>
  );
}
