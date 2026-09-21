'use client';

import React, { useState, useEffect, useRef } from 'react';
import { PageHeader } from '@/components/ui/PageHeader';
import { FilterBar } from '@/components/ui/FilterBar';
import { MetricCard } from '@/components/ui/MetricCard';
import { DataTable, Column } from '@/components/ui/DataTable';
import { DecisionBadge, SeverityBadge } from '@/components/ui/StatusBadge';
import { DetailDrawer } from '@/components/ui/DetailDrawer';
import { ExecutionTruth } from '@/components/ui/ExecutionTruth';
import { DEMO_EVENTS } from '@/data/demo';
import { Activity, Pause, Play, AlertTriangle, CheckCircle2, Clock, ShieldAlert, Radio } from 'lucide-react';

export default function ActivityPage() {
  const [paused, setPaused] = useState<boolean>(false);
  const [decisionFilter, setDecisionFilter] = useState<string>('ALL');
  const [search, setSearch] = useState<string>('');
  const [events, setEvents] = useState<any[]>(DEMO_EVENTS.slice(0, 30));
  const [selectedEvent, setSelectedEvent] = useState<any | null>(null);
  const [isDrawerOpen, setIsDrawerOpen] = useState(false);

  // Live simulation event generator (bounded buffer to 100 max)
  useEffect(() => {
    if (paused) return;
    const interval = setInterval(() => {
      const sample = DEMO_EVENTS[Math.floor(Math.random() * DEMO_EVENTS.length)];
      const newEvt = {
        ...sample,
        event_id: `evt_live_${Date.now().toString(36)}`,
        timestamp: new Date().toLocaleTimeString(),
      };
      setEvents((prev) => [newEvt, ...prev].slice(0, 100));
    }, 3000);
    return () => clearInterval(interval);
  }, [paused]);

  const filtered = events.filter((e) => {
    if (decisionFilter !== 'ALL' && e.decision !== decisionFilter) return false;
    if (search) {
      const q = search.toLowerCase();
      const match =
        (e.event_id || '').toLowerCase().includes(q) ||
        (e.agent_id || '').toLowerCase().includes(q) ||
        (e.tool_name || '').toLowerCase().includes(q) ||
        (e.decision || '').toLowerCase().includes(q);
      if (!match) return false;
    }
    return true;
  });

  const stats = {
    allow: events.filter((e) => e.decision === 'ALLOW').length,
    block: events.filter((e) => e.decision === 'BLOCK').length,
    hitl: events.filter((e) => e.decision === 'HITL').length,
    total: events.length,
  };

  const columns: Column<any>[] = [
    {
      key: 'timestamp',
      header: 'Time',
      mono: true,
      width: '100px',
      render: (row) => <span className="text-slate-500">{row.timestamp || 'Just now'}</span>,
    },
    {
      key: 'event_id',
      header: 'Event ID',
      mono: true,
      width: '130px',
      render: (row) => (
        <span className="font-semibold text-slate-900 hover:text-sky-700 underline decoration-slate-300">
          {row.event_id}
        </span>
      ),
    },
    {
      key: 'agent_id',
      header: 'Agent',
      render: (row) => (
        <span className="font-mono text-[11px] text-slate-800 bg-slate-100 px-1.5 py-0.5 rounded">
          {row.agent_id || 'system'}
        </span>
      ),
    },
    {
      key: 'event_type',
      header: 'Event Type',
      mono: true,
      render: (row) => <span className="text-slate-700 font-medium">{row.event_type || 'tool_invocation'}</span>,
    },
    {
      key: 'tool_name',
      header: 'Tool / Target',
      mono: true,
      render: (row) => <span className="font-semibold text-slate-900">{row.tool_name || 'internal_resource'}</span>,
    },
    {
      key: 'decision',
      header: 'Decision',
      width: '100px',
      render: (row) => <DecisionBadge decision={row.decision || 'ALLOW'} />,
    },
    {
      key: 'risk_score',
      header: 'Risk Score',
      align: 'right',
      width: '100px',
      render: (row) => (
        <span className="font-mono text-[11px] text-slate-600">
          {typeof row.risk_score === 'number' ? row.risk_score.toFixed(2) : '0.00'}
        </span>
      ),
    },
  ];

  return (
    <div className="max-w-[1600px] mx-auto space-y-5">
      <PageHeader
        title="Live Activity Stream"
        description="Real-time security telemetry feed of all tool requests, capability validations, taint tracking events, and deterministic policy evaluations."
        breadcrumbs={[
          { label: 'Overview', href: '/dashboard' },
          { label: 'Live Activity' },
        ]}
        actions={
          <div className="flex items-center gap-2">
            <button
              onClick={() => setPaused(!paused)}
              className={`px-3 py-1.5 text-xs font-semibold rounded-md border flex items-center gap-1.5 transition-colors cursor-pointer ${
                paused
                  ? 'bg-amber-50 text-amber-800 border-amber-200 hover:bg-amber-100'
                  : 'bg-white text-slate-700 border-slate-300 hover:bg-slate-50'
              }`}
            >
              {paused ? (
                <>
                  <Play size={13} className="text-amber-700" />
                  <span>Resume Stream</span>
                </>
              ) : (
                <>
                  <Pause size={13} className="text-slate-600" />
                  <span>Pause Stream</span>
                </>
              )}
            </button>
            <div className="flex items-center gap-1 text-[11px] text-emerald-800 bg-emerald-50 border border-emerald-200 px-2 py-1 rounded font-mono font-medium">
              <span className={`w-2 h-2 rounded-full ${paused ? 'bg-amber-500' : 'bg-emerald-500 animate-pulse'}`} />
              <span>{paused ? 'PAUSED' : 'LIVE (3s)'}</span>
            </div>
          </div>
        }
      />

      {/* KPI Stats */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <MetricCard label="Total Streamed" value={stats.total} subtext="Bounded to 100 max" status="neutral" icon={Activity} />
        <MetricCard label="Allowed Actions" value={stats.allow} subtext="Policy verified" status="healthy" icon={CheckCircle2} />
        <MetricCard label="Blocked Actions" value={stats.block} subtext="Threat contained" status="critical" icon={ShieldAlert} />
        <MetricCard label="Human Approvals" value={stats.hitl} subtext="HITL Escalations" status="warning" icon={Clock} />
      </div>

      {/* Filter Toolbar */}
      <FilterBar
        searchQuery={search}
        onSearchChange={setSearch}
        searchPlaceholder="Search event ID, agent, tool…"
        totalCount={events.length}
        activeCount={filtered.length}
        onReset={() => {
          setSearch('');
          setDecisionFilter('ALL');
        }}
        dropdowns={[
          {
            name: 'decision',
            label: 'Decision',
            value: decisionFilter,
            onChange: setDecisionFilter,
            options: [
              { label: 'All Decisions', value: 'ALL' },
              { label: 'ALLOW', value: 'ALLOW' },
              { label: 'BLOCK', value: 'BLOCK' },
              { label: 'HITL', value: 'HITL' },
            ],
          },
        ]}
      />

      {/* Table */}
      <DataTable
        columns={columns}
        data={filtered}
        keyExtractor={(row) => row.event_id}
        onRowClick={(row) => {
          setSelectedEvent(row);
          setIsDrawerOpen(true);
        }}
        selectedKey={selectedEvent?.event_id}
        pageSize={15}
      />

      {/* Detail Drawer */}
      <DetailDrawer
        isOpen={isDrawerOpen}
        onClose={() => setIsDrawerOpen(false)}
        title={`Event: ${selectedEvent?.event_id}`}
        subtitle={`${selectedEvent?.timestamp} • ${selectedEvent?.tool_name}`}
        badge={selectedEvent && <DecisionBadge decision={selectedEvent.decision} />}
      >
        {selectedEvent && (
          <div className="space-y-4 text-xs">
            <ExecutionTruth
              intended={selectedEvent.decision === 'ALLOW'}
              requested={true}
              allowed={selectedEvent.decision === 'ALLOW'}
              executed={selectedEvent.decision === 'ALLOW'}
              blockedAt={selectedEvent.decision === 'BLOCK' ? 'Deterministic Policy Gate' : undefined}
            />

            <div className="p-3 bg-slate-50 border border-slate-200 rounded-lg space-y-2">
              <div>
                <span className="text-[10px] font-bold text-slate-400 uppercase block">AGENT</span>
                <span className="font-mono text-slate-900">{selectedEvent.agent_id}</span>
              </div>
              <div>
                <span className="text-[10px] font-bold text-slate-400 uppercase block">INVOKED TOOL</span>
                <span className="font-mono font-semibold text-slate-900">{selectedEvent.tool_name}</span>
              </div>
              <div>
                <span className="text-[10px] font-bold text-slate-400 uppercase block">TRACE ID</span>
                <span className="font-mono text-slate-600">{selectedEvent.trace_id || 'trc_default'}</span>
              </div>
            </div>

            <div>
              <span className="text-[10px] font-bold text-slate-400 uppercase block mb-1">EVENT PAYLOAD</span>
              <pre className="p-3 bg-slate-900 text-slate-100 rounded-lg font-mono text-[11px] overflow-x-auto whitespace-pre-wrap leading-relaxed">
                {JSON.stringify(selectedEvent, null, 2)}
              </pre>
            </div>
          </div>
        )}
      </DetailDrawer>
    </div>
  );
}
