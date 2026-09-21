'use client';

import { useState, useEffect } from 'react';
import {
  Activity, Shield, AlertTriangle, RefreshCw, Lock, Zap,
  Database, ArrowRight, CheckCircle2, Eye, GitBranch,
  Layers, Search, Filter
} from 'lucide-react';
import { PageHeader } from '@/components/ui/PageHeader';
import { MetricCard } from '@/components/ui/MetricCard';
import { FilterBar } from '@/components/ui/FilterBar';
import { DataTable } from '@/components/ui/DataTable';
import { StatusBadge } from '@/components/ui/StatusBadge';
import { DetailDrawer } from '@/components/ui/DetailDrawer';

const API_BASE = 'http://127.0.0.1:8000/api/v1';

interface DriftEvent {
  drift_id: string;
  category: 'CONTEXT_DRIFT' | 'AUTHORITY_DRIFT' | 'ACCESS_DRIFT' | string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | string;
  entity_id: string;
  entity_type: string;
  title: string;
  description: string;
  before_state: any;
  after_state: any;
  security_implication: string;
  review_required: boolean;
  detected_at: string;
  evidence_refs?: string[];
}

interface AgentBaseline {
  agent_id: string;
  normal_tools: string[];
  normal_resources: string[];
  normal_max_depth: number;
  normal_context_sources: string[];
  sample_count: number;
  last_updated: string;
}

const FALLBACK_EVENTS: DriftEvent[] = [
  {
    drift_id: 'drf_a7fe6289575f406f',
    category: 'CONTEXT_DRIFT',
    severity: 'HIGH',
    entity_id: 'ctx_59eaf37bafbc4bc4',
    entity_type: 'context',
    title: 'Context Trust State Transition (TRUSTED -> UNTRUSTED)',
    description: "Context from source 'external_mcp' changed trust classification to 'UNTRUSTED'.",
    before_state: 'TRUSTED',
    after_state: 'UNTRUSTED',
    security_implication: 'Taint boundary crossed. Downstream agents consuming this context must be restricted from sensitive sinks.',
    review_required: true,
    detected_at: new Date().toISOString(),
    evidence_refs: ['mcp_req_0091'],
  },
  {
    drift_id: 'drf_363372b7cac94429',
    category: 'AUTHORITY_DRIFT',
    severity: 'HIGH',
    entity_id: 'agt_60aeff2cd2a44742',
    entity_type: 'agent',
    title: "Authority Expansion Detected on Agent 'agt_60aeff2cd2a44742'",
    description: "Agent granted new capabilities: ['exec_bash', 'write_db']",
    before_state: ['read_file'],
    after_state: ['read_file', 'write_db', 'exec_bash'],
    security_implication: 'Agent capability boundary expanded. Verify alignment with principle of least privilege.',
    review_required: true,
    detected_at: new Date().toISOString(),
    evidence_refs: ['del_003'],
  },
  {
    drift_id: 'drf_7cf39d1b76304bc3',
    category: 'ACCESS_DRIFT',
    severity: 'MEDIUM',
    entity_id: 'agt_220dca9e87ac4fe2',
    entity_type: 'agent',
    title: "New Resource Target Attempted: 'fin_export_api'",
    description: "Agent 'agt_220dca9e87ac4fe2' attempted access to 'fin_export_api' for the first time.",
    before_state: ['local_fs', 'quarterly_reports'],
    after_state: ['local_fs', 'quarterly_reports', 'fin_export_api'],
    security_implication: 'Anomalous resource access path. Potential lateral movement or prompt injection target.',
    review_required: true,
    detected_at: new Date().toISOString(),
    evidence_refs: ['act_0942'],
  },
];

const SEVERITY_BADGES: Record<string, string> = {
  CRITICAL: 'bg-red-50 text-red-700 border-red-200 font-semibold',
  HIGH: 'bg-amber-50 text-amber-700 border-amber-200 font-medium',
  MEDIUM: 'bg-blue-50 text-blue-700 border-blue-200',
  LOW: 'bg-slate-50 text-slate-700 border-slate-200',
};

const CATEGORY_BADGES: Record<string, string> = {
  CONTEXT_DRIFT: 'bg-purple-50 text-purple-700 border-purple-200',
  AUTHORITY_DRIFT: 'bg-amber-50 text-amber-700 border-amber-200',
  ACCESS_DRIFT: 'bg-blue-50 text-blue-700 border-blue-200',
};

export default function DriftPage() {
  const [events, setEvents] = useState<DriftEvent[]>(FALLBACK_EVENTS);
  const [loading, setLoading] = useState(false);
  const [search, setSearch] = useState('');
  const [categoryFilter, setCategoryFilter] = useState('ALL');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [selectedDrift, setSelectedDrift] = useState<DriftEvent | null>(null);

  const fetchDrift = async () => {
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/drift`);
      if (res.ok) {
        const data = await res.json();
        const evs = data.events || data.drift_events || [];
        if (evs.length > 0) setEvents(evs);
      }
    } catch {
      // Fallback in use
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDrift();
  }, []);

  const filtered = events.filter(e => {
    const matchSearch =
      e.title.toLowerCase().includes(search.toLowerCase()) ||
      e.description.toLowerCase().includes(search.toLowerCase()) ||
      e.entity_id.toLowerCase().includes(search.toLowerCase());

    const matchCategory = categoryFilter === 'ALL' || e.category === categoryFilter;
    const matchSeverity = severityFilter === 'ALL' || e.severity === severityFilter;

    return matchSearch && matchCategory && matchSeverity;
  });

  const columns = [
    {
      key: 'title',
      header: 'Anomaly Event',
      render: (row: DriftEvent) => (
        <div className="flex items-center gap-2.5">
          <div className="w-7 h-7 rounded-md bg-slate-100 flex items-center justify-center text-slate-600 border border-slate-200">
            <Activity size={13} />
          </div>
          <div>
            <div className="font-semibold text-xs text-slate-900">{row.title}</div>
            <div className="text-[11px] font-mono text-slate-500">{row.drift_id}</div>
          </div>
        </div>
      ),
    },
    {
      key: 'category',
      header: 'Category',
      width: '150px',
      render: (row: DriftEvent) => (
        <span className={`text-[11px] font-mono px-2 py-0.5 rounded border ${CATEGORY_BADGES[row.category] || 'bg-slate-100 text-slate-700'}`}>
          {row.category.replace('_', ' ')}
        </span>
      ),
    },
    {
      key: 'severity',
      header: 'Severity',
      width: '100px',
      render: (row: DriftEvent) => (
        <span className={`text-[11px] px-2 py-0.5 rounded border ${SEVERITY_BADGES[row.severity] || 'bg-slate-100 text-slate-700'}`}>
          {row.severity}
        </span>
      ),
    },
    {
      key: 'entity_id',
      header: 'Entity Impacted',
      width: '160px',
      render: (row: DriftEvent) => (
        <span className="font-mono text-xs text-blue-700 bg-blue-50 px-2 py-0.5 rounded border border-blue-200">
          {row.entity_id}
        </span>
      ),
    },
    {
      key: 'review_required',
      header: 'Triage Status',
      width: '120px',
      render: (row: DriftEvent) => (
        <span className={`text-[11px] font-medium px-2 py-0.5 rounded border ${
          row.review_required ? 'bg-amber-50 text-amber-800 border-amber-200' : 'bg-slate-50 text-slate-600 border-slate-200'
        }`}>
          {row.review_required ? 'Review Pending' : 'Resolved'}
        </span>
      ),
    },
    {
      key: 'detected_at',
      header: 'Detected',
      width: '130px',
      render: (row: DriftEvent) => (
        <span className="text-xs text-slate-500">{new Date(row.detected_at).toLocaleTimeString()}</span>
      ),
    },
  ];

  return (
    <div className="p-8 space-y-6 max-w-7xl mx-auto">
      <PageHeader
        title="Behavioral Drift & Anomalies"
        subtitle="Real-time statistical and deterministic drift detection against verified agent baseline models"
        badge="Anomaly Engine"
        actions={
          <button
            onClick={fetchDrift}
            disabled={loading}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-white border border-slate-200 rounded-md text-xs font-medium text-slate-700 hover:bg-slate-50 transition-colors shadow-2xs"
          >
            <RefreshCw size={13} className={loading ? 'animate-spin' : ''} />
            <span>Refresh</span>
          </button>
        }
      />

      {/* KPI Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <MetricCard label="Total Drift Events" value={events.length} />
        <MetricCard label="Context Drifts" value={events.filter(e => e.category === 'CONTEXT_DRIFT').length} status="BLOCK" />
        <MetricCard label="Authority Expansions" value={events.filter(e => e.category === 'AUTHORITY_DRIFT').length} status="HITL" />
        <MetricCard label="Access Path Drifts" value={events.filter(e => e.category === 'ACCESS_DRIFT').length} status="ALLOW" />
      </div>

      {/* Filter and Table */}
      <div className="bg-white border border-slate-200 rounded-lg p-5 shadow-xs space-y-4">
        <FilterBar
          searchQuery={search}
          onSearchChange={setSearch}
          searchPlaceholder="Search drift events by title, entity, or description..."
          filters={[
            {
              key: 'category',
              label: 'Category',
              options: [
                { label: 'All Categories', value: 'ALL' },
                { label: 'Context Drift', value: 'CONTEXT_DRIFT' },
                { label: 'Authority Drift', value: 'AUTHORITY_DRIFT' },
                { label: 'Access Drift', value: 'ACCESS_DRIFT' },
              ],
              value: categoryFilter,
              onChange: setCategoryFilter,
            },
            {
              key: 'severity',
              label: 'Severity',
              options: [
                { label: 'All Severities', value: 'ALL' },
                { label: 'High / Critical', value: 'HIGH' },
                { label: 'Medium', value: 'MEDIUM' },
                { label: 'Low', value: 'LOW' },
              ],
              value: severityFilter,
              onChange: setSeverityFilter,
            },
          ]}
          activeCount={categoryFilter !== 'ALL' || severityFilter !== 'ALL' || search ? 1 : 0}
          onReset={() => {
            setSearch('');
            setCategoryFilter('ALL');
            setSeverityFilter('ALL');
          }}
        />

        <DataTable
          columns={columns}
          data={filtered}
          keyField="drift_id"
          onRowClick={(row) => setSelectedDrift(row)}
          emptyMessage="No drift anomalies matched your filter criteria."
        />
      </div>

      {/* Detail Drawer */}
      <DetailDrawer
        isOpen={!!selectedDrift}
        onClose={() => setSelectedDrift(null)}
        title={selectedDrift ? selectedDrift.title : ''}
        subtitle={selectedDrift ? `ID: ${selectedDrift.drift_id} • Entity: ${selectedDrift.entity_id}` : ''}
        badge={selectedDrift ? (
          <span className={`text-xs px-2 py-0.5 rounded border ${SEVERITY_BADGES[selectedDrift.severity]}`}>
            {selectedDrift.severity}
          </span>
        ) : null}
      >
        {selectedDrift && (
          <div className="space-y-6">
            {/* Description */}
            <div className="bg-slate-50 border border-slate-200 rounded-lg p-3.5 space-y-2">
              <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">Event Description</div>
              <p className="text-xs text-slate-800 leading-relaxed">{selectedDrift.description}</p>
            </div>

            {/* State Transition Diff */}
            <div>
              <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-500 mb-2">State Transition Diff</div>
              <div className="grid grid-cols-2 gap-3">
                <div className="p-3 bg-red-50/60 border border-red-200 rounded-lg">
                  <div className="text-[10px] uppercase font-semibold text-red-700 mb-1">Baseline / Before</div>
                  <pre className="text-xs font-mono text-red-900 overflow-x-auto whitespace-pre-wrap">
                    {JSON.stringify(selectedDrift.before_state, null, 2)}
                  </pre>
                </div>
                <div className="p-3 bg-emerald-50/60 border border-emerald-200 rounded-lg">
                  <div className="text-[10px] uppercase font-semibold text-emerald-700 mb-1">Observed / After</div>
                  <pre className="text-xs font-mono text-emerald-900 overflow-x-auto whitespace-pre-wrap">
                    {JSON.stringify(selectedDrift.after_state, null, 2)}
                  </pre>
                </div>
              </div>
            </div>

            {/* Security Implication */}
            <div>
              <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-500 mb-2">Security Implication</div>
              <div className="p-3.5 bg-amber-50/80 border border-amber-200 rounded-lg text-xs text-amber-900 leading-relaxed">
                <span className="font-semibold block mb-1">Threat Model Impact:</span>
                {selectedDrift.security_implication}
              </div>
            </div>

            {/* Metadata & Evidence */}
            <div className="border-t border-slate-200 pt-4 space-y-2 text-xs text-slate-600">
              <div className="flex justify-between">
                <span className="text-slate-500">Detected At</span>
                <span className="font-mono">{new Date(selectedDrift.detected_at).toUTCString()}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-500">Triage Requirement</span>
                <span className="font-medium text-slate-800">{selectedDrift.review_required ? 'HITL Review Required' : 'Informational Only'}</span>
              </div>
            </div>
          </div>
        )}
      </DetailDrawer>
    </div>
  );
}
