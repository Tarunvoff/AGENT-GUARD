'use client';

import { useState } from 'react';
import { Brain, Shield, AlertTriangle, CheckCircle2, Zap, Activity, Info, BarChart2 } from 'lucide-react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, RadarChart, PolarGrid, PolarAngleAxis, Radar } from 'recharts';
import { PageHeader } from '@/components/ui/PageHeader';
import { MetricCard } from '@/components/ui/MetricCard';
import { StatusBadge } from '@/components/ui/StatusBadge';
import { FilterBar } from '@/components/ui/FilterBar';
import { DataTable } from '@/components/ui/DataTable';
import { DetailDrawer } from '@/components/ui/DetailDrawer';

const THREAT_TIMELINE = [
  { time: '08:00', threat: 0.12, confidence: 0.95 },
  { time: '09:00', threat: 0.31, confidence: 0.87 },
  { time: '09:11', threat: 0.89, confidence: 0.92 },
  { time: '09:30', threat: 0.45, confidence: 0.88 },
  { time: '10:00', threat: 0.21, confidence: 0.94 },
  { time: '10:30', threat: 0.82, confidence: 0.91 },
  { time: '10:45', threat: 0.97, confidence: 0.96 },
  { time: '11:00', threat: 0.18, confidence: 0.97 },
];

const THREAT_DIMENSIONS = [
  { dimension: 'Prompt Inj.', score: 87 },
  { dimension: 'Data Exfil', score: 73 },
  { dimension: 'Auth Esc.', score: 91 },
  { dimension: 'Tool Poison', score: 65 },
  { dimension: 'Taint Leak', score: 78 },
  { dimension: 'Intent Drift', score: 84 },
];

interface AiAnalysis {
  id: string;
  event_id: string;
  timestamp: string;
  intent_aligned: boolean;
  threat_severity: number;
  threat_category: string | null;
  confidence: number;
  reasoning: string;
  policy_overridden: boolean;
  final_decision: 'BLOCK' | 'HITL' | 'ALLOW';
}

const RECENT_AI_ANALYSES: AiAnalysis[] = [
  {
    id: 'ai_001',
    event_id: 'evt_pinj_001',
    timestamp: '2026-09-19T10:45:00Z',
    intent_aligned: false,
    threat_severity: 0.97,
    threat_category: 'prompt_injection',
    confidence: 0.96,
    reasoning: 'Detected adversarial instruction in MCP tool response. Original task intent (financial analysis) diverged from detected action intent (data exfiltration). High confidence manipulation pattern.',
    policy_overridden: false,
    final_decision: 'BLOCK',
  },
  {
    id: 'ai_002',
    event_id: 'evt_auth_001',
    timestamp: '2026-09-19T10:30:00Z',
    intent_aligned: false,
    threat_severity: 0.82,
    threat_category: 'authority_escalation',
    confidence: 0.91,
    reasoning: 'Agent requested capabilities significantly exceeding delegated authority scope. Pattern consistent with privilege escalation attempt. Delegation graph analysis confirms violation.',
    policy_overridden: false,
    final_decision: 'BLOCK',
  },
  {
    id: 'ai_003',
    event_id: 'evt_q3_001',
    timestamp: '2026-09-19T08:05:00Z',
    intent_aligned: true,
    threat_severity: 0.08,
    threat_category: null,
    confidence: 0.98,
    reasoning: 'Task intent (Q3 financial analysis) aligns with all tool calls made. No taint propagation detected. Authority within delegated bounds.',
    policy_overridden: false,
    final_decision: 'ALLOW',
  },
];

export default function AiSecuraPage() {
  const [search, setSearch] = useState('');
  const [selectedAnalysis, setSelectedAnalysis] = useState<AiAnalysis | null>(null);

  const filtered = RECENT_AI_ANALYSES.filter(a =>
    a.id.toLowerCase().includes(search.toLowerCase()) ||
    a.event_id.toLowerCase().includes(search.toLowerCase()) ||
    a.reasoning.toLowerCase().includes(search.toLowerCase()) ||
    (a.threat_category && a.threat_category.toLowerCase().includes(search.toLowerCase()))
  );

  const columns = [
    {
      key: 'id',
      header: 'Analysis ID',
      render: (row: AiAnalysis) => (
        <div className="flex items-center gap-2">
          <div className="w-6 h-6 rounded bg-purple-50 flex items-center justify-center text-purple-700 border border-purple-200">
            <Brain size={12} />
          </div>
          <div>
            <div className="font-mono text-xs font-semibold text-slate-900">{row.id}</div>
            <div className="font-mono text-[10px] text-slate-500">{row.event_id}</div>
          </div>
        </div>
      ),
    },
    {
      key: 'threat_category',
      header: 'Threat Category',
      render: (row: AiAnalysis) => (
        <span className="text-xs font-mono text-slate-700 capitalize">
          {row.threat_category ? row.threat_category.replace(/_/g, ' ') : 'None (Benign)'}
        </span>
      ),
    },
    {
      key: 'threat_severity',
      header: 'Threat Index',
      width: '120px',
      render: (row: AiAnalysis) => (
        <div className="flex items-center gap-2">
          <div className="w-10 bg-slate-100 rounded-full h-1.5 overflow-hidden">
            <div
              className={`h-full ${row.threat_severity > 0.7 ? 'bg-red-500' : 'bg-emerald-500'}`}
              style={{ width: `${row.threat_severity * 100}%` }}
            />
          </div>
          <span className="font-mono text-xs text-slate-700">{row.threat_severity.toFixed(2)}</span>
        </div>
      ),
    },
    {
      key: 'confidence',
      header: 'Confidence',
      width: '100px',
      render: (row: AiAnalysis) => (
        <span className="font-mono text-xs text-slate-600">{`${(row.confidence * 100).toFixed(0)}%`}</span>
      ),
    },
    {
      key: 'final_decision',
      header: 'Policy Verdict',
      width: '120px',
      render: (row: AiAnalysis) => (
        <StatusBadge status={row.final_decision} />
      ),
    },
  ];

  return (
    <div className="p-8 space-y-6 max-w-7xl mx-auto">
      <PageHeader
        title="AI Secura Reasoning"
        subtitle="Advisory semantic intent alignment and threat analysis. Deterministic policy maintains absolute enforcement authority"
        badge="Semantic Engine"
        actions={
          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-purple-50 border border-purple-200 text-xs text-purple-800 font-medium">
            <Activity size={13} className="text-purple-600" />
            <span>Local Reasoning Model Active</span>
          </div>
        }
      />

      {/* Principle Callout */}
      <div className="bg-amber-50/70 border border-amber-200 rounded-lg p-3.5 flex items-start gap-3">
        <AlertTriangle size={16} className="text-amber-600 mt-0.5 flex-shrink-0" />
        <div className="text-xs text-amber-900 leading-relaxed">
          <span className="font-semibold">Architectural Invariant (AI Reasons, Policy Enforces):</span> AI Secura provides intent alignment signals, threat categorization, and anomaly scoring. All enforcement decisions are executed exclusively by the deterministic PolicyEvaluator. AI outputs can never override deterministic block rules.
        </div>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <MetricCard label="Analyses (24h)" value={47} />
        <MetricCard label="High Threat Alerts" value={3} status="BLOCK" />
        <MetricCard label="Mean Confidence" value="94.2%" status="ALLOW" />
        <MetricCard label="Policy Overrides" value="0 (Zero AI Override)" status="ALLOW" />
      </div>

      {/* Visual Analytics Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-white border border-slate-200 rounded-lg p-5 shadow-xs space-y-4">
          <div className="text-xs font-semibold uppercase tracking-wider text-slate-500">Threat Severity Timeline</div>
          <div className="h-56">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={THREAT_TIMELINE} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#f1f5f9" vertical={false} />
                <XAxis dataKey="time" stroke="#94a3b8" fontSize={11} />
                <YAxis stroke="#94a3b8" fontSize={11} />
                <Tooltip contentStyle={{ backgroundColor: '#ffffff', borderColor: '#e2e8f0', borderRadius: '6px', fontSize: '11px' }} />
                <Area type="monotone" dataKey="threat" stroke="#dc2626" fill="#fee2e2" name="Threat Score" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="bg-white border border-slate-200 rounded-lg p-5 shadow-xs space-y-4">
          <div className="text-xs font-semibold uppercase tracking-wider text-slate-500">Threat Dimension Coverage</div>
          <div className="h-56">
            <ResponsiveContainer width="100%" height="100%">
              <RadarChart data={THREAT_DIMENSIONS} margin={{ top: 10, right: 20, left: 20, bottom: 10 }}>
                <PolarGrid stroke="#e2e8f0" />
                <PolarAngleAxis dataKey="dimension" stroke="#64748b" fontSize={10} />
                <Radar name="Severity Index" dataKey="score" stroke="#8b5cf6" fill="#c4b5fd" fillOpacity={0.3} />
              </RadarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Analyses Table */}
      <div className="bg-white border border-slate-200 rounded-lg p-5 shadow-xs space-y-4">
        <FilterBar
          searchQuery={search}
          onSearchChange={setSearch}
          searchPlaceholder="Search AI reasoning traces..."
        />

        <DataTable
          columns={columns}
          data={filtered}
          keyField="id"
          onRowClick={(row) => setSelectedAnalysis(row)}
          emptyMessage="No AI analysis records matched your filter."
        />
      </div>

      {/* Detail Drawer */}
      <DetailDrawer
        isOpen={!!selectedAnalysis}
        onClose={() => setSelectedAnalysis(null)}
        title={selectedAnalysis ? `Analysis: ${selectedAnalysis.id}` : ''}
        subtitle={selectedAnalysis ? `Event Ref: ${selectedAnalysis.event_id}` : ''}
        badge={selectedAnalysis ? <StatusBadge status={selectedAnalysis.final_decision} /> : null}
      >
        {selectedAnalysis && (
          <div className="space-y-6">
            <div className="p-3.5 bg-slate-50 border border-slate-200 rounded-lg space-y-1.5">
              <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">Semantic Reasoning Output</div>
              <p className="text-xs text-slate-800 leading-relaxed">{selectedAnalysis.reasoning}</p>
            </div>

            <div className="grid grid-cols-2 gap-3 text-xs">
              <div className="p-3 bg-white border border-slate-200 rounded-lg">
                <span className="text-slate-500 block mb-1">Threat Category</span>
                <span className="font-mono font-semibold text-slate-800 capitalize">
                  {selectedAnalysis.threat_category || 'None'}
                </span>
              </div>
              <div className="p-3 bg-white border border-slate-200 rounded-lg">
                <span className="text-slate-500 block mb-1">Intent Alignment</span>
                <span className={`font-semibold ${selectedAnalysis.intent_aligned ? 'text-emerald-700' : 'text-red-700'}`}>
                  {selectedAnalysis.intent_aligned ? 'Aligned with Goal' : 'Intent Divergence Detected'}
                </span>
              </div>
            </div>
          </div>
        )}
      </DetailDrawer>
    </div>
  );
}
