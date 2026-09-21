'use client';

import { useState } from 'react';
import { Code, Play, Copy, CheckCircle2, Terminal, Globe, BookOpen } from 'lucide-react';
import { PageHeader } from '@/components/ui/PageHeader';
import { FilterBar } from '@/components/ui/FilterBar';
import { DataTable } from '@/components/ui/DataTable';

const API_ENDPOINTS = [
  {
    method: 'GET',
    path: '/api/v1/agents',
    description: 'List all registered agents with identity, trust level, and capability set',
    category: 'Agents',
  },
  {
    method: 'GET',
    path: '/api/v1/agents/{agent_id}',
    description: 'Get agent profile, current capabilities, and delegation chain',
    category: 'Agents',
  },
  {
    method: 'GET',
    path: '/api/v1/events',
    description: 'Stream security decision events with filtering by decision, agent, time range',
    category: 'Events',
  },
  {
    method: 'POST',
    path: '/api/v1/policy/evaluate',
    description: 'Evaluate a proposed action against the deterministic policy engine without executing',
    category: 'Policy',
  },
  {
    method: 'GET',
    path: '/api/v1/forensics/{event_id}',
    description: 'Full forensic evidence record and causal explanation for a specific event',
    category: 'Forensics',
  },
  {
    method: 'GET',
    path: '/api/v1/traces/{trace_id}',
    description: 'Causal execution trace with span-level decision evidence',
    category: 'Traces',
  },
  {
    method: 'GET',
    path: '/api/v1/campaigns',
    description: 'List all offensive validation campaigns with empirical prevention metrics',
    category: 'Offensive',
  },
  {
    method: 'POST',
    path: '/api/v1/attack/run',
    description: 'Trigger a new adaptive attack campaign (safe, local sandbox targets only)',
    category: 'Offensive',
  },
  {
    method: 'GET',
    path: '/api/v1/posture',
    description: '6-dimension security posture scorecard JSON for monitoring systems',
    category: 'Posture',
  },
];

const METHOD_BADGES: Record<string, string> = {
  GET: 'bg-emerald-50 text-emerald-700 border-emerald-200 font-bold',
  POST: 'bg-blue-50 text-blue-700 border-blue-200 font-bold',
  PUT: 'bg-amber-50 text-amber-700 border-amber-200 font-bold',
  DELETE: 'bg-red-50 text-red-700 border-red-200 font-bold',
};

const DEMO_RESPONSES: Record<string, string> = {
  '/api/v1/agents': JSON.stringify({
    agents: [
      { agent_id: 'orchestrator_v2', trust_level: 'HIGH', capabilities: ['read_db', 'delegate', 'generate_summary'], status: 'ACTIVE' },
      { agent_id: 'data_agent', trust_level: 'MEDIUM', capabilities: ['read_db', 'query_customers'], status: 'ACTIVE' },
    ],
    total: 5,
  }, null, 2),
  '/api/v1/events': JSON.stringify({
    events: [
      { event_id: 'evt_001', decision: 'BLOCK', tool: 'upload_s3', agent_id: 'escalation_agent', timestamp: '2026-09-19T10:30:00Z' },
      { event_id: 'evt_002', decision: 'ALLOW', tool: 'read_file', agent_id: 'analyst_agent', timestamp: '2026-09-19T08:02:00Z' },
    ],
    total: 47,
  }, null, 2),
  default: JSON.stringify({ status: 'ok', message: 'Select an endpoint from the left to inspect documentation and live schema payload.' }, null, 2),
};

export default function ApiPage() {
  const [selectedEndpoint, setSelectedEndpoint] = useState<typeof API_ENDPOINTS[0]>(API_ENDPOINTS[0]);
  const [copied, setCopied] = useState(false);
  const [categoryFilter, setCategoryFilter] = useState('ALL');
  const [search, setSearch] = useState('');

  const responseJson = selectedEndpoint ? (DEMO_RESPONSES[selectedEndpoint.path] || DEMO_RESPONSES.default) : DEMO_RESPONSES.default;

  const handleCopy = () => {
    navigator.clipboard.writeText(responseJson);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const filtered = API_ENDPOINTS.filter(e => {
    const matchSearch =
      e.path.toLowerCase().includes(search.toLowerCase()) ||
      e.description.toLowerCase().includes(search.toLowerCase());

    const matchCategory = categoryFilter === 'ALL' || e.category === categoryFilter;

    return matchSearch && matchCategory;
  });

  return (
    <div className="p-8 space-y-6 max-w-7xl mx-auto">
      <PageHeader
        title="REST API Reference"
        subtitle="Complete HTTP API specification for ActShield SDK integration, telemetry streaming, and automated policy verification"
        badge="API Documentation"
        actions={
          <div className="flex items-center gap-2 text-xs font-mono text-slate-500">
            <Globe size={13} />
            <span>Base URL: http://127.0.0.1:8000</span>
          </div>
        }
      />

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Endpoints List */}
        <div className="lg:col-span-6 bg-white border border-slate-200 rounded-lg p-5 shadow-xs space-y-4">
          <FilterBar
            searchQuery={search}
            onSearchChange={setSearch}
            searchPlaceholder="Search endpoints..."
            filters={[
              {
                key: 'category',
                label: 'Category',
                options: [
                  { label: 'All Categories', value: 'ALL' },
                  { label: 'Agents', value: 'Agents' },
                  { label: 'Events', value: 'Events' },
                  { label: 'Policy', value: 'Policy' },
                  { label: 'Forensics', value: 'Forensics' },
                  { label: 'Traces', value: 'Traces' },
                  { label: 'Offensive', value: 'Offensive' },
                  { label: 'Posture', value: 'Posture' },
                ],
                value: categoryFilter,
                onChange: setCategoryFilter,
              },
            ]}
            activeCount={categoryFilter !== 'ALL' || search ? 1 : 0}
            onReset={() => {
              setSearch('');
              setCategoryFilter('ALL');
            }}
          />

          <div className="space-y-2">
            {filtered.map(endpoint => (
              <button
                key={endpoint.path}
                onClick={() => setSelectedEndpoint(endpoint)}
                className={`w-full text-left p-3 rounded-lg border text-xs transition-colors ${
                  selectedEndpoint?.path === endpoint.path
                    ? 'border-blue-600 bg-blue-50/50 shadow-2xs'
                    : 'border-slate-200 bg-white hover:bg-slate-50'
                }`}
              >
                <div className="flex items-center gap-2 mb-1">
                  <span className={`text-[10px] px-1.5 py-0.2 rounded border font-mono ${METHOD_BADGES[endpoint.method]}`}>
                    {endpoint.method}
                  </span>
                  <span className="font-mono font-semibold text-slate-900">{endpoint.path}</span>
                </div>
                <p className="text-slate-500 text-[11px] leading-relaxed">{endpoint.description}</p>
              </button>
            ))}
          </div>
        </div>

        {/* Response Preview Panel */}
        <div className="lg:col-span-6 bg-white border border-slate-200 rounded-lg p-5 shadow-xs flex flex-col">
          <div className="flex items-center justify-between pb-3 border-b border-slate-200 mb-4">
            <div className="flex items-center gap-2">
              <Code size={14} className="text-slate-500" />
              <span className="text-xs font-semibold uppercase tracking-wider text-slate-700">Schema & Response Payload</span>
            </div>
            <button
              onClick={handleCopy}
              className="flex items-center gap-1.5 text-xs text-slate-600 hover:text-slate-900 px-2.5 py-1 rounded bg-slate-100 hover:bg-slate-200 transition-colors"
            >
              {copied ? <CheckCircle2 size={13} className="text-emerald-600" /> : <Copy size={13} />}
              <span>{copied ? 'Copied' : 'Copy JSON'}</span>
            </button>
          </div>

          {selectedEndpoint && (
            <div className="mb-3 space-y-1">
              <div className="flex items-center gap-2">
                <span className={`text-[10px] px-1.5 py-0.2 rounded border font-mono ${METHOD_BADGES[selectedEndpoint.method]}`}>
                  {selectedEndpoint.method}
                </span>
                <span className="font-mono text-xs font-bold text-slate-900">{selectedEndpoint.path}</span>
              </div>
              <p className="text-xs text-slate-600">{selectedEndpoint.description}</p>
            </div>
          )}

          <div className="flex-1 bg-slate-900 text-slate-100 rounded-lg p-4 font-mono text-xs overflow-auto border border-slate-800 max-h-[420px]">
            <pre className="text-slate-200 leading-relaxed">{responseJson}</pre>
          </div>
        </div>
      </div>
    </div>
  );
}
