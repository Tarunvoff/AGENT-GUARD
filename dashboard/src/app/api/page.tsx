'use client';

import { useState } from 'react';
import { Code, Play, Copy, CheckCircle2, ChevronDown } from 'lucide-react';

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
    description: 'Evaluate a proposed action against the policy engine without executing',
    category: 'Policy',
  },
  {
    method: 'GET',
    path: '/api/v1/forensics/{event_id}',
    description: 'Full forensic evidence record for a specific event',
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
    description: 'Trigger a new adaptive attack campaign (safe, local targets only)',
    category: 'Offensive',
  },
  {
    method: 'GET',
    path: '/api/v1/dashboard/scorecard',
    description: 'Dashboard-ready security scorecard JSON for frontend consumption',
    category: 'Reports',
  },
];

const METHOD_STYLES: Record<string, string> = {
  GET: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20',
  POST: 'text-sky-400 bg-sky-500/10 border-sky-500/20',
  PUT: 'text-amber-400 bg-amber-500/10 border-amber-500/20',
  DELETE: 'text-red-400 bg-red-500/10 border-red-500/20',
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
  default: JSON.stringify({ status: 'ok', message: 'Select an endpoint to see example response' }, null, 2),
};

export default function ApiPage() {
  const [selectedEndpoint, setSelectedEndpoint] = useState<typeof API_ENDPOINTS[0] | null>(null);
  const [copied, setCopied] = useState(false);
  const [categoryFilter, setCategoryFilter] = useState('all');

  const categories = ['all', ...Array.from(new Set(API_ENDPOINTS.map(e => e.category)))];
  const filtered = categoryFilter === 'all' ? API_ENDPOINTS : API_ENDPOINTS.filter(e => e.category === categoryFilter);
  const responseJson = selectedEndpoint ? (DEMO_RESPONSES[selectedEndpoint.path] || DEMO_RESPONSES.default) : DEMO_RESPONSES.default;

  const handleCopy = () => {
    navigator.clipboard.writeText(responseJson);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  return (
    <div className="p-6 space-y-5 min-h-screen bg-[#090d16]">
      <div>
        <h1 className="text-xl font-bold text-white flex items-center gap-2">
          <Code size={18} className="text-sky-400" />
          API Console
        </h1>
        <p className="text-sm text-zinc-500 mt-1">
          AgentGuard REST API — base URL: <span className="font-mono text-zinc-300">http://localhost:8080</span>
        </p>
      </div>

      {/* Category filter */}
      <div className="flex gap-2 flex-wrap">
        {categories.map(c => (
          <button key={c} onClick={() => setCategoryFilter(c)}
            className={`px-2.5 py-1 text-[11px] rounded font-medium transition-colors ${
              categoryFilter === c ? 'bg-sky-500/15 border border-sky-500/30 text-sky-300' : 'text-zinc-500 hover:text-zinc-300'
            }`}>
            {c}
          </button>
        ))}
      </div>

      <div className="grid grid-cols-2 gap-4">
        {/* Endpoint List */}
        <div className="space-y-2">
          {filtered.map(ep => (
            <div
              key={ep.path}
              onClick={() => setSelectedEndpoint(ep)}
              className={`rounded-xl border p-3 cursor-pointer transition-all ${
                selectedEndpoint?.path === ep.path
                  ? 'border-sky-500/40 bg-sky-500/5'
                  : 'border-zinc-800/50 bg-zinc-900/30 hover:border-zinc-700/50'
              }`}
            >
              <div className="flex items-center gap-2 mb-1">
                <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded border ${METHOD_STYLES[ep.method] || ''}`}>{ep.method}</span>
                <span className="font-mono text-xs text-zinc-300">{ep.path}</span>
              </div>
              <p className="text-[11px] text-zinc-500">{ep.description}</p>
            </div>
          ))}
        </div>

        {/* Response Panel */}
        <div className="rounded-xl border border-zinc-800/50 bg-zinc-900/30 flex flex-col">
          <div className="flex items-center justify-between px-4 py-3 border-b border-zinc-800/50">
            <div className="text-[10px] uppercase tracking-wider text-zinc-500">Response</div>
            <button onClick={handleCopy} className="flex items-center gap-1 text-[11px] text-zinc-500 hover:text-zinc-300 transition-colors">
              {copied ? <CheckCircle2 size={11} className="text-emerald-400" /> : <Copy size={11} />}
              {copied ? 'Copied' : 'Copy'}
            </button>
          </div>
          <pre className="flex-1 p-4 font-mono text-[11px] text-emerald-300 overflow-auto">
            {responseJson}
          </pre>
          {selectedEndpoint && (
            <div className="px-4 py-3 border-t border-zinc-800/50 flex items-center gap-2">
              <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded border ${METHOD_STYLES[selectedEndpoint.method] || ''}`}>{selectedEndpoint.method}</span>
              <span className="font-mono text-[11px] text-zinc-400">{selectedEndpoint.path}</span>
              <div className="flex-1" />
              <span className="text-[10px] text-emerald-400">200 OK</span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
