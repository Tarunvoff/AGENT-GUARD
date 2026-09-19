'use client';

import { useState } from 'react';
import { Wrench, Shield, AlertTriangle, CheckCircle2, XCircle, Zap, Globe, Code, Search } from 'lucide-react';
import { DecisionBadge, SensitivityBadge } from '@/components/ui/security';

const DEMO_TOOLS = [
  {
    tool_id: 'tool_read_db',
    name: 'read_db',
    protocol: 'MCP',
    server: 'internal-mcp-server',
    risk_level: 'HIGH',
    allowed_agents: ['orchestrator_v2', 'data_agent'],
    blocked_agents: ['escalation_agent', 'external_caller'],
    calls_24h: 47,
    blocked_calls_24h: 3,
    last_used: '2026-09-19T09:12:00Z',
    apiris_score: 0.72,
    description: 'Read from internal database tables',
  },
  {
    tool_id: 'tool_upload_s3',
    name: 'upload_s3',
    protocol: 'HTTP',
    server: 'aws-s3-gateway',
    risk_level: 'CRITICAL',
    allowed_agents: [],
    blocked_agents: ['all'],
    calls_24h: 0,
    blocked_calls_24h: 2,
    last_used: null,
    apiris_score: 0.95,
    description: 'Upload data to external S3 buckets — egress control required',
  },
  {
    tool_id: 'tool_send_email',
    name: 'send_email',
    protocol: 'HTTP',
    server: 'email-api-gateway',
    risk_level: 'CRITICAL',
    allowed_agents: [],
    blocked_agents: ['all'],
    calls_24h: 0,
    blocked_calls_24h: 1,
    last_used: null,
    apiris_score: 0.91,
    description: 'Send email via external API — data exfiltration risk',
  },
  {
    tool_id: 'tool_read_file',
    name: 'read_file',
    protocol: 'LOCAL',
    server: 'local-fs',
    risk_level: 'MEDIUM',
    allowed_agents: ['orchestrator_v2', 'analyst_agent'],
    blocked_agents: ['data_agent', 'escalation_agent'],
    calls_24h: 12,
    blocked_calls_24h: 0,
    last_used: '2026-09-19T08:02:00Z',
    apiris_score: 0.38,
    description: 'Read local files within allowed paths',
  },
  {
    tool_id: 'tool_generate_summary',
    name: 'generate_summary',
    protocol: 'LOCAL',
    server: 'internal-llm',
    risk_level: 'LOW',
    allowed_agents: ['orchestrator_v2', 'analyst_agent', 'report_agent'],
    blocked_agents: [],
    calls_24h: 34,
    blocked_calls_24h: 0,
    last_used: '2026-09-19T11:05:00Z',
    apiris_score: 0.12,
    description: 'LLM summarization — read-only, no external egress',
  },
  {
    tool_id: 'tool_external_mcp',
    name: 'external_mcp_tool',
    protocol: 'MCP',
    server: 'untrusted-external-mcp',
    risk_level: 'CRITICAL',
    allowed_agents: [],
    blocked_agents: ['all'],
    calls_24h: 0,
    blocked_calls_24h: 1,
    last_used: null,
    apiris_score: 0.98,
    description: 'Untrusted external MCP server — prompt injection source detected',
    flags: ['PROMPT_INJECTION_SOURCE', 'UNTRUSTED_SERVER'],
  },
];

const RISK_STYLES: Record<string, string> = {
  CRITICAL: 'text-red-400 border-red-500/30 bg-red-500/10',
  HIGH: 'text-orange-400 border-orange-500/30 bg-orange-500/10',
  MEDIUM: 'text-amber-400 border-amber-500/20 bg-amber-500/10',
  LOW: 'text-emerald-400 border-emerald-500/20 bg-emerald-500/10',
};

const PROTOCOL_ICONS: Record<string, React.ElementType> = {
  MCP: Zap,
  HTTP: Globe,
  LOCAL: Code,
};

function ApirisScoreBar({ score }: { score: number }) {
  const color = score > 0.8 ? 'bg-red-500' : score > 0.5 ? 'bg-amber-500' : score > 0.3 ? 'bg-yellow-500' : 'bg-emerald-500';
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-1.5 bg-zinc-800 rounded-full overflow-hidden">
        <div className={`h-full rounded-full ${color}`} style={{ width: `${score * 100}%` }} />
      </div>
      <span className={`text-[10px] font-mono font-bold ${score > 0.8 ? 'text-red-400' : score > 0.5 ? 'text-amber-400' : 'text-emerald-400'}`}>
        {score.toFixed(2)}
      </span>
    </div>
  );
}

export default function ToolsPage() {
  const [search, setSearch] = useState('');
  const [riskFilter, setRiskFilter] = useState('all');

  const filtered = DEMO_TOOLS.filter(t => {
    const matchSearch = t.name.includes(search) || t.description.toLowerCase().includes(search.toLowerCase());
    const matchRisk = riskFilter === 'all' || t.risk_level === riskFilter;
    return matchSearch && matchRisk;
  });

  return (
    <div className="p-6 space-y-5 min-h-screen bg-[#090d16]">
      <div>
        <h1 className="text-xl font-bold text-white flex items-center gap-2">
          <Wrench size={18} className="text-orange-400" />
          Tool / MCP Security
        </h1>
        <p className="text-sm text-zinc-500 mt-1">
          All tools and MCP servers with APIRIS risk scores, agent permissions, and access history
        </p>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-4 gap-3">
        <div className="rounded-xl border border-zinc-700/30 bg-zinc-800/40 p-3 text-center">
          <div className="text-[10px] text-zinc-500 uppercase tracking-wider mb-1">Tools Registered</div>
          <div className="text-xl font-bold font-mono text-zinc-200">{DEMO_TOOLS.length}</div>
        </div>
        <div className="rounded-xl border border-red-500/20 bg-red-500/5 p-3 text-center">
          <div className="text-[10px] text-zinc-500 uppercase tracking-wider mb-1">Critical Risk</div>
          <div className="text-xl font-bold font-mono text-red-400">{DEMO_TOOLS.filter(t => t.risk_level === 'CRITICAL').length}</div>
        </div>
        <div className="rounded-xl border border-red-500/20 bg-red-500/5 p-3 text-center">
          <div className="text-[10px] text-zinc-500 uppercase tracking-wider mb-1">Blocked Calls (24h)</div>
          <div className="text-xl font-bold font-mono text-red-400">{DEMO_TOOLS.reduce((s, t) => s + t.blocked_calls_24h, 0)}</div>
        </div>
        <div className="rounded-xl border border-sky-500/20 bg-sky-500/5 p-3 text-center">
          <div className="text-[10px] text-zinc-500 uppercase tracking-wider mb-1">Total Calls (24h)</div>
          <div className="text-xl font-bold font-mono text-sky-400">{DEMO_TOOLS.reduce((s, t) => s + t.calls_24h, 0)}</div>
        </div>
      </div>

      {/* Search + Filter */}
      <div className="flex gap-3 items-center">
        <div className="relative flex-1 max-w-xs">
          <Search size={13} className="absolute left-3 top-1/2 -translate-y-1/2 text-zinc-500" />
          <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search tools..."
            className="w-full pl-8 pr-3 py-2 bg-zinc-800/60 border border-zinc-700/50 rounded-lg text-sm text-zinc-200 placeholder:text-zinc-600 focus:outline-none focus:border-sky-500/50"
          />
        </div>
        {['all', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(f => (
          <button key={f} onClick={() => setRiskFilter(f)}
            className={`px-2.5 py-1 text-[11px] rounded font-medium uppercase tracking-wider transition-colors ${
              riskFilter === f ? 'bg-sky-500/15 border border-sky-500/30 text-sky-300' : 'text-zinc-500 hover:text-zinc-300'
            }`}>
            {f}
          </button>
        ))}
      </div>

      {/* Tool Cards */}
      <div className="space-y-3">
        {filtered.map(tool => {
          const ProtoIcon = PROTOCOL_ICONS[tool.protocol] || Wrench;
          const riskStyle = RISK_STYLES[tool.risk_level] || '';
          return (
            <div key={tool.tool_id} className={`rounded-xl border p-4 ${tool.flags?.length ? 'border-red-500/40 bg-red-500/5' : 'border-zinc-800/50 bg-zinc-900/30'}`}>
              <div className="flex items-start gap-3">
                <ProtoIcon size={16} className="text-zinc-400 mt-0.5 flex-shrink-0" />
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1 flex-wrap">
                    <span className="font-mono text-sm text-zinc-100">{tool.name}</span>
                    <span className={`text-[10px] font-semibold px-1.5 py-0.5 rounded border ${riskStyle}`}>{tool.risk_level}</span>
                    <span className="text-[10px] text-zinc-500 bg-zinc-800/60 px-1.5 py-0.5 rounded">{tool.protocol}</span>
                    <span className="text-[10px] text-zinc-600 font-mono">{tool.server}</span>
                    {tool.flags?.map(f => (
                      <span key={f} className="text-[10px] font-semibold px-1.5 py-0.5 rounded border text-red-400 border-red-500/20 bg-red-500/10">{f}</span>
                    ))}
                  </div>
                  <p className="text-xs text-zinc-500 mb-2">{tool.description}</p>

                  {/* APIRIS score */}
                  <div className="mb-2">
                    <div className="text-[10px] text-zinc-500 uppercase tracking-wider mb-1">APIRIS Risk Score</div>
                    <ApirisScoreBar score={tool.apiris_score} />
                  </div>

                  <div className="flex items-center gap-4 text-xs text-zinc-500">
                    <span>{tool.calls_24h} calls (24h)</span>
                    {tool.blocked_calls_24h > 0 && <span className="text-red-400">{tool.blocked_calls_24h} blocked</span>}
                    {tool.allowed_agents.length > 0
                      ? <span>{tool.allowed_agents.length} agents allowed</span>
                      : <span className="flex items-center gap-1 text-red-400"><XCircle size={10} /> All agents blocked</span>
                    }
                    {tool.last_used && <span className="ml-auto font-mono text-zinc-600">{new Date(tool.last_used).toLocaleTimeString()}</span>}
                  </div>
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
