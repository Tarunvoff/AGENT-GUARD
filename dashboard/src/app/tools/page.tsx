'use client';

import { useState } from 'react';
import { Wrench, Shield, AlertTriangle, CheckCircle2, Zap, Globe, Code, Layers, Server } from 'lucide-react';
import { PageHeader } from '@/components/ui/PageHeader';
import { MetricCard } from '@/components/ui/MetricCard';
import { FilterBar } from '@/components/ui/FilterBar';
import { DataTable } from '@/components/ui/DataTable';
import { StatusBadge } from '@/components/ui/StatusBadge';
import { DetailDrawer } from '@/components/ui/DetailDrawer';

interface ToolItem {
  tool_id: string;
  name: string;
  protocol: 'MCP' | 'HTTP' | 'LOCAL';
  server: string;
  risk_level: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  allowed_agents: string[];
  blocked_agents: string[];
  calls_24h: number;
  blocked_calls_24h: number;
  last_used: string | null;
  apiris_score: number;
  description: string;
  flags?: string[];
}

const DEMO_TOOLS: ToolItem[] = [
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
    description: 'Read from internal database tables via MCP bridge',
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
    flags: ['EXTERNAL_EGRESS', 'UNTRUSTED_DESTINATION'],
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
    flags: ['EXTERNAL_EGRESS'],
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
    description: 'Read local files within allowed workspace sandbox paths',
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
    description: 'LLM summarization — read-only processing, no external egress',
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

const RISK_BADGES: Record<string, string> = {
  CRITICAL: 'bg-red-50 text-red-700 border-red-200 font-semibold',
  HIGH: 'bg-amber-50 text-amber-700 border-amber-200 font-medium',
  MEDIUM: 'bg-blue-50 text-blue-700 border-blue-200',
  LOW: 'bg-slate-50 text-slate-700 border-slate-200',
};

const PROTOCOL_BADGES: Record<string, string> = {
  MCP: 'bg-purple-50 text-purple-700 border-purple-200',
  HTTP: 'bg-blue-50 text-blue-700 border-blue-200',
  LOCAL: 'bg-slate-50 text-slate-700 border-slate-200',
};

export default function ToolsPage() {
  const [search, setSearch] = useState('');
  const [protocolFilter, setProtocolFilter] = useState('ALL');
  const [riskFilter, setRiskFilter] = useState('ALL');
  const [selectedTool, setSelectedTool] = useState<ToolItem | null>(null);

  const criticalCount = DEMO_TOOLS.filter(t => t.risk_level === 'CRITICAL').length;
  const blockedCallsTotal = DEMO_TOOLS.reduce((s, t) => s + t.blocked_calls_24h, 0);
  const avgApiris = (DEMO_TOOLS.reduce((s, t) => s + t.apiris_score, 0) / DEMO_TOOLS.length).toFixed(2);

  const filtered = DEMO_TOOLS.filter(t => {
    const matchSearch =
      t.name.toLowerCase().includes(search.toLowerCase()) ||
      t.server.toLowerCase().includes(search.toLowerCase()) ||
      t.description.toLowerCase().includes(search.toLowerCase());

    const matchProtocol = protocolFilter === 'ALL' || t.protocol === protocolFilter;
    const matchRisk = riskFilter === 'ALL' || t.risk_level === riskFilter;

    return matchSearch && matchProtocol && matchRisk;
  });

  const columns = [
    {
      key: 'name',
      header: 'Tool & Server',
      render: (row: ToolItem) => (
        <div className="flex items-center gap-2.5">
          <div className="w-7 h-7 rounded-md bg-slate-100 flex items-center justify-center text-slate-600 border border-slate-200">
            <Wrench size={13} />
          </div>
          <div>
            <div className="font-mono text-xs font-semibold text-slate-900">{row.name}</div>
            <div className="text-[11px] text-slate-500 font-mono">{row.server}</div>
          </div>
        </div>
      ),
    },
    {
      key: 'protocol',
      header: 'Protocol',
      width: '100px',
      render: (row: ToolItem) => (
        <span className={`text-[11px] font-mono px-2 py-0.5 rounded border ${PROTOCOL_BADGES[row.protocol]}`}>
          {row.protocol}
        </span>
      ),
    },
    {
      key: 'risk_level',
      header: 'Risk Level',
      width: '110px',
      render: (row: ToolItem) => (
        <span className={`text-[11px] px-2 py-0.5 rounded border ${RISK_BADGES[row.risk_level]}`}>
          {row.risk_level}
        </span>
      ),
    },
    {
      key: 'apiris_score',
      header: 'APIRIS Risk',
      width: '120px',
      render: (row: ToolItem) => (
        <div className="flex items-center gap-2">
          <div className="w-12 bg-slate-100 rounded-full h-1.5 overflow-hidden">
            <div
              className={`h-full ${row.apiris_score > 0.7 ? 'bg-red-500' : row.apiris_score > 0.3 ? 'bg-amber-500' : 'bg-emerald-500'}`}
              style={{ width: `${row.apiris_score * 100}%` }}
            />
          </div>
          <span className="font-mono text-xs text-slate-700">{row.apiris_score.toFixed(2)}</span>
        </div>
      ),
    },
    {
      key: 'calls_24h',
      header: 'Calls (24h)',
      width: '110px',
      render: (row: ToolItem) => (
        <span className="font-mono text-xs text-slate-700">{row.calls_24h}</span>
      ),
    },
    {
      key: 'blocked_calls_24h',
      header: 'Blocked',
      width: '100px',
      render: (row: ToolItem) => (
        <span className={`font-mono text-xs font-semibold ${row.blocked_calls_24h > 0 ? 'text-red-700' : 'text-slate-400'}`}>
          {row.blocked_calls_24h}
        </span>
      ),
    },
  ];

  return (
    <div className="p-8 space-y-6 max-w-7xl mx-auto">
      <PageHeader
        title="Tool & MCP Registry"
        subtitle="Registered MCP servers, HTTP tools, local utilities, and automated APIRIS risk scoring"
        badge="Tool Governance"
      />

      {/* KPI Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <MetricCard label="Registered Tools" value={DEMO_TOOLS.length} />
        <MetricCard label="Critical Risk Tools" value={criticalCount} status={criticalCount > 0 ? 'BLOCK' : 'ALLOW'} />
        <MetricCard label="APIRIS Avg Risk" value={avgApiris} />
        <MetricCard label="Blocked Invocations" value={blockedCallsTotal} status={blockedCallsTotal > 0 ? 'BLOCK' : 'ALLOW'} />
      </div>

      {/* Filter and Table */}
      <div className="bg-white border border-slate-200 rounded-lg p-5 shadow-xs space-y-4">
        <FilterBar
          searchQuery={search}
          onSearchChange={setSearch}
          searchPlaceholder="Search tools by name, server, or description..."
          filters={[
            {
              key: 'protocol',
              label: 'Protocol',
              options: [
                { label: 'All Protocols', value: 'ALL' },
                { label: 'MCP', value: 'MCP' },
                { label: 'HTTP', value: 'HTTP' },
                { label: 'LOCAL', value: 'LOCAL' },
              ],
              value: protocolFilter,
              onChange: setProtocolFilter,
            },
            {
              key: 'risk',
              label: 'Risk Level',
              options: [
                { label: 'All Risks', value: 'ALL' },
                { label: 'Critical', value: 'CRITICAL' },
                { label: 'High', value: 'HIGH' },
                { label: 'Medium', value: 'MEDIUM' },
                { label: 'Low', value: 'LOW' },
              ],
              value: riskFilter,
              onChange: setRiskFilter,
            },
          ]}
          activeCount={protocolFilter !== 'ALL' || riskFilter !== 'ALL' || search ? 1 : 0}
          onReset={() => {
            setSearch('');
            setProtocolFilter('ALL');
            setRiskFilter('ALL');
          }}
        />

        <DataTable
          columns={columns}
          data={filtered}
          keyField="tool_id"
          onRowClick={(row) => setSelectedTool(row)}
          emptyMessage="No tools matched your filter criteria."
        />
      </div>

      {/* Detail Drawer */}
      <DetailDrawer
        isOpen={!!selectedTool}
        onClose={() => setSelectedTool(null)}
        title={selectedTool ? selectedTool.name : ''}
        subtitle={selectedTool ? `Protocol: ${selectedTool.protocol} • Server: ${selectedTool.server}` : ''}
        badge={selectedTool ? (
          <span className={`text-xs px-2 py-0.5 rounded border ${RISK_BADGES[selectedTool.risk_level]}`}>
            {selectedTool.risk_level}
          </span>
        ) : null}
      >
        {selectedTool && (
          <div className="space-y-6">
            {/* Description */}
            <div className="bg-slate-50 border border-slate-200 rounded-lg p-3.5 space-y-2">
              <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">Functionality & Scope</div>
              <p className="text-xs text-slate-800 leading-relaxed">{selectedTool.description}</p>
            </div>

            {/* Risk & Intelligence Flags */}
            {selectedTool.flags && selectedTool.flags.length > 0 && (
              <div>
                <div className="text-[11px] font-semibold uppercase tracking-wider text-red-600 mb-2">Security Flags</div>
                <div className="flex flex-wrap gap-1.5">
                  {selectedTool.flags.map(flag => (
                    <span key={flag} className="font-mono text-xs px-2 py-0.5 rounded bg-red-50 text-red-800 border border-red-200 font-semibold">
                      ⚠ {flag}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* APIRIS Risk Breakdown */}
            <div>
              <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-500 mb-2">APIRIS Structural Risk Score</div>
              <div className="bg-white border border-slate-200 rounded-lg p-3 space-y-2">
                <div className="flex justify-between items-center text-xs">
                  <span className="text-slate-600">Calculated Risk Index</span>
                  <span className="font-mono font-bold text-slate-900">{selectedTool.apiris_score.toFixed(2)} / 1.00</span>
                </div>
                <div className="w-full bg-slate-100 rounded-full h-2 overflow-hidden">
                  <div
                    className={`h-full ${selectedTool.apiris_score > 0.7 ? 'bg-red-500' : selectedTool.apiris_score > 0.3 ? 'bg-amber-500' : 'bg-emerald-500'}`}
                    style={{ width: `${selectedTool.apiris_score * 100}%` }}
                  />
                </div>
              </div>
            </div>

            {/* Access Matrix for Tool */}
            <div>
              <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-500 mb-2">Agent Authorization</div>
              <div className="space-y-3">
                <div className="bg-white border border-slate-200 rounded-lg p-3">
                  <div className="text-[10px] text-slate-500 uppercase font-medium mb-1.5">Permitted Agents</div>
                  {selectedTool.allowed_agents.length > 0 ? (
                    <div className="flex flex-wrap gap-1.5">
                      {selectedTool.allowed_agents.map(a => (
                        <span key={a} className="font-mono text-xs px-2 py-0.5 rounded bg-blue-50 text-blue-800 border border-blue-200 font-medium">
                          {a}
                        </span>
                      ))}
                    </div>
                  ) : (
                    <span className="text-xs text-slate-400 italic">None (All callers blocked)</span>
                  )}
                </div>

                <div className="bg-white border border-slate-200 rounded-lg p-3">
                  <div className="text-[10px] text-slate-500 uppercase font-medium mb-1.5">Explicitly Blocked</div>
                  <div className="flex flex-wrap gap-1.5">
                    {selectedTool.blocked_agents.map(b => (
                      <span key={b} className="font-mono text-xs px-2 py-0.5 rounded bg-red-50 text-red-800 border border-red-200">
                        {b}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}
      </DetailDrawer>
    </div>
  );
}
