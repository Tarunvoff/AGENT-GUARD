'use client';

import { useState } from 'react';
import { DEMO_CAMPAIGNS, DEMO_ATTACKS, DEMO_MUTATION_TREE } from '@/data/demo';
import type { MutationNode, Campaign } from '@/types';
import { DecisionBadge, SeverityBadge, SectionHeader } from '@/components/ui/security';
import { Swords, ChevronRight, ChevronDown, Shield, Target, RotateCcw, AlertTriangle } from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';

export default function CampaignsPage() {
  const [selectedCampaign, setSelectedCampaign] = useState(DEMO_CAMPAIGNS[0]);

  const chartData = [
    { name: 'IPI', blocked: 25, bypasses: 0 },
    { name: 'Auth Esc', blocked: 15, bypasses: 0 },
    { name: 'Tool Poison', blocked: 10, bypasses: 0 },
    { name: 'Taint', blocked: 12, bypasses: 0 },
    { name: 'Deleg Esc', blocked: 8, bypasses: 0 },
  ];

  return (
    <div className="p-6 space-y-5 min-h-screen bg-[#090d16]">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-white flex items-center gap-2">
            <Swords size={18} className="text-red-400" />
            Attack Campaigns
          </h1>
          <p className="text-sm text-zinc-500 mt-1">Adaptive offensive security validation results</p>
        </div>
        <div className="px-3 py-1.5 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-xs text-emerald-400 flex items-center gap-1.5">
          <Shield size={11} />
          LOCAL_ONLY — No external targets
        </div>
      </div>

      {/* Phase 5 headline */}
      <div className="grid grid-cols-5 gap-3">
        {[
          { label: 'Total Variants', value: '70', color: 'text-zinc-200' },
          { label: 'Blocked', value: '70 / 70', color: 'text-emerald-400' },
          { label: 'Bypasses', value: '0', color: 'text-emerald-400' },
          { label: 'Sensitive DB Calls', value: '0', color: 'text-emerald-400' },
          { label: 'Mean Latency', value: '0.64 ms', color: 'text-sky-300' },
        ].map(({ label, value, color }) => (
          <div key={label} className="rounded-xl border border-zinc-800/50 bg-zinc-900/40 p-3 text-center">
            <div className="text-[10px] text-zinc-500 uppercase tracking-wider mb-1">{label}</div>
            <div className={`text-xl font-bold font-mono ${color}`}>{value}</div>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-3 gap-4">
        {/* Campaign list */}
        <div className="space-y-2">
          <SectionHeader title="Campaigns" />
          {DEMO_CAMPAIGNS.map(campaign => (
            <button key={campaign.campaign_id}
              onClick={() => setSelectedCampaign(campaign)}
              className={`w-full text-left rounded-xl border p-3 transition-all text-xs ${
                selectedCampaign.campaign_id === campaign.campaign_id
                  ? 'border-sky-500/30 bg-sky-500/10'
                  : 'border-zinc-800/50 bg-zinc-900/40 hover:border-zinc-700'
              }`}>
              <div className="font-semibold text-zinc-200 mb-1">{campaign.name}</div>
              <div className="flex items-center gap-2 text-zinc-500">
                <span>{campaign.total_attacks} variants</span>
                <span className={campaign.bypasses > 0 ? 'text-red-400' : 'text-emerald-400'}>
                  {campaign.bypasses} bypasses
                </span>
              </div>
            </button>
          ))}
        </div>

        {/* Campaign detail */}
        <div className="space-y-3">
          <SectionHeader title={selectedCampaign.name ?? 'Campaign Details'} />
          <div className="rounded-xl border border-zinc-800/50 bg-zinc-900/30 p-4 space-y-2 text-xs">
            {[
              { label: 'Campaign ID', value: selectedCampaign.campaign_id },
              { label: 'Total attacks', value: selectedCampaign.total_attacks },
              { label: 'Blocked', value: `${selectedCampaign.blocks} (${(selectedCampaign.blocks / selectedCampaign.total_attacks * 100).toFixed(0)}%)` },
              { label: 'Bypasses', value: selectedCampaign.bypasses },
              { label: 'Bypass rate', value: `${(selectedCampaign.bypass_rate * 100).toFixed(1)}%` },
              { label: 'Sensitive DB calls', value: selectedCampaign.sensitive_db_calls ?? 0 },
              { label: 'Mean latency', value: `${selectedCampaign.mean_latency_ms} ms` },
              { label: 'P95 latency', value: `${selectedCampaign.p95_latency_ms} ms` },
              { label: 'AI Secura', value: `${((selectedCampaign.ai_secura_availability ?? 1) * 100).toFixed(0)}%` },
              { label: 'APIRIS', value: `${((selectedCampaign.apiris_availability ?? 1) * 100).toFixed(0)}%` },
            ].map(({ label, value }) => (
              <div key={label} className="flex justify-between border-b border-zinc-800/30 py-1 last:border-0">
                <span className="text-zinc-500">{label}</span>
                <span className="font-mono text-zinc-300">{String(value)}</span>
              </div>
            ))}
          </div>

          {/* Block distribution chart */}
          <div className="rounded-xl border border-zinc-800/50 bg-zinc-900/30 p-3">
            <div className="text-[10px] text-zinc-500 uppercase tracking-wider mb-2">Blocks by Attack Type</div>
            <ResponsiveContainer width="100%" height={150}>
              <BarChart data={chartData} margin={{ top: 0, right: 0, bottom: 0, left: -20 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" />
                <XAxis dataKey="name" tick={{ fontSize: 9, fill: '#6b7280' }} />
                <YAxis tick={{ fontSize: 9, fill: '#6b7280' }} />
                <Tooltip contentStyle={{ background: '#111827', border: '1px solid #1f2937', borderRadius: 6, fontSize: 10 }} />
                <Bar dataKey="blocked" fill="#10b981" fillOpacity={0.8} radius={[3, 3, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Mutation tree */}
        <div>
          <SectionHeader title="Mutation Lineage Tree" />
          <div className="rounded-xl border border-zinc-800/50 bg-zinc-900/30 p-4 overflow-y-auto max-h-96">
            <MutationTree node={DEMO_MUTATION_TREE} depth={0} />
          </div>
        </div>
      </div>
    </div>
  );
}

function MutationTree({ node, depth }: { node: MutationNode; depth: number }) {
  const [expanded, setExpanded] = useState(depth < 1);

  return (
    <div style={{ marginLeft: depth * 16 }}>
      <div
        className={`flex items-center gap-1.5 py-1.5 px-2 rounded cursor-pointer hover:bg-zinc-800/40 text-[11px] group transition-colors ${
          node.bypassed ? 'border-l-2 border-red-500/50' : ''
        }`}
        onClick={() => setExpanded(!expanded)}
      >
        {node.children.length > 0 && (
          expanded
            ? <ChevronDown size={10} className="text-zinc-600" />
            : <ChevronRight size={10} className="text-zinc-600" />
        )}
        <div className={`w-2 h-2 rounded-full ${node.bypassed ? 'bg-red-400' : 'bg-emerald-400'}`} />
        <span className="font-mono text-[10px] text-zinc-500">{node.attack_id.slice(0, 12)}</span>
        <span className="text-zinc-400 truncate flex-1">{node.attack_type.replace(/_/g, ' ')}</span>
        <span className={`text-[9px] font-bold ${node.bypassed ? 'text-red-400' : 'text-emerald-400'}`}>
          {node.bypassed ? 'BYPASS' : 'BLOCK'}
        </span>
        <span className="text-[9px] text-zinc-700">D{node.depth}</span>
      </div>
      {expanded && node.children.map(child => (
        <MutationTree key={child.node_id} node={child} depth={depth + 1} />
      ))}
    </div>
  );
}
