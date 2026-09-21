'use client';

import { useState } from 'react';
import { DEMO_CAMPAIGNS, DEMO_ATTACKS } from '@/data/demo';
import { PageHeader } from '@/components/ui/PageHeader';
import { MetricCard } from '@/components/ui/MetricCard';
import { StatusBadge } from '@/components/ui/StatusBadge';
import { FilterBar } from '@/components/ui/FilterBar';
import { DataTable } from '@/components/ui/DataTable';
import { DetailDrawer } from '@/components/ui/DetailDrawer';
import { Swords, Shield, Target, RotateCcw, AlertTriangle, CheckCircle2, BarChart2 } from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';

export default function CampaignsPage() {
  const [selectedCampaign, setSelectedCampaign] = useState(DEMO_CAMPAIGNS[0]);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [search, setSearch] = useState('');

  const chartData = [
    { name: 'Prompt Inj.', blocked: 25, bypasses: 0 },
    { name: 'Auth Esc.', blocked: 15, bypasses: 0 },
    { name: 'Tool Poison', blocked: 10, bypasses: 0 },
    { name: 'Taint Leak', blocked: 12, bypasses: 0 },
    { name: 'Deleg Esc.', blocked: 8, bypasses: 0 },
  ];

  const filteredCampaigns = DEMO_CAMPAIGNS.filter(c =>
    (c.name || '').toLowerCase().includes(search.toLowerCase()) ||
    c.campaign_id.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="p-8 space-y-6 max-w-7xl mx-auto">
      <PageHeader
        title="Offensive Validation Campaigns"
        subtitle="Automated adversarial mutation suites testing containment, taint propagation, and delegation boundaries"
        badge="Red-Team Engine"
        actions={
          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-emerald-50 border border-emerald-200 text-xs text-emerald-800 font-medium">
            <Shield size={13} className="text-emerald-600" />
            <span>Sandbox Mode: LOCAL_ONLY</span>
          </div>
        }
      />

      {/* KPI Cards */}
      <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
        <MetricCard label="Total Variants" value="70" />
        <MetricCard label="Blocked Variants" value="70 / 70" status="ALLOW" />
        <MetricCard label="Bypasses Found" value="0" status="ALLOW" />
        <MetricCard label="Sensitive DB Calls" value="0" status="ALLOW" />
        <MetricCard label="Mean Eval Latency" value="0.64 ms" />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Campaign List */}
        <div className="bg-white border border-slate-200 rounded-lg p-5 shadow-xs space-y-4">
          <div className="text-xs font-semibold uppercase tracking-wider text-slate-500">Validation Campaigns</div>
          <div className="space-y-2">
            {filteredCampaigns.map(campaign => (
              <button
                key={campaign.campaign_id}
                onClick={() => setSelectedCampaign(campaign)}
                className={`w-full text-left p-3.5 rounded-lg border text-xs transition-all ${
                  selectedCampaign.campaign_id === campaign.campaign_id
                    ? 'border-blue-600 bg-blue-50/50 text-blue-900 font-semibold'
                    : 'border-slate-200 bg-white hover:bg-slate-50 text-slate-700'
                }`}
              >
                <div className="flex items-center justify-between mb-1">
                  <span className="font-semibold text-slate-900">{campaign.name}</span>
                  <span className="font-mono text-[11px] text-slate-500">{campaign.campaign_id}</span>
                </div>
                <div className="flex items-center gap-3 text-slate-500 text-[11px]">
                  <span>{campaign.total_attacks} variants</span>
                  <span className="text-emerald-700 font-medium">{campaign.blocks} blocked</span>
                  <span className={campaign.bypasses > 0 ? 'text-red-700' : 'text-slate-400'}>
                    {campaign.bypasses} bypasses
                  </span>
                </div>
              </button>
            ))}
          </div>
        </div>

        {/* Selected Campaign Details */}
        <div className="bg-white border border-slate-200 rounded-lg p-5 shadow-xs space-y-4">
          <div className="flex items-center justify-between">
            <div className="text-xs font-semibold uppercase tracking-wider text-slate-500">Campaign Diagnostics</div>
            <span className="font-mono text-xs font-semibold text-blue-700 bg-blue-50 px-2 py-0.5 rounded border border-blue-200">
              {selectedCampaign.campaign_id}
            </span>
          </div>

          <div className="space-y-2 text-xs">
            {[
              { label: 'Total Attack Tests', value: selectedCampaign.total_attacks },
              { label: 'Blocked Invocations', value: `${selectedCampaign.blocks} (${((selectedCampaign.blocks / selectedCampaign.total_attacks) * 100).toFixed(0)}%)` },
              { label: 'Observed Bypasses', value: selectedCampaign.bypasses },
              { label: 'Bypass Probability', value: `${(selectedCampaign.bypass_rate * 100).toFixed(1)}%` },
              { label: 'Sensitive DB Accesses', value: selectedCampaign.sensitive_db_calls ?? 0 },
              { label: 'Mean Intercept Latency', value: `${selectedCampaign.mean_latency_ms} ms` },
              { label: 'P95 Intercept Latency', value: `${selectedCampaign.p95_latency_ms} ms` },
            ].map(({ label, value }) => (
              <div key={label} className="flex justify-between py-1.5 border-b border-slate-100 last:border-0">
                <span className="text-slate-500">{label}</span>
                <span className="font-mono font-medium text-slate-900">{String(value)}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Chart View */}
        <div className="bg-white border border-slate-200 rounded-lg p-5 shadow-xs space-y-4">
          <div className="text-xs font-semibold uppercase tracking-wider text-slate-500">Variants Blocked by Category</div>
          <div className="h-56">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={chartData} margin={{ top: 10, right: 10, left: -20, bottom: 20 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#f1f5f9" vertical={false} />
                <XAxis dataKey="name" stroke="#94a3b8" fontSize={10} angle={-25} textAnchor="end" />
                <YAxis stroke="#94a3b8" fontSize={10} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#ffffff', borderColor: '#e2e8f0', borderRadius: '6px', fontSize: '11px' }}
                />
                <Bar dataKey="blocked" fill="#2563eb" radius={[4, 4, 0, 0]} name="Blocked (Safe)" />
                <Bar dataKey="bypasses" fill="#dc2626" radius={[4, 4, 0, 0]} name="Bypasses" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>
    </div>
  );
}
