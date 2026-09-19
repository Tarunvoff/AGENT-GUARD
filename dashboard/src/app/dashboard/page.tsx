'use client';

import { useState } from 'react';
import { 
  Shield, Users, CheckSquare, Zap, AlertTriangle, XCircle, 
  Activity, Lock, Database, Brain, Network, ArrowRight,
  ChevronDown, ChevronUp, TrendingUp, TrendingDown
} from 'lucide-react';
import { 
  AreaChart, Area, BarChart, Bar, XAxis, YAxis, CartesianGrid, 
  Tooltip, ResponsiveContainer, PieChart, Pie, Cell, Legend 
} from 'recharts';
import { DEMO_OVERVIEW, DEMO_EVENTS, DECISION_TIME_SERIES } from '@/data/demo';
import { DecisionBadge, TaintBadge, SeverityBadge, StatCard, SectionHeader } from '@/components/ui/security';
import LiveActivityFeed from '@/components/cards/LiveActivityFeed';
import MantaFlow from '@/components/cards/MantaFlow';
import { formatRelative } from '@/lib/colors';
import Link from 'next/link';

const PIE_COLORS = ['#10b981', '#f59e0b', '#ef4444', '#60a5fa'];

export default function CommandCenterPage() {
  const overview = DEMO_OVERVIEW;
  const [activeTab, setActiveTab] = useState<'timeline' | 'distribution'>('timeline');

  const pieData = [
    { name: 'ALLOW', value: overview.blocked === 0 ? 0 : 70 },
    { name: 'HITL', value: overview.hitl },
    { name: 'BLOCK', value: overview.blocked },
    { name: 'MONITOR', value: 12 },
  ];

  return (
    <div className="p-6 space-y-6 min-h-screen bg-[#090d16]">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-xl font-bold text-white tracking-tight">Agent Security Command Center</h1>
          <p className="text-sm text-zinc-500 mt-1 max-w-xl">
            Real-time causal visibility and deterministic enforcement across autonomous AI systems.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <div className="px-3 py-1.5 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-xs text-emerald-400 flex items-center gap-1.5">
            <div className="w-1.5 h-1.5 bg-emerald-400 rounded-full animate-pulse" />
            Unauthorized Executions: 0
          </div>
          <Link href="/demo" className="px-3 py-1.5 rounded-lg bg-sky-500/10 border border-sky-500/30 text-xs text-sky-300 hover:bg-sky-500/20 transition-colors">
            Run Demo →
          </Link>
        </div>
      </div>

      {/* 4 MANTA Visual */}
      <MantaFlow />

      {/* KPI Row 1 */}
      <div className="grid grid-cols-6 gap-3">
        <StatCard label="Active Agents" value={overview.agents} icon={Users} color="text-sky-300" sublabel="Multi-agent runtime" />
        <StatCard label="Active Tasks" value={overview.active_tasks ?? 1} icon={CheckSquare} color="text-indigo-300" sublabel="In execution" />
        <StatCard label="Tool Calls" value={overview.sensitive_attempts + 20} icon={Zap} color="text-violet-300" sublabel="Total intercepted" />
        <StatCard label="Blocked Actions" value={overview.blocked} icon={XCircle} color="text-red-400" critical sublabel={`${((overview.blocked / 73) * 100).toFixed(0)}% block rate`} />
        <StatCard label="Incidents" value={overview.incidents} icon={AlertTriangle} color="text-orange-400" sublabel="Open incidents" />
        <StatCard label="Bypasses" value={overview.bypasses} icon={Shield} color="text-emerald-400" sublabel="0 unauthorized execs" />
      </div>

      {/* KPI Row 2 */}
      <div className="grid grid-cols-6 gap-3">
        <StatCard label="Attack Variants" value={overview.attacks_today} icon={Network} color="text-red-300" sublabel="Phase 5 campaign" />
        <StatCard label="Regressions" value={overview.regressions} icon={Lock} color="text-purple-400" sublabel="1 secured replay" />
        <StatCard label="Sensitive Prevented" value={overview.sensitive_prevented} icon={Database} color="text-emerald-300" sublabel="PII vault protected" />
        <StatCard label="Sensitive Executed" value={overview.sensitive_executed} icon={Database} color="text-emerald-400" sublabel="ZERO unauthorized" />
        <StatCard label="AI Secura" value="100%" icon={Brain} color="text-violet-300" sublabel="100% availability" />
        <StatCard label="APIRIS" value="100%" icon={Zap} color="text-sky-300" sublabel="100% availability" />
      </div>

      {/* Main grid: chart + live feed */}
      <div className="grid grid-cols-3 gap-4">
        {/* Policy decisions chart */}
        <div className="col-span-2 rounded-xl border border-zinc-800/50 bg-zinc-900/30 p-4">
          <SectionHeader title="Policy Decision Timeline">
            <div className="flex gap-1">
              {(['timeline', 'distribution'] as const).map(tab => (
                <button
                  key={tab}
                  onClick={() => setActiveTab(tab)}
                  className={`px-2 py-1 text-[10px] font-medium rounded uppercase tracking-wider transition-colors ${
                    activeTab === tab
                      ? 'bg-sky-500/20 text-sky-300 border border-sky-500/30'
                      : 'text-zinc-500 hover:text-zinc-300'
                  }`}
                >
                  {tab}
                </button>
              ))}
            </div>
          </SectionHeader>

          {activeTab === 'timeline' ? (
            <ResponsiveContainer width="100%" height={200}>
              <AreaChart data={DECISION_TIME_SERIES} margin={{ top: 4, right: 4, bottom: 0, left: -20 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" />
                <XAxis dataKey="time" tick={{ fontSize: 10, fill: '#6b7280' }} />
                <YAxis tick={{ fontSize: 10, fill: '#6b7280' }} />
                <Tooltip
                  contentStyle={{ background: '#111827', border: '1px solid #1f2937', borderRadius: 8, fontSize: 11 }}
                  labelStyle={{ color: '#9ca3af' }}
                />
                <Area type="monotone" dataKey="allowed" stroke="#10b981" fill="#10b981" fillOpacity={0.1} strokeWidth={1.5} name="ALLOW" />
                <Area type="monotone" dataKey="blocked" stroke="#ef4444" fill="#ef4444" fillOpacity={0.15} strokeWidth={1.5} name="BLOCK" />
                <Area type="monotone" dataKey="hitl" stroke="#f59e0b" fill="#f59e0b" fillOpacity={0.1} strokeWidth={1.5} name="HITL" />
                <Area type="monotone" dataKey="tainted" stroke="#8b5cf6" fill="#8b5cf6" fillOpacity={0.08} strokeWidth={1.5} name="TAINTED" />
              </AreaChart>
            </ResponsiveContainer>
          ) : (
            <ResponsiveContainer width="100%" height={200}>
              <PieChart>
                <Pie data={pieData} cx="50%" cy="50%" innerRadius={50} outerRadius={80} paddingAngle={3} dataKey="value">
                  {pieData.map((_, i) => <Cell key={i} fill={PIE_COLORS[i]} fillOpacity={0.8} />)}
                </Pie>
                <Tooltip contentStyle={{ background: '#111827', border: '1px solid #1f2937', borderRadius: 8, fontSize: 11 }} />
                <Legend wrapperStyle={{ fontSize: 11, color: '#9ca3af' }} />
              </PieChart>
            </ResponsiveContainer>
          )}

          {/* Legend */}
          <div className="flex gap-4 mt-3 text-[10px]">
            {[
              { color: '#10b981', label: 'ALLOW' },
              { color: '#ef4444', label: 'BLOCK' },
              { color: '#f59e0b', label: 'HITL' },
              { color: '#8b5cf6', label: 'TAINTED' },
            ].map(({ color, label }) => (
              <div key={label} className="flex items-center gap-1.5">
                <div className="w-2 h-2 rounded-full" style={{ background: color }} />
                <span className="text-zinc-500">{label}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Live feed */}
        <div className="rounded-xl border border-zinc-800/50 bg-zinc-900/30 p-4 overflow-hidden">
          <LiveActivityFeed />
        </div>
      </div>

      {/* Bottom row: Phase 5 summary + quick links */}
      <div className="grid grid-cols-3 gap-4">
        {/* Phase 5 Results */}
        <div className="rounded-xl border border-zinc-800/50 bg-zinc-900/30 p-4">
          <SectionHeader title="Phase 5 Campaign Results" subtitle="Adaptive Offensive Validation" />
          <div className="space-y-2">
            {[
              { label: 'Attack Variants', value: '70 / 70', sub: '100% blocked', color: 'text-emerald-400' },
              { label: 'Unauthorized DB Calls', value: '0', sub: 'Zero sensitive executions', color: 'text-emerald-400' },
              { label: 'Mean Latency', value: '0.64 ms', sub: 'P95: 0.93 ms', color: 'text-sky-400' },
              { label: 'AI Secura', value: '100%', sub: 'Available throughout', color: 'text-violet-400' },
              { label: 'Regression Secured', value: '1 / 1', sub: 'Replay: BLOCK', color: 'text-emerald-400' },
            ].map(({ label, value, sub, color }) => (
              <div key={label} className="flex items-center justify-between py-1.5 border-b border-zinc-800/40 last:border-0">
                <div>
                  <div className="text-xs text-zinc-300">{label}</div>
                  <div className="text-[10px] text-zinc-600">{sub}</div>
                </div>
                <div className={`text-sm font-bold font-mono ${color}`}>{value}</div>
              </div>
            ))}
          </div>
        </div>

        {/* Authority violation summary */}
        <div className="rounded-xl border border-zinc-800/50 bg-zinc-900/30 p-4">
          <SectionHeader title="Security Scorecard" subtitle="Measurable policy metrics" />
          <div className="space-y-2">
            {[
              { label: 'Policy Decisions', value: 1248, color: 'text-zinc-200' },
              { label: 'Blocked', value: 312, color: 'text-red-400' },
              { label: 'HITL', value: 48, color: 'text-amber-400' },
              { label: 'Allowed', value: 888, color: 'text-emerald-400' },
              { label: 'Tainted Attempts', value: 97, color: 'text-orange-400' },
              { label: 'Authority Violations', value: 54, color: 'text-orange-400' },
              { label: 'Unauthorized Executions', value: 0, color: 'text-emerald-400' },
            ].map(({ label, value, color }) => (
              <div key={label} className="flex items-center justify-between py-1 border-b border-zinc-800/30 last:border-0">
                <span className="text-xs text-zinc-400">{label}</span>
                <span className={`text-sm font-bold font-mono ${color}`}>{value.toLocaleString()}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Quick Navigation */}
        <div className="rounded-xl border border-zinc-800/50 bg-zinc-900/30 p-4">
          <SectionHeader title="Investigate" subtitle="Click to drill down" />
          <div className="space-y-1.5">
            {[
              { label: 'Why was this blocked?', href: '/forensics', color: 'text-red-300', desc: 'Forensic explanation' },
              { label: 'Attack graph', href: '/attack-graph', color: 'text-orange-300', desc: 'Visual causal chain' },
              { label: 'Agent profiles', href: '/agents', color: 'text-sky-300', desc: 'Identity & authority' },
              { label: 'Access matrix', href: '/access/matrix', color: 'text-violet-300', desc: 'Permissions overview' },
              { label: 'Open incidents', href: '/incidents', color: 'text-orange-300', desc: '2 CRITICAL' },
              { label: 'Mutation lineage', href: '/campaigns', color: 'text-rose-300', desc: 'Phase 5 attack trees' },
              { label: 'Regression library', href: '/regressions', color: 'text-purple-300', desc: '1 secured replay' },
            ].map(({ label, href, color, desc }) => (
              <Link
                key={href}
                href={href}
                className="flex items-center justify-between p-2 rounded-lg hover:bg-zinc-800/40 group transition-colors"
              >
                <div>
                  <div className={`text-xs font-medium ${color}`}>{label}</div>
                  <div className="text-[10px] text-zinc-600">{desc}</div>
                </div>
                <ArrowRight size={12} className="text-zinc-700 group-hover:text-zinc-400 transition-colors" />
              </Link>
            ))}
          </div>
        </div>
      </div>

      {/* Fail-safe notice */}
      <div className="rounded-xl border border-zinc-800/40 bg-zinc-900/20 px-4 py-3 flex items-center gap-3">
        <Shield size={14} className="text-sky-400 flex-shrink-0" />
        <div className="text-[11px] text-zinc-500">
          <span className="text-sky-400 font-semibold">AI provider availability does not determine authorization.</span>
          {' '}The Policy Engine remains deterministic and fully authoritative whether AI Secura and APIRIS are online or degraded.
        </div>
      </div>
    </div>
  );
}
