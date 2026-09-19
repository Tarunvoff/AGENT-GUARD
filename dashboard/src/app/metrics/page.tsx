'use client';

import { BarChart2, TrendingUp, TrendingDown, Shield, Clock } from 'lucide-react';
import {
  LineChart, Line, AreaChart, Area, BarChart, Bar,
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend,
} from 'recharts';

const HOURLY_DECISIONS = [
  { hour: '00:00', allow: 12, block: 0, hitl: 1 },
  { hour: '02:00', allow: 8, block: 0, hitl: 0 },
  { hour: '04:00', allow: 5, block: 0, hitl: 0 },
  { hour: '06:00', allow: 22, block: 0, hitl: 2 },
  { hour: '08:00', allow: 45, block: 0, hitl: 3 },
  { hour: '09:00', allow: 31, block: 3, hitl: 1 },
  { hour: '10:00', allow: 28, block: 2, hitl: 2 },
  { hour: '11:00', allow: 38, block: 0, hitl: 1 },
];

const LATENCY_DATA = [
  { hour: '08:00', p50: 4, p95: 12, p99: 28 },
  { hour: '09:00', p50: 5, p95: 18, p99: 45 },
  { hour: '09:11', p50: 8, p95: 32, p99: 89 },
  { hour: '10:00', p50: 4, p95: 11, p99: 22 },
  { hour: '10:30', p50: 6, p95: 19, p99: 48 },
  { hour: '11:00', p50: 4, p95: 10, p99: 20 },
];

const DAILY_PREVENTION = [
  { day: 'Mon', prevention_rate: 100 },
  { day: 'Tue', prevention_rate: 100 },
  { day: 'Wed', prevention_rate: 100 },
  { day: 'Thu', prevention_rate: 100 },
  { day: 'Fri', prevention_rate: 100 },
  { day: 'Sat', prevention_rate: 100 },
  { day: 'Sun', prevention_rate: 100 },
];

const KPI = [
  { label: 'Empirical Prevention Rate', value: '100.0%', delta: '+0%', good: true, sub: 'Phase 5 baseline' },
  { label: 'Decisions Today', value: '189', delta: '+12%', good: true, sub: 'vs. yesterday' },
  { label: 'Avg Enforcement Latency', value: '4.2ms', delta: '-8%', good: true, sub: 'P50 decision time' },
  { label: 'Policy Engine Uptime', value: '100%', delta: '0%', good: true, sub: 'Last 30 days' },
  { label: 'HITL Escalations', value: '4', delta: '+1', good: null, sub: 'Awaiting review' },
  { label: 'Active Agents', value: '5', delta: '0', good: null, sub: 'All trusted' },
];

export default function MetricsPage() {
  return (
    <div className="p-6 space-y-5 min-h-screen bg-[#090d16]">
      <div>
        <h1 className="text-xl font-bold text-white flex items-center gap-2">
          <BarChart2 size={18} className="text-sky-400" />
          Metrics
        </h1>
        <p className="text-sm text-zinc-500 mt-1">Security performance metrics, enforcement latency, and prevention rate trends</p>
      </div>

      {/* KPI Grid */}
      <div className="grid grid-cols-3 gap-3">
        {KPI.map(kpi => (
          <div key={kpi.label} className="rounded-xl border border-zinc-800/50 bg-zinc-900/30 p-4">
            <div className="text-[10px] text-zinc-500 uppercase tracking-wider mb-2">{kpi.label}</div>
            <div className="flex items-end gap-2 mb-1">
              <div className="text-2xl font-bold font-mono text-zinc-100">{kpi.value}</div>
              <div className={`text-[11px] font-semibold mb-0.5 flex items-center gap-0.5 ${kpi.good === true ? 'text-emerald-400' : kpi.good === false ? 'text-red-400' : 'text-zinc-400'}`}>
                {kpi.good === true ? <TrendingUp size={11} /> : kpi.good === false ? <TrendingDown size={11} /> : null}
                {kpi.delta}
              </div>
            </div>
            <div className="text-[10px] text-zinc-600">{kpi.sub}</div>
          </div>
        ))}
      </div>

      {/* Charts */}
      <div className="grid grid-cols-2 gap-4">
        {/* Decision timeline */}
        <div className="rounded-xl border border-zinc-800/50 bg-zinc-900/30 p-4">
          <div className="text-[10px] uppercase tracking-wider text-zinc-500 mb-3">Decisions by Hour (Today)</div>
          <ResponsiveContainer width="100%" height={180}>
            <BarChart data={HOURLY_DECISIONS} margin={{ top: 0, right: 0, bottom: 0, left: -20 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" />
              <XAxis dataKey="hour" stroke="#374151" tick={{ fill: '#6b7280', fontSize: 10 }} />
              <YAxis stroke="#374151" tick={{ fill: '#6b7280', fontSize: 10 }} />
              <Tooltip contentStyle={{ background: '#0c1119', border: '1px solid #1f2937', borderRadius: 8, fontSize: 11 }} />
              <Bar dataKey="allow" stackId="a" fill="#10b981" radius={[0, 0, 0, 0]} name="Allow" />
              <Bar dataKey="hitl" stackId="a" fill="#f59e0b" name="HITL" />
              <Bar dataKey="block" stackId="a" fill="#ef4444" radius={[3, 3, 0, 0]} name="Block" />
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Latency */}
        <div className="rounded-xl border border-zinc-800/50 bg-zinc-900/30 p-4">
          <div className="text-[10px] uppercase tracking-wider text-zinc-500 mb-3">Enforcement Latency (ms)</div>
          <ResponsiveContainer width="100%" height={180}>
            <LineChart data={LATENCY_DATA} margin={{ top: 0, right: 0, bottom: 0, left: -20 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" />
              <XAxis dataKey="hour" stroke="#374151" tick={{ fill: '#6b7280', fontSize: 10 }} />
              <YAxis stroke="#374151" tick={{ fill: '#6b7280', fontSize: 10 }} />
              <Tooltip contentStyle={{ background: '#0c1119', border: '1px solid #1f2937', borderRadius: 8, fontSize: 11 }} />
              <Line type="monotone" dataKey="p50" stroke="#10b981" strokeWidth={2} dot={false} name="P50" />
              <Line type="monotone" dataKey="p95" stroke="#f59e0b" strokeWidth={2} dot={false} name="P95" />
              <Line type="monotone" dataKey="p99" stroke="#ef4444" strokeWidth={2} dot={false} name="P99" />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Prevention Rate 7d */}
      <div className="rounded-xl border border-emerald-500/20 bg-emerald-500/5 p-4">
        <div className="text-[10px] uppercase tracking-wider text-zinc-500 mb-3">Empirical Prevention Rate — 7 Days</div>
        <ResponsiveContainer width="100%" height={100}>
          <AreaChart data={DAILY_PREVENTION} margin={{ top: 0, right: 0, bottom: 0, left: -20 }}>
            <defs>
              <linearGradient id="prevGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#10b981" stopOpacity={0.3} />
                <stop offset="95%" stopColor="#10b981" stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" />
            <XAxis dataKey="day" stroke="#374151" tick={{ fill: '#6b7280', fontSize: 10 }} />
            <YAxis stroke="#374151" tick={{ fill: '#6b7280', fontSize: 10 }} domain={[90, 100]} />
            <Tooltip contentStyle={{ background: '#0c1119', border: '1px solid #1f2937', borderRadius: 8, fontSize: 11 }} />
            <Area type="monotone" dataKey="prevention_rate" stroke="#10b981" fill="url(#prevGrad)" strokeWidth={2} />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
