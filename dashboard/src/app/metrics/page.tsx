'use client';

import { BarChart2, TrendingUp, TrendingDown, Shield, Clock } from 'lucide-react';
import {
  LineChart, Line, AreaChart, Area, BarChart, Bar,
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend,
} from 'recharts';
import { PageHeader } from '@/components/ui/PageHeader';
import { MetricCard } from '@/components/ui/MetricCard';

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
  { hour: '08:00', p50: 1.2, p95: 2.8, p99: 4.5 },
  { hour: '09:00', p50: 1.4, p95: 3.1, p99: 5.2 },
  { hour: '09:11', p50: 1.9, p95: 4.2, p99: 8.1 },
  { hour: '10:00', p50: 1.3, p95: 2.9, p99: 4.8 },
  { hour: '10:30', p50: 1.5, p95: 3.4, p99: 5.9 },
  { hour: '11:00', p50: 1.2, p95: 2.7, p99: 4.3 },
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

export default function MetricsPage() {
  return (
    <div className="p-8 space-y-6 max-w-7xl mx-auto">
      <PageHeader
        title="Security & Runtime Telemetry"
        subtitle="Granular decision rates, enforcement latency distributions, and prevention rate performance"
        badge="Telemetry Engine"
      />

      {/* KPI Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-6 gap-4">
        <MetricCard label="Prevention Rate" value="100.0%" status="ALLOW" subtext="Zero bypasses" />
        <MetricCard label="Decisions (Today)" value="189" status="ALLOW" subtext="+12% vs yesterday" />
        <MetricCard label="P50 Latency" value="1.4ms" status="ALLOW" subtext="-8% vs baseline" />
        <MetricCard label="P99 Latency" value="4.8ms" subtext="Sub-5ms SLA" />
        <MetricCard label="Engine Uptime" value="100.0%" status="ALLOW" subtext="30-day SLA" />
        <MetricCard label="HITL Queue" value="4" status="HITL" subtext="Pending reviews" />
      </div>

      {/* Charts Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Decisions Hourly */}
        <div className="bg-white border border-slate-200 rounded-lg p-5 shadow-xs space-y-4">
          <div className="text-xs font-semibold uppercase tracking-wider text-slate-500">Hourly Decision Volume (Today)</div>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={HOURLY_DECISIONS} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#f1f5f9" vertical={false} />
                <XAxis dataKey="hour" stroke="#94a3b8" fontSize={11} />
                <YAxis stroke="#94a3b8" fontSize={11} />
                <Tooltip contentStyle={{ backgroundColor: '#ffffff', borderColor: '#e2e8f0', borderRadius: '6px', fontSize: '11px' }} />
                <Legend wrapperStyle={{ fontSize: '11px', paddingTop: '10px' }} />
                <Bar dataKey="allow" stackId="a" fill="#10b981" radius={[0, 0, 0, 0]} name="Allow" />
                <Bar dataKey="hitl" stackId="a" fill="#f59e0b" name="HITL" />
                <Bar dataKey="block" stackId="a" fill="#ef4444" radius={[4, 4, 0, 0]} name="Block" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Latency Percentiles */}
        <div className="bg-white border border-slate-200 rounded-lg p-5 shadow-xs space-y-4">
          <div className="text-xs font-semibold uppercase tracking-wider text-slate-500">Enforcement Latency Percentiles (ms)</div>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={LATENCY_DATA} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#f1f5f9" vertical={false} />
                <XAxis dataKey="hour" stroke="#94a3b8" fontSize={11} />
                <YAxis stroke="#94a3b8" fontSize={11} />
                <Tooltip contentStyle={{ backgroundColor: '#ffffff', borderColor: '#e2e8f0', borderRadius: '6px', fontSize: '11px' }} />
                <Legend wrapperStyle={{ fontSize: '11px', paddingTop: '10px' }} />
                <Line type="monotone" dataKey="p50" stroke="#10b981" strokeWidth={2} name="P50 (Median)" />
                <Line type="monotone" dataKey="p95" stroke="#f59e0b" strokeWidth={2} name="P95" />
                <Line type="monotone" dataKey="p99" stroke="#ef4444" strokeWidth={2} name="P99" />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>
    </div>
  );
}
