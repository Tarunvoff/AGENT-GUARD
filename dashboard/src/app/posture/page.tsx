'use client';

import { useState, useEffect } from 'react';
import {
  Shield, Activity, AlertTriangle, CheckCircle2, RefreshCw,
  Lock, Zap, Database, Clock, ArrowRight, Server
} from 'lucide-react';
import {
  RadarChart, PolarGrid, PolarAngleAxis, Radar, ResponsiveContainer,
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Cell
} from 'recharts';
import Link from 'next/link';

const API_BASE = 'http://127.0.0.1:8000/api/v1';

interface PostureMetrics {
  unauthorized_access_attempts?: number;
  actual_unauthorized_executions?: number;
  authority_violations?: number;
  ai_secura_availability_pct?: number;
  apiris_availability_pct?: number;
  policy_engine_availability_pct?: number;
  mean_enforcement_latency_ms?: number;
  open_regressions?: number;
  high_risk_agents_count?: number;
  offensive_validation_failures?: number;
}

interface PostureData {
  snapshot_id?: string;
  rating?: string;
  security_score?: number;
  metrics?: PostureMetrics;
  active_incidents_count?: number;
  findings?: any[];
  timestamp?: string;
  environment?: string;
}

function ratingColor(r?: string): string {
  if (!r) return 'text-emerald-400';
  if (r === 'HEALTHY') return 'text-emerald-400';
  if (r === 'DEGRADED') return 'text-amber-400';
  return 'text-red-400';
}

function ratingGrade(r?: string): string {
  if (r === 'HEALTHY') return 'A+';
  if (r === 'DEGRADED') return 'B';
  return 'C';
}

export default function PosturePage() {
  const [posture, setPosture] = useState<PostureData | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [lastFetch, setLastFetch] = useState<Date | null>(null);

  const fetchPosture = async () => {
    try {
      const res = await fetch(API_BASE + '/posture');
      if (!res.ok) throw new Error('HTTP ' + res.status);
      const data = await res.json();
      setPosture(data);
      setLastFetch(new Date());
      setError(null);
    } catch (e: any) {
      setError(e.message || 'Failed to load');
      setPosture({
        snapshot_id: 'demo_fallback',
        rating: 'HEALTHY',
        security_score: 97.5,
        metrics: {
          unauthorized_access_attempts: 0,
          actual_unauthorized_executions: 0,
          authority_violations: 0,
          ai_secura_availability_pct: 100.0,
          apiris_availability_pct: 100.0,
          policy_engine_availability_pct: 100.0,
          mean_enforcement_latency_ms: 1.4,
          open_regressions: 0,
          high_risk_agents_count: 1,
        },
        active_incidents_count: 0,
        findings: [],
      });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchPosture();
    const id = setInterval(fetchPosture, 15000);
    return () => clearInterval(id);
  }, []);

  const metrics = posture?.metrics || {};

  // Build radar data from key metrics
  const radarData = [
    { subject: 'Enforcement', value: metrics.policy_engine_availability_pct ?? 100 },
    { subject: 'AI Secura', value: metrics.ai_secura_availability_pct ?? 100 },
    { subject: 'APIRIS', value: metrics.apiris_availability_pct ?? 100 },
    { subject: 'Zero Exec', value: metrics.actual_unauthorized_executions === 0 ? 100 : 0 },
    { subject: 'Zero Auth', value: metrics.authority_violations === 0 ? 100 : 80 },
    { subject: 'No Bypass', value: (metrics.offensive_validation_failures ?? 0) === 0 ? 100 : 50 },
  ];

  // Key metrics cards
  const metricCards = [
    { label: 'Unauth Executions', value: metrics.actual_unauthorized_executions ?? 0, ok: metrics.actual_unauthorized_executions === 0, format: (v: number) => v.toString() },
    { label: 'Auth Violations', value: metrics.authority_violations ?? 0, ok: metrics.authority_violations === 0, format: (v: number) => v.toString() },
    { label: 'Policy Uptime', value: metrics.policy_engine_availability_pct ?? 100, ok: true, format: (v: number) => v.toFixed(1) + '%' },
    { label: 'AI Secura Uptime', value: metrics.ai_secura_availability_pct ?? 100, ok: true, format: (v: number) => v.toFixed(1) + '%' },
    { label: 'APIRIS Uptime', value: metrics.apiris_availability_pct ?? 100, ok: true, format: (v: number) => v.toFixed(1) + '%' },
    { label: 'Mean Latency', value: metrics.mean_enforcement_latency_ms ?? 0, ok: true, format: (v: number) => v.toFixed(2) + ' ms' },
    { label: 'Open Regressions', value: metrics.open_regressions ?? 0, ok: (metrics.open_regressions ?? 0) === 0, format: (v: number) => v.toString() },
    { label: 'High Risk Agents', value: metrics.high_risk_agents_count ?? 0, ok: (metrics.high_risk_agents_count ?? 0) <= 2, format: (v: number) => v.toString() },
  ];

  const barData = [
    { label: 'Policy Engine', score: metrics.policy_engine_availability_pct ?? 100, color: '#10b981' },
    { label: 'AI Secura', score: metrics.ai_secura_availability_pct ?? 100, color: '#60a5fa' },
    { label: 'APIRIS', score: metrics.apiris_availability_pct ?? 100, color: '#a78bfa' },
    { label: 'Security Score', score: posture?.security_score ?? 100, color: '#34d399' },
  ];

  return (
    <div className="p-6 space-y-6 min-h-screen bg-[#090d16]">
      <div className="flex items-start justify-between">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded border border-violet-500/40 bg-violet-500/10 text-violet-400">
              PHASE 9 — CONTINUOUS SECURITY
            </span>
          </div>
          <h1 className="text-xl font-bold text-white flex items-center gap-2">
            <Shield size={18} className="text-violet-400" />
            Security Posture Assessment
          </h1>
          <p className="text-sm text-zinc-500 mt-1">Multi-dimensional real-time posture scored live from AgentGuard runtime</p>
        </div>
        <div className="flex items-center gap-3">
          {lastFetch && <span className="text-[10px] text-zinc-600 font-mono">Updated: {lastFetch.toLocaleTimeString()}</span>}
          <button onClick={fetchPosture} className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-zinc-800 text-xs text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800/50 transition-colors cursor-pointer">
            <RefreshCw size={12} /> Refresh
          </button>
          <Link href="/security-gates" className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-violet-600 hover:bg-violet-500 text-xs font-semibold text-white transition-colors">
            CI/CD Gates <ArrowRight size={12} />
          </Link>
        </div>
      </div>

      {error && (
        <div className="p-3 rounded-xl border border-amber-500/30 bg-amber-500/10 text-xs text-amber-300">
          ⚠ Backend unreachable ({error}) — showing fallback posture data
        </div>
      )}

      {posture && (
        <>
          {/* Grade + snapshot banner */}
          <div className="grid grid-cols-4 gap-4">
            <div className="col-span-1 rounded-xl border border-violet-500/30 bg-gradient-to-b from-violet-500/10 to-transparent p-5 flex flex-col items-center justify-center text-center">
              <div className="text-[10px] text-zinc-500 uppercase tracking-widest mb-2">Security Rating</div>
              <div className={"text-5xl font-black font-mono " + ratingColor(posture.rating)}>
                {ratingGrade(posture.rating)}
              </div>
              <div className={"text-sm font-bold mt-1 " + ratingColor(posture.rating)}>{posture.rating}</div>
              <div className="text-2xl font-bold text-zinc-200 mt-2 font-mono">
                {(posture.security_score ?? 100).toFixed(1)}
                <span className="text-sm text-zinc-500 font-normal">/100</span>
              </div>
              <div className="mt-3 text-[10px] text-emerald-400 flex items-center gap-1">
                <CheckCircle2 size={10} /> {posture.active_incidents_count ?? 0} active incidents
              </div>
            </div>

            <div className="col-span-3 grid grid-cols-4 gap-3">
              {metricCards.map(({ label, value, ok, format }) => (
                <div key={label} className="rounded-xl border border-zinc-800/50 bg-zinc-900/30 p-3 flex flex-col gap-1">
                  <div className="text-[10px] text-zinc-500">{label}</div>
                  <div className={"text-lg font-bold font-mono " + (ok ? 'text-emerald-400' : 'text-red-400')}>
                    {format(value)}
                  </div>
                  <div className={"text-[10px] " + (ok ? 'text-emerald-600' : 'text-red-500')}>
                    {ok ? '✓ OK' : '✕ Alert'}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Charts */}
          <div className="grid grid-cols-2 gap-4">
            <div className="rounded-xl border border-zinc-800/50 bg-zinc-900/30 p-4">
              <div className="text-xs font-semibold text-zinc-300 mb-3 flex items-center gap-2">
                <Activity size={13} className="text-violet-400" /> Posture Radar
              </div>
              <ResponsiveContainer width="100%" height={220}>
                <RadarChart data={radarData} outerRadius={80}>
                  <PolarGrid stroke="#1f2937" />
                  <PolarAngleAxis dataKey="subject" tick={{ fontSize: 10, fill: '#6b7280' }} />
                  <Radar name="Score" dataKey="value" stroke="#8b5cf6" fill="#8b5cf6" fillOpacity={0.25} strokeWidth={2} />
                </RadarChart>
              </ResponsiveContainer>
            </div>

            <div className="rounded-xl border border-zinc-800/50 bg-zinc-900/30 p-4">
              <div className="text-xs font-semibold text-zinc-300 mb-3 flex items-center gap-2">
                <Database size={13} className="text-sky-400" /> Component Availability
              </div>
              <ResponsiveContainer width="100%" height={220}>
                <BarChart data={barData} margin={{ top: 4, right: 4, bottom: 20, left: -20 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" />
                  <XAxis dataKey="label" tick={{ fontSize: 9, fill: '#4b5563' }} />
                  <YAxis domain={[0, 100]} tick={{ fontSize: 9, fill: '#4b5563' }} />
                  <Tooltip contentStyle={{ background: '#111827', border: '1px solid #1f2937', borderRadius: 8, fontSize: 11 }} formatter={(v: any) => [typeof v === 'number' ? v.toFixed(1) + '%' : String(v), 'Score']} />
                  <Bar dataKey="score" radius={[3, 3, 0, 0]}>
                    {barData.map((e, i) => <Cell key={i} fill={e.color} fillOpacity={0.85} />)}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Findings */}
          <div className="rounded-xl border border-zinc-800/50 bg-zinc-900/30 p-4">
            <div className="text-xs font-semibold text-zinc-300 mb-3 flex items-center gap-2">
              <AlertTriangle size={13} className="text-orange-400" /> Active Findings & Metadata
            </div>
            <div className="grid grid-cols-4 gap-3 text-xs">
              <div>
                <div className="text-zinc-600">Snapshot ID</div>
                <div className="text-zinc-300 font-mono mt-0.5 truncate">{posture.snapshot_id ?? 'posture_live'}</div>
              </div>
              <div>
                <div className="text-zinc-600">Generated</div>
                <div className="text-zinc-300 font-mono mt-0.5">
                  {posture.timestamp ? new Date(posture.timestamp).toLocaleString() : 'Now'}
                </div>
              </div>
              <div>
                <div className="text-zinc-600">Environment</div>
                <div className="text-emerald-400 font-bold mt-0.5 capitalize">{posture.environment ?? 'production'}</div>
              </div>
              <div>
                <div className="text-zinc-600">Active Findings</div>
                <div className={"font-bold mt-0.5 " + (((posture.findings?.length ?? 0) > 0) ? 'text-orange-400' : 'text-emerald-400')}>
                  {posture.findings?.length ?? 0} {((posture.findings?.length ?? 0) > 0) ? 'findings' : '(clean)'}
                </div>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-4">
            <Link href="/incidents" className="text-xs text-sky-400 hover:text-sky-300 flex items-center gap-1 transition-colors">
              <AlertTriangle size={11} /> Incidents <ArrowRight size={10} />
            </Link>
            <Link href="/security-gates" className="text-xs text-violet-400 hover:text-violet-300 flex items-center gap-1 transition-colors">
              <Lock size={11} /> CI/CD Gates <ArrowRight size={10} />
            </Link>
            <Link href="/campaigns" className="text-xs text-orange-400 hover:text-orange-300 flex items-center gap-1 transition-colors">
              <Zap size={11} /> Attack Campaigns <ArrowRight size={10} />
            </Link>
          </div>
        </>
      )}
    </div>
  );
}
