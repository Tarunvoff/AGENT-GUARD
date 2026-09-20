'use client';

import { useState, useEffect } from 'react';
import {
  Activity, Shield, AlertTriangle, RefreshCw, Lock, Zap,
  Database, UserCheck, ArrowRight, CheckCircle2, Eye, GitBranch,
  Layers, Search, Filter
} from 'lucide-react';
import Link from 'next/link';

const API_BASE = 'http://127.0.0.1:8000/api/v1';

interface DriftEvent {
  drift_id: string;
  category: 'CONTEXT_DRIFT' | 'AUTHORITY_DRIFT' | 'ACCESS_DRIFT' | string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | string;
  entity_id: string;
  entity_type: string;
  title: string;
  description: string;
  before_state: any;
  after_state: any;
  security_implication: string;
  review_required: boolean;
  detected_at: string;
  evidence_refs?: string[];
}

interface AgentBaseline {
  agent_id: string;
  normal_tools: string[];
  normal_resources: string[];
  normal_max_depth: number;
  normal_context_sources: string[];
  sample_count: number;
  last_updated: string;
}

interface DriftReportData {
  total_drifts: number;
  events?: DriftEvent[];
  drift_events?: DriftEvent[];
  agent_baselines?: Record<string, AgentBaseline>;
}

const FALLBACK_DATA: DriftReportData = {
  total_drifts: 3,
  events: [
    {
      drift_id: 'drf_a7fe6289575f406f',
      category: 'CONTEXT_DRIFT',
      severity: 'HIGH',
      entity_id: 'ctx_59eaf37bafbc4bc4',
      entity_type: 'context',
      title: 'Context Trust State Transition (TRUSTED -> UNTRUSTED)',
      description: "Context from source 'external_mcp' changed trust classification to 'UNTRUSTED'.",
      before_state: 'TRUSTED',
      after_state: 'UNTRUSTED',
      security_implication: 'Taint boundary crossed. Downstream agents consuming this context must be restricted from sensitive sinks.',
      review_required: true,
      detected_at: new Date().toISOString(),
      evidence_refs: [],
    },
    {
      drift_id: 'drf_363372b7cac94429',
      category: 'AUTHORITY_DRIFT',
      severity: 'HIGH',
      entity_id: 'agt_60aeff2cd2a44742',
      entity_type: 'agent',
      title: "Authority Expansion Detected on Agent 'agt_60aeff2cd2a44742'",
      description: "Agent granted new capabilities: ['exec_bash', 'write_db']",
      before_state: ['read_file'],
      after_state: ['read_file', 'write_db', 'exec_bash'],
      security_implication: 'Agent capability boundary expanded. Verify alignment with principle of least privilege.',
      review_required: true,
      detected_at: new Date().toISOString(),
      evidence_refs: [],
    },
    {
      drift_id: 'drf_7cf39d1b76304bc3',
      category: 'ACCESS_DRIFT',
      severity: 'HIGH',
      entity_id: 'agt_220dca9e87ac4fe2',
      entity_type: 'agent',
      title: "New Resource Target Attempted: 'fin_export_api'",
      description: "Agent 'agt_220dca9e87ac4fe2' attempted access to 'fin_export_api' for the first time.",
      before_state: ['local_fs', 'quarterly_reports'],
      after_state: ['local_fs', 'quarterly_reports', 'fin_export_api'],
      security_implication: 'Anomalous resource access path. Potential lateral movement or prompt injection target.',
      review_required: true,
      detected_at: new Date().toISOString(),
      evidence_refs: [],
    },
  ],
  agent_baselines: {
    'agt_a1cdcb142ae84e75': {
      agent_id: 'agt_a1cdcb142ae84e75',
      normal_tools: ['execute_database_query'],
      normal_resources: ['dw_customers_prod'],
      normal_max_depth: 2,
      normal_context_sources: ['user'],
      sample_count: 5,
      last_updated: new Date().toISOString(),
    },
    'agt_970a2aafa2e04a06': {
      agent_id: 'agt_970a2aafa2e04a06',
      normal_tools: ['generate_summary'],
      normal_resources: ['local_fs'],
      normal_max_depth: 2,
      normal_context_sources: ['user'],
      sample_count: 5,
      last_updated: new Date().toISOString(),
    },
  },
};

function categoryBadge(cat: string) {
  if (cat === 'CONTEXT_DRIFT') {
    return { bg: 'bg-amber-500/10 text-amber-400 border-amber-500/20', icon: Zap, label: 'Context Drift' };
  }
  if (cat === 'AUTHORITY_DRIFT') {
    return { bg: 'bg-violet-500/10 text-violet-400 border-violet-500/20', icon: Lock, label: 'Authority Drift' };
  }
  if (cat === 'ACCESS_DRIFT') {
    return { bg: 'bg-rose-500/10 text-rose-400 border-rose-500/20', icon: Database, label: 'Access Drift' };
  }
  return { bg: 'bg-sky-500/10 text-sky-400 border-sky-500/20', icon: Activity, label: cat };
}

function severityBadge(sev: string) {
  if (sev === 'CRITICAL') return 'bg-red-500/15 text-red-400 border-red-500/30';
  if (sev === 'HIGH') return 'bg-amber-500/15 text-amber-400 border-amber-500/30';
  if (sev === 'MEDIUM') return 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30';
  return 'bg-blue-500/15 text-blue-400 border-blue-500/30';
}

function formatStateVal(val: any): string {
  if (Array.isArray(val)) return `[${val.join(', ')}]`;
  if (typeof val === 'object' && val !== null) return JSON.stringify(val);
  return String(val);
}

export default function DriftPage() {
  const [data, setData] = useState<DriftReportData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lastFetch, setLastFetch] = useState<Date | null>(null);
  const [activeTab, setActiveTab] = useState<'events' | 'baselines'>('events');
  const [filterCategory, setFilterCategory] = useState<string>('ALL');

  const fetchDrift = async () => {
    try {
      const res = await fetch(`${API_BASE}/drift`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const json = await res.json();
      setData(json);
      setLastFetch(new Date());
      setError(null);
    } catch (e: any) {
      setError(e.message || 'Failed to fetch drift report');
      setData(FALLBACK_DATA);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDrift();
    const interval = setInterval(fetchDrift, 20000);
    return () => clearInterval(interval);
  }, []);

  const driftEvents = data?.events || data?.drift_events || [];
  const filteredEvents = filterCategory === 'ALL'
    ? driftEvents
    : driftEvents.filter((e) => e.category === filterCategory);

  const contextDriftCount = driftEvents.filter((e) => e.category === 'CONTEXT_DRIFT').length;
  const authDriftCount = driftEvents.filter((e) => e.category === 'AUTHORITY_DRIFT').length;
  const accessDriftCount = driftEvents.filter((e) => e.category === 'ACCESS_DRIFT').length;
  const baselines = data?.agent_baselines || {};
  const baselineCount = Object.keys(baselines).length;

  return (
    <div className="min-h-screen bg-[#060910] text-zinc-100 p-6 space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-zinc-800/80">
        <div>
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-lg bg-violet-500/10 border border-violet-500/20 text-violet-400">
              <Activity size={20} />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-xl font-bold text-white tracking-tight">Behavioral & Authority Drift Monitor</h1>
                <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-violet-500/20 text-violet-300 border border-violet-500/30">
                  PHASE 9
                </span>
                <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 animate-pulse">
                  CONTINUOUS MONITORING
                </span>
              </div>
              <p className="text-xs text-zinc-400 mt-0.5">
                Statistical profiling of agent capabilities, resource access patterns, and context trust state transitions.
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-3">
          {error && (
            <span className="text-[11px] text-amber-400 bg-amber-500/10 border border-amber-500/20 px-2 py-1 rounded">
              Demo Fallback Active
            </span>
          )}
          <button
            onClick={fetchDrift}
            disabled={loading}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-zinc-800 hover:bg-zinc-700 text-zinc-200 rounded-lg border border-zinc-700/60 transition-colors"
          >
            <RefreshCw size={13} className={loading ? 'animate-spin' : ''} />
            Refresh
          </button>
          {lastFetch && (
            <span className="text-[11px] font-mono text-zinc-500 hidden sm:inline">
              Updated {lastFetch.toLocaleTimeString()}
            </span>
          )}
        </div>
      </div>

      {/* KPI Stats Row */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        <div className="p-3.5 rounded-xl bg-zinc-900/60 border border-zinc-800/80 flex flex-col justify-between">
          <div className="flex items-center justify-between text-zinc-400 text-xs">
            <span>Total Drift Events</span>
            <Activity size={14} className="text-violet-400" />
          </div>
          <div className="mt-2 text-2xl font-bold text-white font-mono">{driftEvents.length}</div>
          <div className="text-[10px] text-zinc-500 mt-1">Tracked across system</div>
        </div>

        <div className="p-3.5 rounded-xl bg-zinc-900/60 border border-zinc-800/80 flex flex-col justify-between">
          <div className="flex items-center justify-between text-zinc-400 text-xs">
            <span>Context Drifts</span>
            <Zap size={14} className="text-amber-400" />
          </div>
          <div className="mt-2 text-2xl font-bold text-amber-400 font-mono">{contextDriftCount}</div>
          <div className="text-[10px] text-zinc-500 mt-1">Trust downgrades</div>
        </div>

        <div className="p-3.5 rounded-xl bg-zinc-900/60 border border-zinc-800/80 flex flex-col justify-between">
          <div className="flex items-center justify-between text-zinc-400 text-xs">
            <span>Authority Creep</span>
            <Lock size={14} className="text-violet-400" />
          </div>
          <div className="mt-2 text-2xl font-bold text-violet-400 font-mono">{authDriftCount}</div>
          <div className="text-[10px] text-zinc-500 mt-1">Capability expansions</div>
        </div>

        <div className="p-3.5 rounded-xl bg-zinc-900/60 border border-zinc-800/80 flex flex-col justify-between">
          <div className="flex items-center justify-between text-zinc-400 text-xs">
            <span>Access Anomalies</span>
            <Database size={14} className="text-rose-400" />
          </div>
          <div className="mt-2 text-2xl font-bold text-rose-400 font-mono">{accessDriftCount}</div>
          <div className="text-[10px] text-zinc-500 mt-1">Novel target sinks</div>
        </div>

        <div className="p-3.5 rounded-xl bg-zinc-900/60 border border-zinc-800/80 flex flex-col justify-between col-span-2 md:col-span-1">
          <div className="flex items-center justify-between text-zinc-400 text-xs">
            <span>Trained Baselines</span>
            <UserCheck size={14} className="text-emerald-400" />
          </div>
          <div className="mt-2 text-2xl font-bold text-emerald-400 font-mono">{baselineCount}</div>
          <div className="text-[10px] text-zinc-500 mt-1">Active agent profiles</div>
        </div>
      </div>

      {/* Tabs and Filters */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 border-b border-zinc-800/60 pb-3">
        <div className="flex items-center gap-2">
          <button
            onClick={() => setActiveTab('events')}
            className={`px-3 py-1.5 text-xs font-semibold rounded-lg transition-colors ${
              activeTab === 'events'
                ? 'bg-violet-600 text-white shadow-lg shadow-violet-600/20'
                : 'text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800/60'
            }`}
          >
            Drift Alerts ({driftEvents.length})
          </button>
          <button
            onClick={() => setActiveTab('baselines')}
            className={`px-3 py-1.5 text-xs font-semibold rounded-lg transition-colors ${
              activeTab === 'baselines'
                ? 'bg-violet-600 text-white shadow-lg shadow-violet-600/20'
                : 'text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800/60'
            }`}
          >
            Agent Behavioral Baselines ({baselineCount})
          </button>
        </div>

        {activeTab === 'events' && (
          <div className="flex items-center gap-1.5 text-xs">
            <Filter size={12} className="text-zinc-500" />
            <span className="text-zinc-500">Filter:</span>
            {['ALL', 'CONTEXT_DRIFT', 'AUTHORITY_DRIFT', 'ACCESS_DRIFT'].map((cat) => (
              <button
                key={cat}
                onClick={() => setFilterCategory(cat)}
                className={`px-2 py-0.5 rounded text-[11px] font-medium transition-colors ${
                  filterCategory === cat
                    ? 'bg-zinc-700 text-white'
                    : 'text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800'
                }`}
              >
                {cat === 'ALL' ? 'All' : cat.replace('_DRIFT', '')}
              </button>
            ))}
          </div>
        )}
      </div>

      {/* Main Tab Content */}
      {activeTab === 'events' ? (
        <div className="space-y-3">
          {filteredEvents.length === 0 ? (
            <div className="p-8 text-center rounded-xl bg-zinc-900/40 border border-zinc-800/60">
              <CheckCircle2 size={32} className="mx-auto text-emerald-400 mb-2" />
              <h3 className="text-sm font-semibold text-white">No Drift Events Detected</h3>
              <p className="text-xs text-zinc-400 mt-1">
                All agent behaviors, context taint classifications, and capability boundaries are within normal baseline thresholds.
              </p>
            </div>
          ) : (
            filteredEvents.map((evt) => {
              const badge = categoryBadge(evt.category);
              const Icon = badge.icon;
              return (
                <div
                  key={evt.drift_id}
                  className="p-4 rounded-xl bg-zinc-900/60 border border-zinc-800/80 hover:border-zinc-700/80 transition-all space-y-3"
                >
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                    <div className="flex items-center gap-2.5 flex-wrap">
                      <span className={`flex items-center gap-1.5 px-2 py-0.5 rounded-md border text-xs font-semibold ${badge.bg}`}>
                        <Icon size={12} />
                        {badge.label}
                      </span>
                      <span className={`px-2 py-0.5 rounded-md border text-[11px] font-semibold ${severityBadge(evt.severity)}`}>
                        {evt.severity}
                      </span>
                      <span className="text-xs font-mono text-zinc-400">ID: {evt.drift_id}</span>
                      {evt.review_required && (
                        <span className="text-[10px] font-bold px-1.5 py-0.5 rounded bg-red-500/20 text-red-400 border border-red-500/30">
                          REVIEW REQUIRED
                        </span>
                      )}
                    </div>
                    <span className="text-[11px] font-mono text-zinc-500">
                      {new Date(evt.detected_at).toLocaleString()}
                    </span>
                  </div>

                  <div>
                    <h3 className="text-sm font-bold text-white tracking-tight">{evt.title}</h3>
                    <p className="text-xs text-zinc-300 mt-0.5">{evt.description}</p>
                  </div>

                  {/* Before vs After State Comparison Strip */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3 p-3 rounded-lg bg-black/40 border border-zinc-800/60">
                    <div>
                      <div className="text-[10px] uppercase tracking-wider text-zinc-500 font-semibold mb-1">
                        Baseline / Before State
                      </div>
                      <div className="font-mono text-xs text-emerald-400/90 bg-emerald-950/30 px-2 py-1 rounded border border-emerald-800/30 break-all">
                        {formatStateVal(evt.before_state)}
                      </div>
                    </div>
                    <div>
                      <div className="text-[10px] uppercase tracking-wider text-zinc-500 font-semibold mb-1">
                        Observed Drift / After State
                      </div>
                      <div className="font-mono text-xs text-amber-400/90 bg-amber-950/30 px-2 py-1 rounded border border-amber-800/30 break-all">
                        {formatStateVal(evt.after_state)}
                      </div>
                    </div>
                  </div>

                  {/* Security Implication and Affected Entity */}
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs pt-1 border-t border-zinc-800/40 text-zinc-400">
                    <div className="flex items-center gap-1.5">
                      <span className="text-zinc-500 font-medium">Security Implication:</span>
                      <span className="text-zinc-300">{evt.security_implication}</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="text-zinc-500 font-mono text-[11px]">
                        Target: <span className="text-sky-400">{evt.entity_type}:{evt.entity_id}</span>
                      </span>
                    </div>
                  </div>
                </div>
              );
            })
          )}
        </div>
      ) : (
        /* Baselines Tab */
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {Object.entries(baselines).map(([aid, b]) => (
            <div
              key={aid}
              className="p-4 rounded-xl bg-zinc-900/60 border border-zinc-800/80 space-y-3"
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <div className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
                  <span className="text-xs font-mono font-bold text-white">{b.agent_id}</span>
                </div>
                <span className="text-[10px] px-2 py-0.5 rounded bg-zinc-800 text-zinc-400 border border-zinc-700/60">
                  {b.sample_count} Training Samples
                </span>
              </div>

              <div className="space-y-2 text-xs">
                <div>
                  <span className="text-zinc-500 block mb-1">Authorized Baseline Tools:</span>
                  <div className="flex flex-wrap gap-1">
                    {b.normal_tools.map((t) => (
                      <span key={t} className="font-mono text-[11px] px-2 py-0.5 rounded bg-sky-950/40 text-sky-300 border border-sky-800/40">
                        {t}
                      </span>
                    ))}
                  </div>
                </div>

                <div>
                  <span className="text-zinc-500 block mb-1">Permitted Resources:</span>
                  <div className="flex flex-wrap gap-1">
                    {b.normal_resources.map((r) => (
                      <span key={r} className="font-mono text-[11px] px-2 py-0.5 rounded bg-violet-950/40 text-violet-300 border border-violet-800/40">
                        {r}
                      </span>
                    ))}
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-2 pt-2 border-t border-zinc-800/50 text-[11px]">
                  <div>
                    <span className="text-zinc-500">Max Depth: </span>
                    <span className="font-mono font-bold text-zinc-300">{b.normal_max_depth}</span>
                  </div>
                  <div>
                    <span className="text-zinc-500">Context Source: </span>
                    <span className="font-mono font-bold text-zinc-300">{b.normal_context_sources.join(', ')}</span>
                  </div>
                </div>
              </div>

              <div className="pt-2 border-t border-zinc-800/40 text-[10px] font-mono text-zinc-500">
                Baseline updated: {new Date(b.last_updated).toLocaleString()}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Integration Banner linking to other Phase 9 modules */}
      <div className="p-4 rounded-xl bg-gradient-to-r from-violet-950/30 to-sky-950/30 border border-violet-800/30 flex flex-col md:flex-row items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-violet-500/20 text-violet-300">
            <Shield size={18} />
          </div>
          <div>
            <div className="text-xs font-bold text-white">Unified Continuous Security Architecture</div>
            <div className="text-[11px] text-zinc-400">
              Drift detections automatically feed into the Security Posture Engine and trigger Incident State Machines.
            </div>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Link
            href="/posture"
            className="flex items-center gap-1 px-3 py-1.5 rounded-lg bg-violet-600 hover:bg-violet-500 text-white text-xs font-medium transition-colors"
          >
            <span>View Security Posture</span>
            <ArrowRight size={12} />
          </Link>
          <Link
            href="/security-gates"
            className="flex items-center gap-1 px-3 py-1.5 rounded-lg bg-zinc-800 hover:bg-zinc-700 text-zinc-200 text-xs font-medium border border-zinc-700 transition-colors"
          >
            <span>Quality Gates</span>
            <ArrowRight size={12} />
          </Link>
        </div>
      </div>
    </div>
  );
}
