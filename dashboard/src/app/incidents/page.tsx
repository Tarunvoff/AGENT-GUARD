'use client';

import { useState, useEffect } from 'react';
import { AlertTriangle, CheckCircle2, Clock, ArrowRight, RefreshCw, Shield, ChevronDown, ChevronRight } from 'lucide-react';
import Link from 'next/link';

const API_BASE = 'http://127.0.0.1:8000/api/v1';

interface IncidentTimelineItem {
  timestamp: string;
  stage?: string;
  state?: string;
  incident_state?: string;
  agent_id?: string;
  action?: string;
  detail?: string;
  reason?: string;
  actor?: string;
  actor_name?: string;
}

interface IncidentItem {
  incident_id: string;
  title?: string;
  severity: string;
  state: string;
  incident_type?: string;
  attack_type?: string;
  description?: string;
  agent_id?: string;
  tool_name?: string;
  created_at?: string;
  timestamp?: string;
  trace_id?: string;
  timeline?: IncidentTimelineItem[];
}

const STATE_COLORS: Record<string, string> = {
  DETECTED: 'border-red-500/50 bg-red-500/10 text-red-300',
  TRIAGED: 'border-orange-500/50 bg-orange-500/10 text-orange-300',
  INVESTIGATING: 'border-amber-500/50 bg-amber-500/10 text-amber-300',
  CONTAINED: 'border-sky-500/50 bg-sky-500/10 text-sky-300',
  REMEDIATING: 'border-indigo-500/50 bg-indigo-500/10 text-indigo-300',
  REMEDIATED: 'border-indigo-500/50 bg-indigo-500/10 text-indigo-300',
  VALIDATED: 'border-emerald-500/50 bg-emerald-500/10 text-emerald-300',
  RESOLVED: 'border-emerald-500/50 bg-emerald-500/10 text-emerald-300',
  CLOSED: 'border-zinc-500/50 bg-zinc-500/10 text-zinc-400',
};

const SEV_COLORS: Record<string, string> = {
  CRITICAL: 'text-red-400',
  HIGH: 'text-orange-400',
  MEDIUM: 'text-amber-400',
  LOW: 'text-sky-400',
};

function formatRelative(ts?: string): string {
  if (!ts) return '';
  const diff = Date.now() - new Date(ts).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return mins + 'm ago';
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return hrs + 'h ago';
  return Math.floor(hrs / 24) + 'd ago';
}

function IncidentCard({ inc }: { inc: IncidentItem }) {
  const [open, setOpen] = useState<boolean>(false);
  const stateCls = STATE_COLORS[inc.state] || STATE_COLORS.DETECTED;
  const sevCls = SEV_COLORS[inc.severity] || 'text-zinc-400';
  const timeline = inc.timeline || [];

  return (
    <div className={"rounded-xl border bg-zinc-900/40 transition-all " + (inc.severity === 'CRITICAL' ? 'border-red-500/30 shadow-lg shadow-red-500/5' : inc.severity === 'HIGH' ? 'border-orange-500/20' : 'border-zinc-800/50')}>
      <div className="p-4">
        <div className="flex items-start justify-between">
          <div className="flex items-start gap-3">
            <div className={"w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0 " + (inc.severity === 'CRITICAL' ? 'bg-red-500/10' : 'bg-orange-500/10')}>
              <AlertTriangle size={14} className={inc.severity === 'CRITICAL' ? 'text-red-400' : 'text-orange-400'} />
            </div>
            <div>
              <div className="flex items-center gap-2 mb-1 flex-wrap">
                <span className={"text-[10px] font-bold " + sevCls}>{inc.severity}</span>
                <span className="text-xs font-mono text-zinc-500">{inc.incident_id}</span>
                <span className={"text-[10px] px-1.5 py-0.5 rounded border font-medium " + stateCls}>{inc.state}</span>
              </div>
              <div className="text-sm font-medium text-zinc-200 mb-1">
                {inc.title || (inc.incident_type ? inc.incident_type.replace(/_/g, ' ') : inc.attack_type?.replace(/_/g, ' ') || 'Security Incident')}
              </div>
              <div className="text-xs text-zinc-500 leading-relaxed max-w-2xl">{inc.description}</div>
              <div className="flex items-center gap-3 mt-2 text-[10px] text-zinc-600">
                {inc.agent_id && <span>Agent: <span className="font-mono text-zinc-500">{inc.agent_id}</span></span>}
                {inc.tool_name && <span>Tool: <span className="font-mono text-zinc-500">{inc.tool_name}</span></span>}
                <span className="flex items-center gap-1"><Clock size={9} /> {formatRelative(inc.created_at || inc.timestamp)}</span>
              </div>
            </div>
          </div>
          <button onClick={() => setOpen(!open)} className="flex items-center gap-1 text-[11px] text-zinc-500 hover:text-zinc-300 transition-colors cursor-pointer mt-1">
            {open ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
            Timeline ({timeline.length})
          </button>
        </div>

        {/* Timeline */}
        {open && timeline.length > 0 && (
          <div className="mt-4 pt-4 border-t border-zinc-800/50 space-y-1.5">
            <div className="text-[10px] text-zinc-500 uppercase tracking-widest mb-2">State Machine Timeline</div>
            {timeline.map((t: IncidentTimelineItem, i: number) => {
              const stateName = t.state || t.incident_state || t.stage || 'STAGE';
              return (
                <div key={i} className="flex items-start gap-3 text-[11px]">
                  <div className="font-mono text-zinc-600 w-20 flex-shrink-0">{String(t.timestamp).slice(11, 19)}</div>
                  <div className={"px-1.5 py-0.5 rounded text-[10px] font-bold font-mono flex-shrink-0 " + (STATE_COLORS[stateName] || 'text-zinc-400 bg-zinc-800')}>
                    {stateName}
                  </div>
                  <div className="text-zinc-400 flex-1">
                    {t.reason || t.detail || t.action} <span className="text-zinc-600">by {t.actor || t.actor_name || 'system'}</span>
                  </div>
                </div>
              );
            })}
          </div>
        )}

        <div className="flex items-center gap-2 mt-3 pt-3 border-t border-zinc-800/40">
          <Link href="/forensics" className="text-[11px] text-sky-400 hover:text-sky-300 flex items-center gap-1">
            Forensics <ArrowRight size={10} />
          </Link>
          <Link href="/attack-graph" className="text-[11px] text-sky-400 hover:text-sky-300 flex items-center gap-1">
            Attack Graph <ArrowRight size={10} />
          </Link>
          {inc.trace_id && (
            <Link href="/traces" className="text-[11px] text-sky-400 hover:text-sky-300 flex items-center gap-1">
              Trace <ArrowRight size={10} />
            </Link>
          )}
        </div>
      </div>
    </div>
  );
}

export default function IncidentsPage() {
  const [incidents, setIncidents] = useState<IncidentItem[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<string>('all');
  const [lastFetch, setLastFetch] = useState<Date | null>(null);

  const fetchIncidents = async () => {
    try {
      const res = await fetch(API_BASE + '/incidents');
      if (!res.ok) throw new Error('HTTP ' + res.status);
      const data = await res.json();
      setIncidents(Array.isArray(data) ? data : []);
      setLastFetch(new Date());
      setError(null);
    } catch (e: any) {
      setError(e.message || 'Failed to load');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchIncidents();
    const id = setInterval(fetchIncidents, 20000);
    return () => clearInterval(id);
  }, []);

  const FILTERS = ['all', 'CRITICAL', 'HIGH', 'MEDIUM', 'DETECTED', 'CONTAINED', 'RESOLVED', 'CLOSED'];
  const filtered = incidents.filter(i => {
    if (filter === 'all') return true;
    return i.severity === filter || i.state === filter;
  });

  const active = incidents.filter(i => !['RESOLVED', 'CLOSED', 'VALIDATED'].includes(i.state)).length;

  return (
    <div className="p-6 space-y-5 min-h-screen bg-[#090d16]">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-xl font-bold text-white flex items-center gap-2">
            <AlertTriangle size={18} className="text-orange-400" />
            Incidents
          </h1>
          <p className="text-sm text-zinc-500 mt-1">Live Phase 9 state machine — 7-stage incident lifecycle</p>
        </div>
        <div className="flex items-center gap-3">
          <div className="text-sm text-zinc-500">
            <span className="text-red-400 font-bold">{active}</span> active,{' '}
            <span className="text-zinc-200 font-bold">{incidents.length}</span> total
          </div>
          {lastFetch && <span className="text-[10px] text-zinc-600 font-mono">{lastFetch.toLocaleTimeString()}</span>}
          <button onClick={fetchIncidents} className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-zinc-800 text-xs text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800/50 transition-colors cursor-pointer">
            <RefreshCw size={12} /> Refresh
          </button>
        </div>
      </div>

      {error && (
        <div className="p-3 rounded-xl border border-amber-500/30 bg-amber-500/10 text-xs text-amber-300">
          ⚠ Backend unreachable ({error}) — run the Phase 9 demo first to generate incidents
        </div>
      )}

      <div className="flex gap-2 flex-wrap">
        {FILTERS.map(f => (
          <button key={f} onClick={() => setFilter(f)}
            className={"px-2.5 py-1 text-[11px] rounded font-medium uppercase tracking-wider transition-colors cursor-pointer " +
              (filter === f ? 'bg-sky-500/15 border border-sky-500/30 text-sky-300' : 'text-zinc-500 hover:text-zinc-300')}>
            {f}
          </button>
        ))}
      </div>

      <div className="space-y-3">
        {loading && (
          <div className="flex items-center gap-3 p-6 rounded-xl border border-zinc-800/50 bg-zinc-900/30">
            <RefreshCw size={14} className="text-sky-400 animate-spin" />
            <span className="text-sm text-zinc-400">Loading incidents from Phase 9 backend...</span>
          </div>
        )}

        {!loading && filtered.length === 0 && (
          <div className="flex flex-col items-center gap-3 p-10 rounded-xl border border-zinc-800/50 bg-zinc-900/30 text-center">
            <CheckCircle2 size={32} className="text-emerald-400" />
            <div className="text-sm font-medium text-zinc-300">No incidents match your filter</div>
            <div className="text-xs text-zinc-500">
              {incidents.length === 0
                ? 'Run the continuous_security_demo.py to generate Phase 9 incident data'
                : 'Try selecting a different filter'}
            </div>
            {incidents.length === 0 && (
              <div className="mt-2 p-2 bg-zinc-900 rounded text-[11px] font-mono text-zinc-400">
                python examples/phase9/continuous_security_demo.py
              </div>
            )}
          </div>
        )}

        {filtered.map(inc => <IncidentCard key={inc.incident_id} inc={inc} />)}
      </div>
    </div>
  );
}
