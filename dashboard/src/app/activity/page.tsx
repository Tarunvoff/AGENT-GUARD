'use client';

import { useState, useEffect, useRef } from 'react';
import { DEMO_EVENTS, DEMO_AGENTS } from '@/data/demo';
import { DecisionBadge, TrustBadge, SeverityBadge } from '@/components/ui/security';
import { Activity, Pause, Play, Filter, Terminal, Shield, AlertTriangle, CheckCircle2, Clock } from 'lucide-react';

const DECISION_ICONS: Record<string, React.ElementType> = {
  ALLOW: CheckCircle2,
  BLOCK: AlertTriangle,
  HITL: Clock,
  MONITOR: Activity,
};

const DECISION_COLORS: Record<string, string> = {
  ALLOW: 'text-emerald-400',
  BLOCK: 'text-red-400',
  HITL: 'text-amber-400',
  MONITOR: 'text-sky-400',
};

export default function ActivityPage() {
  const [paused, setPaused] = useState(false);
  const [filter, setFilter] = useState<string>('all');
  const [events, setEvents] = useState(DEMO_EVENTS.slice(0, 20));
  const [tick, setTick] = useState(0);
  const feedRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (paused) return;
    const interval = setInterval(() => {
      setTick(t => t + 1);
      const newEvt = {
        ...DEMO_EVENTS[Math.floor(Math.random() * DEMO_EVENTS.length)],
        event_id: `evt_live_${Date.now()}`,
        timestamp: new Date().toISOString(),
      };
      setEvents(prev => [newEvt, ...prev].slice(0, 100));
    }, 2200);
    return () => clearInterval(interval);
  }, [paused]);

  const filtered = filter === 'all' ? events : events.filter(e => e.decision === filter);

  const stats = {
    ALLOW: events.filter(e => e.decision === 'ALLOW').length,
    BLOCK: events.filter(e => e.decision === 'BLOCK').length,
    HITL: events.filter(e => e.decision === 'HITL').length,
    total: events.length,
  };

  return (
    <div className="p-6 space-y-5 min-h-screen bg-[#090d16]">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-white flex items-center gap-2">
            <Activity size={18} className="text-sky-400" />
            Live Activity Feed
          </h1>
          <p className="text-sm text-zinc-500 mt-1">Real-time security decisions across all agents and tools</p>
        </div>
        <div className="flex items-center gap-2">
          <div className={`w-2 h-2 rounded-full ${paused ? 'bg-zinc-500' : 'bg-emerald-400 animate-pulse'}`} />
          <span className="text-xs text-zinc-400">{paused ? 'PAUSED' : 'LIVE'}</span>
          <button
            onClick={() => setPaused(p => !p)}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-zinc-800/80 border border-zinc-700/50 text-xs text-zinc-300 hover:text-white hover:bg-zinc-700/80 transition-colors"
          >
            {paused ? <Play size={12} /> : <Pause size={12} />}
            {paused ? 'Resume' : 'Pause'}
          </button>
        </div>
      </div>

      {/* Stats Row */}
      <div className="grid grid-cols-4 gap-3">
        {[
          { label: 'Total Events', value: stats.total, color: 'text-zinc-200', bg: 'bg-zinc-800/40', border: 'border-zinc-700/30' },
          { label: 'Allowed', value: stats.ALLOW, color: 'text-emerald-400', bg: 'bg-emerald-500/5', border: 'border-emerald-500/20' },
          { label: 'Blocked', value: stats.BLOCK, color: 'text-red-400', bg: 'bg-red-500/5', border: 'border-red-500/20' },
          { label: 'HITL Review', value: stats.HITL, color: 'text-amber-400', bg: 'bg-amber-500/5', border: 'border-amber-500/20' },
        ].map(s => (
          <div key={s.label} className={`rounded-xl border ${s.border} ${s.bg} p-4 text-center`}>
            <div className="text-[10px] text-zinc-500 uppercase tracking-wider mb-1">{s.label}</div>
            <div className={`text-2xl font-bold font-mono ${s.color}`}>{s.value}</div>
          </div>
        ))}
      </div>

      {/* Filter Bar */}
      <div className="flex items-center gap-3">
        <Filter size={13} className="text-zinc-500" />
        {['all', 'ALLOW', 'BLOCK', 'HITL', 'MONITOR'].map(f => (
          <button
            key={f}
            onClick={() => setFilter(f)}
            className={`px-3 py-1 text-[11px] rounded font-medium uppercase tracking-wider transition-colors ${
              filter === f ? 'bg-sky-500/15 border border-sky-500/30 text-sky-300' : 'text-zinc-500 hover:text-zinc-300'
            }`}
          >
            {f}
          </button>
        ))}
      </div>

      {/* Live Feed */}
      <div ref={feedRef} className="space-y-1.5 max-h-[600px] overflow-y-auto pr-1">
        {filtered.map((evt, i) => {
          const DecIcon = DECISION_ICONS[evt.decision] || Activity;
          const isNew = i === 0 && !paused;
          return (
            <div
              key={evt.event_id}
              className={`flex items-start gap-3 p-3 rounded-lg border transition-all ${
                isNew
                  ? 'bg-sky-500/5 border-sky-500/20 animate-pulse-slow'
                  : 'bg-zinc-900/30 border-zinc-800/40 hover:border-zinc-700/50'
              }`}
            >
              <DecIcon size={14} className={`mt-0.5 flex-shrink-0 ${DECISION_COLORS[evt.decision] || 'text-zinc-400'}`} />
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="text-xs font-mono text-zinc-300 truncate">{evt.tool || 'unknown_tool'}</span>
                  <DecisionBadge decision={evt.decision as any} />
                  {evt.agent_id && (
                    <span className="text-[10px] text-zinc-500 bg-zinc-800/60 px-2 py-0.5 rounded font-mono">{evt.agent_id}</span>
                  )}
                </div>
                {evt.action && (
                  <div className="text-[11px] text-zinc-500 mt-0.5 truncate">{evt.action}</div>
                )}
              </div>
              <div className="text-[10px] text-zinc-600 font-mono flex-shrink-0">
                {new Date(evt.timestamp).toLocaleTimeString()}
              </div>
            </div>
          );
        })}
      </div>

      {/* Terminal-style footer */}
      <div className="rounded-lg bg-black/40 border border-zinc-800/50 p-3 flex items-center gap-2">
        <Terminal size={12} className="text-emerald-400" />
        <span className="font-mono text-[11px] text-emerald-400">
          agentguard stream --follow --format json &gt; /var/log/agentguard/live.jsonl
        </span>
        <div className="flex-1" />
        <span className="text-[10px] text-zinc-600 font-mono">{events.length} events buffered</span>
      </div>
    </div>
  );
}
