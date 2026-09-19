'use client';

import { useState } from 'react';
import { DEMO_INCIDENTS } from '@/data/demo';
import { SeverityBadge, DecisionBadge, EmptyState, SectionHeader } from '@/components/ui/security';
import { AlertTriangle, CheckCircle2, Clock, ArrowRight } from 'lucide-react';
import { formatRelative } from '@/lib/colors';
import Link from 'next/link';

export default function IncidentsPage() {
  const [filter, setFilter] = useState<string>('all');
  const incidents = DEMO_INCIDENTS.filter(i =>
    filter === 'all' || i.severity === filter || i.status === filter
  );

  return (
    <div className="p-6 space-y-5 min-h-screen bg-[#090d16]">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-xl font-bold text-white flex items-center gap-2">
            <AlertTriangle size={18} className="text-orange-400" />
            Incidents
          </h1>
          <p className="text-sm text-zinc-500 mt-1">Security incidents with evidence, root cause, and remediation status</p>
        </div>
        <div className="text-sm text-zinc-500">
          <span className="text-red-400 font-bold">{DEMO_INCIDENTS.filter(i => i.status === 'ACTIVE').length}</span> active,{' '}
          <span className="text-zinc-200 font-bold">{DEMO_INCIDENTS.length}</span> total
        </div>
      </div>

      {/* Filters */}
      <div className="flex gap-2">
        {['all', 'CRITICAL', 'HIGH', 'MEDIUM', 'ACTIVE', 'CONTAINED', 'RESOLVED'].map(f => (
          <button key={f} onClick={() => setFilter(f)}
            className={`px-2.5 py-1 text-[11px] rounded font-medium uppercase tracking-wider transition-colors ${
              filter === f ? 'bg-sky-500/15 border border-sky-500/30 text-sky-300' : 'text-zinc-500 hover:text-zinc-300'
            }`}>
            {f}
          </button>
        ))}
      </div>

      <div className="space-y-3">
        {incidents.map(incident => (
          <div key={incident.incident_id}
            className={`rounded-xl border p-4 bg-zinc-900/40 transition-all hover:border-zinc-700/60 cursor-pointer ${
              incident.severity === 'CRITICAL' ? 'border-red-500/30 shadow-lg shadow-red-500/5' :
              incident.severity === 'HIGH' ? 'border-orange-500/20' : 'border-zinc-800/50'
            }`}>
            <div className="flex items-start justify-between">
              <div className="flex items-start gap-3">
                <div className={`w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0 ${
                  incident.severity === 'CRITICAL' ? 'bg-red-500/10' : 'bg-orange-500/10'
                }`}>
                  <AlertTriangle size={14} className={incident.severity === 'CRITICAL' ? 'text-red-400' : 'text-orange-400'} />
                </div>
                <div>
                  <div className="flex items-center gap-2 mb-1">
                    <SeverityBadge severity={incident.severity} />
                    <span className="text-xs font-mono text-zinc-500">{incident.incident_id}</span>
                    <span className={`text-[10px] px-1.5 py-0.5 rounded border font-medium ${
                      incident.status === 'CONTAINED' ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-400' :
                      incident.status === 'RESOLVED' ? 'border-sky-500/30 bg-sky-500/10 text-sky-400' :
                      'border-red-500/30 bg-red-500/10 text-red-400'
                    }`}>{incident.status}</span>
                  </div>
                  <div className="text-sm font-medium text-zinc-200 mb-1">{incident.incident_type.replace(/_/g, ' ')}</div>
                  <div className="text-xs text-zinc-500 leading-relaxed max-w-2xl">{incident.description}</div>
                  <div className="flex items-center gap-3 mt-2 text-[10px] text-zinc-600">
                    {incident.agent_id && <span>Agent: <span className="font-mono text-zinc-500">{incident.agent_id}</span></span>}
                    {incident.tool_name && <span>Tool: <span className="font-mono text-zinc-500">{incident.tool_name}</span></span>}
                    {incident.resource_name && <span>Resource: <span className="font-mono text-zinc-500">{incident.resource_name}</span></span>}
                    <span>{formatRelative(incident.timestamp)}</span>
                  </div>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <DecisionBadge decision={incident.decision} />
                <div className={`text-xs font-semibold ${incident.executed ? 'text-red-400' : 'text-emerald-400'}`}>
                  {incident.executed ? 'EXECUTED' : 'NOT EXECUTED'}
                </div>
              </div>
            </div>

            <div className="flex items-center gap-2 mt-3 pt-3 border-t border-zinc-800/40">
              <Link href="/forensics" className="text-[11px] text-sky-400 hover:text-sky-300 flex items-center gap-1">
                Open Forensics <ArrowRight size={10} />
              </Link>
              <Link href="/attack-graph" className="text-[11px] text-sky-400 hover:text-sky-300 flex items-center gap-1">
                Attack Graph <ArrowRight size={10} />
              </Link>
              {incident.trace_id && (
                <Link href="/traces" className="text-[11px] text-sky-400 hover:text-sky-300 flex items-center gap-1">
                  Trace <ArrowRight size={10} />
                </Link>
              )}
            </div>
          </div>
        ))}

        {incidents.length === 0 && (
          <EmptyState
            icon={CheckCircle2}
            title="No active incidents"
            description="No incidents match your filter criteria. The system is operating normally."
            positive
          />
        )}
      </div>
    </div>
  );
}
