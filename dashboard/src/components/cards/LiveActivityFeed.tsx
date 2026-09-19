'use client';

import { useState, useEffect, useRef } from 'react';
import { subscribeToEventStream } from '@/services/api';
import type { SecurityEvent } from '@/types';
import { DecisionBadge, TaintBadge } from '@/components/ui/security';
import { formatTimestamp, formatRelative } from '@/lib/colors';
import { Activity, Dot } from 'lucide-react';
import { DEMO_EVENTS } from '@/data/demo';

const MAX_EVENTS = 80;

export default function LiveActivityFeed() {
  const [events, setEvents] = useState<SecurityEvent[]>([...DEMO_EVENTS]);
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const unsub = subscribeToEventStream((event) => {
      setEvents(prev => [event, ...prev].slice(0, MAX_EVENTS));
    });
    return unsub;
  }, []);

  return (
    <div className="h-full flex flex-col">
      <div className="flex items-center gap-2 mb-3">
        <div className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
        <span className="text-xs font-semibold text-zinc-300 uppercase tracking-wider">Live Security Stream</span>
        <span className="text-[10px] text-zinc-600 ml-auto">{events.length} events</span>
      </div>
      <div className="flex-1 overflow-y-auto space-y-1 scrollbar-thin scrollbar-thumb-zinc-800">
        {events.map((event) => (
          <LiveEventRow key={event.event_id} event={event} />
        ))}
        <div ref={bottomRef} />
      </div>
    </div>
  );
}

function LiveEventRow({ event }: { event: SecurityEvent }) {
  const isBlock = event.decision === 'BLOCK';
  const isCritical = event.risk_level === 'CRITICAL';

  return (
    <div className={`
      flex items-start gap-2 p-2 rounded-lg text-xs cursor-pointer
      transition-all duration-150 hover:bg-zinc-800/40 group border
      ${isCritical && isBlock
        ? 'border-red-500/20 bg-red-500/5'
        : 'border-transparent hover:border-zinc-800/60'
      }
    `}>
      <div className="flex-shrink-0 mt-0.5">
        <div className={`w-1.5 h-1.5 rounded-full mt-1 ${
          isBlock ? 'bg-red-400' :
          event.decision === 'ALLOW' ? 'bg-emerald-400' :
          event.decision === 'HITL' ? 'bg-amber-400' :
          'bg-sky-400'
        }`} />
      </div>
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-1.5 mb-0.5">
          <span className="font-mono text-zinc-600 text-[10px]">{formatTimestamp(event.timestamp)}</span>
          {event.trace_id && (
            <span className="font-mono text-[10px] text-zinc-700">{event.trace_id.slice(0, 12)}</span>
          )}
        </div>
        <div className="text-zinc-300 leading-relaxed">{event.summary}</div>
        <div className="flex items-center gap-1.5 mt-1 flex-wrap">
          {event.decision && <DecisionBadge decision={event.decision} />}
          {event.taint_state && event.taint_state !== 'CLEAN' && <TaintBadge state={event.taint_state} />}
          {event.agent_id && (
            <span className="text-[10px] px-1.5 py-0.5 rounded bg-zinc-800/60 text-zinc-500 font-mono">
              {event.agent_id}
            </span>
          )}
        </div>
      </div>
    </div>
  );
}
