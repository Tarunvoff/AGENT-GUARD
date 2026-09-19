'use client';

import { useState } from 'react';
import { Eye, GitBranch, Brain, Shield, ArrowRight, ChevronRight } from 'lucide-react';

type Stage = 'OBSERVE' | 'CORRELATE' | 'ANALYZE' | 'ENFORCE';

const STAGES: { id: Stage; label: string; icon: React.ElementType; color: string; glow: string; description: string; items: string[] }[] = [
  {
    id: 'OBSERVE',
    label: 'OBSERVE',
    icon: Eye,
    color: 'from-sky-500 to-indigo-600',
    glow: 'shadow-sky-500/20',
    description: 'Causal observation across all agent system boundaries',
    items: ['Agent identity', 'Task intent', 'Trace correlation', 'Tool calls', 'Context creation', 'MCP requests', 'API calls', 'Resource access'],
  },
  {
    id: 'CORRELATE',
    label: 'CORRELATE',
    icon: GitBranch,
    color: 'from-violet-500 to-purple-600',
    glow: 'shadow-violet-500/20',
    description: 'Causal graph construction from observed events',
    items: ['Delegation chains', 'Context propagation', 'Taint tracking', 'Provenance', 'Intent alignment', 'Authority lineage'],
  },
  {
    id: 'ANALYZE',
    label: 'ANALYZE',
    icon: Brain,
    color: 'from-amber-500 to-orange-600',
    glow: 'shadow-amber-500/20',
    description: 'AI-powered threat analysis — advisory, not enforcement',
    items: ['AI Secura — threat detection', 'APIRIS — tool intelligence', 'Risk scoring', 'Intent classification', 'Authority assessment', 'Attack type identification'],
  },
  {
    id: 'ENFORCE',
    label: 'ENFORCE',
    icon: Shield,
    color: 'from-emerald-500 to-green-600',
    glow: 'shadow-emerald-500/20',
    description: 'Deterministic policy engine — final enforcement authority',
    items: ['ALLOW', 'HITL (Human-in-the-loop)', 'BLOCK', 'REVOKE', 'Evidence generation', 'Causal explanation'],
  },
];

export default function MantaFlow() {
  const [active, setActive] = useState<Stage | null>(null);

  return (
    <div className="rounded-xl border border-zinc-800/50 bg-zinc-900/30 p-5">
      <div className="flex items-center justify-between mb-4">
        <div>
          <h2 className="text-sm font-semibold text-zinc-200">4 MANTA — Security Intelligence Loop</h2>
          <p className="text-[11px] text-zinc-500 mt-0.5">Click any stage to inspect</p>
        </div>
        <div className="text-[10px] text-zinc-600 font-mono uppercase tracking-widest">
          OBSERVE → CORRELATE → ANALYZE → ENFORCE
        </div>
      </div>

      <div className="flex items-stretch gap-3">
        {STAGES.map((stage, i) => {
          const Icon = stage.icon;
          const isActive = active === stage.id;
          return (
            <div key={stage.id} className="flex items-center gap-2 flex-1">
              <button
                onClick={() => setActive(isActive ? null : stage.id)}
                className={`
                  flex-1 rounded-xl border p-4 text-left cursor-pointer transition-all duration-200
                  ${isActive
                    ? `border-transparent bg-gradient-to-br ${stage.color} shadow-lg ${stage.glow}`
                    : 'border-zinc-800/60 bg-zinc-900/40 hover:border-zinc-700/60 hover:bg-zinc-800/30'
                  }
                `}
              >
                <div className={`w-8 h-8 rounded-lg flex items-center justify-center mb-3 ${
                  isActive
                    ? 'bg-white/20'
                    : `bg-gradient-to-br ${stage.color} opacity-70`
                }`}>
                  <Icon size={16} className="text-white" />
                </div>
                <div className={`text-xs font-bold tracking-widest uppercase mb-1 ${isActive ? 'text-white' : 'text-zinc-300'}`}>
                  {stage.label}
                </div>
                <div className={`text-[10px] leading-relaxed ${isActive ? 'text-white/80' : 'text-zinc-600'}`}>
                  {stage.description}
                </div>
                {isActive && (
                  <ul className="mt-3 space-y-1">
                    {stage.items.map(item => (
                      <li key={item} className="flex items-center gap-1.5 text-[10px] text-white/70">
                        <ChevronRight size={8} />
                        {item}
                      </li>
                    ))}
                  </ul>
                )}
              </button>
              {i < STAGES.length - 1 && (
                <ArrowRight size={14} className="text-zinc-700 flex-shrink-0" />
              )}
            </div>
          );
        })}
      </div>

      {/* AI vs Deterministic notice */}
      <div className="mt-4 grid grid-cols-2 gap-3">
        <div className="rounded-lg bg-amber-500/5 border border-amber-500/20 px-3 py-2 flex items-center gap-2">
          <Brain size={12} className="text-amber-400 flex-shrink-0" />
          <div className="text-[10px] text-amber-300">
            <span className="font-semibold">AI RECOMMENDATION</span>
            {' — '}AI Secura + APIRIS provide analysis. This is advisory.
          </div>
        </div>
        <div className="rounded-lg bg-emerald-500/5 border border-emerald-500/20 px-3 py-2 flex items-center gap-2">
          <Shield size={12} className="text-emerald-400 flex-shrink-0" />
          <div className="text-[10px] text-emerald-300">
            <span className="font-semibold">DETERMINISTIC POLICY DECISION</span>
            {' — '}The Policy Engine is the sole enforcement authority.
          </div>
        </div>
      </div>
    </div>
  );
}
