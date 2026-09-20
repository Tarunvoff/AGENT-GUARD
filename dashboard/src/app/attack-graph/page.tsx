'use client';

import { useCallback, useState } from 'react';
import ReactFlow, {
  Background, Controls, MiniMap, useNodesState, useEdgesState,
  Node, Edge, NodeProps, Handle, Position, BackgroundVariant,
} from 'reactflow';
import 'reactflow/dist/style.css';
import { ATTACK_FLOW_NODES, ATTACK_FLOW_EDGES } from '@/data/demo';
import { DecisionBadge, TrustBadge, TaintBadge } from '@/components/ui/security';
import { SectionHeader } from '@/components/ui/security';
import { Shield, Network, ZoomIn, ZoomOut, Maximize2 } from 'lucide-react';
import type { TrustLevel, TaintState } from '@/types';

// ─── Custom Node Types ────────────────────────────────────────────────────

function GraphNode({ data }: NodeProps) {
  const statusConfig: Record<string, { border: string; bg: string; dot: string; label: string }> = {
    ok: { border: 'border-emerald-500/40', bg: 'bg-emerald-500/5', dot: 'bg-emerald-400', label: 'OK' },
    warn: { border: 'border-amber-500/40', bg: 'bg-amber-500/5', dot: 'bg-amber-400', label: 'WARN' },
    danger: { border: 'border-red-500/50', bg: 'bg-red-500/10', dot: 'bg-red-400', label: 'RISK' },
    blocked: { border: 'border-red-600/60', bg: 'bg-red-500/15', dot: 'bg-red-500', label: 'BLOCKED' },
    block: { border: 'border-red-500/50', bg: 'bg-red-500/10', dot: 'bg-red-400', label: 'BLOCK' },
    protected: { border: 'border-emerald-500/40', bg: 'bg-emerald-500/5', dot: 'bg-emerald-400', label: 'PROTECTED' },
  };

  const typeIcon: Record<string, string> = {
    user: '👤', agent: '🤖', task: '📋', tool: '🔧',
    resource: '🗄️', mcp: '🔌', context: '📄', policy: '⚖️', decision: '✅',
  };

  const conf = statusConfig[data.status] ?? statusConfig.ok;

  return (
    <div className={`
      relative px-3 py-2 rounded-xl border backdrop-blur-sm min-w-[140px] max-w-[180px]
      transition-all duration-200 cursor-pointer hover:scale-105
      ${conf.border} ${conf.bg}
      ${data.status === 'blocked' ? 'glow-red shadow-xl' : ''}
      ${data.status === 'ok' ? 'glow-emerald' : ''}
    `}>
      <Handle type="target" position={Position.Top} style={{ background: '#374151', border: 'none', width: 6, height: 6 }} />

      {/* Status dot */}
      <div className={`absolute top-2 right-2 w-2 h-2 rounded-full ${conf.dot} ${data.status !== 'blocked' ? 'animate-pulse' : ''}`} />

      {/* Content */}
      <div className="flex items-center gap-1.5 mb-1">
        <span className="text-sm">{typeIcon[data.type] ?? '●'}</span>
        <span className="text-[11px] font-semibold text-zinc-200 truncate">{data.label}</span>
      </div>

      <div className="flex flex-wrap gap-1">
        {data.trust && (
          <span className={`text-[9px] px-1 py-0.5 rounded border font-medium uppercase ${
            data.trust === 'high' ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-400' :
            data.trust === 'medium' ? 'border-sky-500/30 bg-sky-500/10 text-sky-400' :
            data.trust === 'untrusted' ? 'border-red-500/30 bg-red-500/10 text-red-400' :
            'border-zinc-700 text-zinc-500'
          }`}>
            {data.trust}
          </span>
        )}
        {data.taint === 'TAINTED' && (
          <span className="text-[9px] px-1 py-0.5 rounded border border-red-500/30 bg-red-500/10 text-red-400 font-bold">
            TAINTED
          </span>
        )}
        {data.status === 'blocked' && (
          <span className="text-[9px] px-1 py-0.5 rounded border border-red-600/40 bg-red-500/20 text-red-300 font-bold">
            BLOCKED
          </span>
        )}
        {data.status === 'block' && (
          <span className="text-[9px] px-1 py-0.5 rounded border border-red-500/40 bg-red-500/15 text-red-300 font-bold">
            BLOCK
          </span>
        )}
        {data.sensitivity === 'CRITICAL' && (
          <span className="text-[9px] px-1 py-0.5 rounded border border-red-500/30 bg-red-500/10 text-red-400 font-bold">
            CRITICAL
          </span>
        )}
      </div>

      <Handle type="source" position={Position.Bottom} style={{ background: '#374151', border: 'none', width: 6, height: 6 }} />
    </div>
  );
}

const nodeTypes = { graphNode: GraphNode };

// ─── Attack Graph Page ────────────────────────────────────────────────────

export default function AttackGraphPage() {
  const [nodes, , onNodesChange] = useNodesState<any>(
    ATTACK_FLOW_NODES.map(n => ({ ...n, type: 'graphNode' }))
  );
  const [edges, , onEdgesChange] = useEdgesState<any>(
    ATTACK_FLOW_EDGES.map(e => ({
      ...e,
      style: {
        stroke: e.animated ? '#ef4444' : '#374151',
        strokeWidth: e.animated ? 2 : 1.5,
      },
      labelStyle: { fill: '#9ca3af', fontSize: 10 },
      labelBgStyle: { fill: '#111827', fillOpacity: 0.8 },
      animated: e.animated,
      markerEnd: { type: 'arrowclosed' as any, color: e.animated ? '#ef4444' : '#374151' },
    }))
  );
  const [selected, setSelected] = useState<any | null>(null);

  return (
    <div className="h-screen flex flex-col bg-[#090d16]">
      {/* Header */}
      <div className="px-6 py-4 border-b border-zinc-800/50 flex items-center justify-between">
        <div>
          <h1 className="text-lg font-bold text-white flex items-center gap-2">
            <Network size={18} className="text-red-400" />
            Attack Graph
          </h1>
          <p className="text-xs text-zinc-500 mt-0.5">
            Indirect Prompt Injection — tainted context propagation chain
          </p>
        </div>

        <div className="flex items-center gap-3">
          {/* Legend */}
          <div className="flex items-center gap-3 text-[10px]">
            {[
              { color: '#10b981', label: 'Authorized' },
              { color: '#f59e0b', label: 'Delegated' },
              { color: '#ef4444', label: 'Tainted / Blocked' },
              { color: '#374151', label: 'Standard' },
            ].map(({ color, label }) => (
              <div key={label} className="flex items-center gap-1">
                <div className="w-4 h-0.5 rounded" style={{ background: color }} />
                <span className="text-zinc-500">{label}</span>
              </div>
            ))}
          </div>

          <div className="px-3 py-1.5 rounded-lg bg-red-500/10 border border-red-500/30 text-xs text-red-300 flex items-center gap-1.5">
            <Shield size={12} />
            BLOCK — 0 sensitive DB calls
          </div>
        </div>
      </div>

      {/* Main graph area */}
      <div className="flex-1 flex">
        <div className="flex-1">
          <ReactFlow
            nodes={nodes}
            edges={edges}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            nodeTypes={nodeTypes}
            onNodeClick={(_, node) => setSelected(node)}
            fitView
            fitViewOptions={{ padding: 0.3 }}
            proOptions={{ hideAttribution: true }}
          >
            <Background variant={BackgroundVariant.Dots} color="#1f2937" gap={20} size={1} />
            <Controls showInteractive={false} />
            <MiniMap
              nodeColor={(n) => {
                const d = n.data as any;
                if (d.status === 'blocked') return '#ef4444';
                if (d.status === 'danger' || d.taint === 'TAINTED') return '#f97316';
                if (d.trust === 'untrusted') return '#dc2626';
                return '#374151';
              }}
              maskColor="rgba(9, 13, 22, 0.8)"
            />
          </ReactFlow>
        </div>

        {/* Detail Panel */}
        {selected && (
          <div className="w-72 border-l border-zinc-800/50 bg-zinc-900/60 p-4 overflow-y-auto">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-sm font-semibold text-zinc-200">Node Details</h3>
              <button onClick={() => setSelected(null)} className="text-zinc-600 hover:text-zinc-400 text-lg">×</button>
            </div>
            <NodeDetailPanel node={selected} />
          </div>
        )}
      </div>

      {/* Attack explanation bottom bar */}
      <div className="border-t border-zinc-800/50 px-6 py-3 bg-zinc-900/40">
        <div className="flex items-center gap-6 text-[11px]">
          <div className="flex items-center gap-2">
            <div className="w-2 h-2 rounded-full bg-red-400 animate-pulse" />
            <span className="text-zinc-400">Attack path: <span className="text-red-300">User → Planner → Research → External MCP → Tainted Context → Analysis → DataAgent → customer_db_read → POLICY → <span className="font-bold text-red-400">BLOCK</span></span></span>
          </div>
          <div className="ml-auto flex items-center gap-2 text-emerald-400">
            <Shield size={11} />
            Sensitive DB calls: 0 — PII vault protected
          </div>
        </div>
      </div>
    </div>
  );
}

function NodeDetailPanel({ node }: { node: Node }) {
  const d = node.data as any;
  return (
    <div className="space-y-3 text-xs">
      <div className="rounded-lg bg-zinc-800/40 p-3 space-y-2">
        <div className="flex justify-between">
          <span className="text-zinc-500">ID</span>
          <span className="font-mono text-zinc-300">{node.id}</span>
        </div>
        <div className="flex justify-between">
          <span className="text-zinc-500">Type</span>
          <span className="text-zinc-300 capitalize">{d.type}</span>
        </div>
        {d.trust && (
          <div className="flex justify-between items-center">
            <span className="text-zinc-500">Trust</span>
            <TrustBadge level={d.trust} />
          </div>
        )}
        {d.taint && (
          <div className="flex justify-between items-center">
            <span className="text-zinc-500">Taint</span>
            <TaintBadge state={d.taint} />
          </div>
        )}
        {d.sensitivity && (
          <div className="flex justify-between">
            <span className="text-zinc-500">Sensitivity</span>
            <span className="text-red-400 font-semibold">{d.sensitivity}</span>
          </div>
        )}
        {d.status && (
          <div className="flex justify-between">
            <span className="text-zinc-500">Status</span>
            <span className={`font-semibold ${
              d.status === 'blocked' ? 'text-red-400' :
              d.status === 'ok' ? 'text-emerald-400' : 'text-amber-400'
            }`}>{d.status.toUpperCase()}</span>
          </div>
        )}
      </div>

      {d.status === 'blocked' && (
        <div className="rounded-lg bg-red-500/10 border border-red-500/20 p-3">
          <div className="text-[10px] font-semibold text-red-400 mb-1">BLOCKED</div>
          <div className="text-[10px] text-red-300/70">
            Tainted context reached CRITICAL resource. Deterministic policy enforced BLOCK.
            Tool NOT executed. Sensitive DB calls: 0.
          </div>
        </div>
      )}

      {d.type === 'mcp' && (
        <div className="rounded-lg bg-amber-500/5 border border-amber-500/20 p-3">
          <div className="text-[10px] font-semibold text-amber-400 mb-1">UNTRUSTED SOURCE</div>
          <div className="text-[10px] text-amber-300/70">
            External MCP server injected malicious prompt content into agent context, causing TAINTED propagation.
          </div>
        </div>
      )}
    </div>
  );
}
