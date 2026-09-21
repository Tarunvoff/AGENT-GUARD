'use client';

import { useCallback, useState } from 'react';
import ReactFlow, {
  Background, Controls, MiniMap, useNodesState, useEdgesState,
  Node, Edge, NodeProps, Handle, Position, BackgroundVariant,
} from 'reactflow';
import 'reactflow/dist/style.css';
import { ATTACK_FLOW_NODES, ATTACK_FLOW_EDGES } from '@/data/demo';
import { PageHeader } from '@/components/ui/PageHeader';
import { StatusBadge } from '@/components/ui/StatusBadge';
import { Shield, Network, ZoomIn, ZoomOut, Maximize2, AlertTriangle, CheckCircle2, Lock } from 'lucide-react';

// ─── Custom Light Enterprise Node ─────────────────────────────────────────

function GraphNode({ data }: NodeProps) {
  const isBlocked = data.status === 'blocked' || data.status === 'block';

  return (
    <div className={`
      px-3.5 py-2.5 rounded-lg border bg-white shadow-xs min-w-[150px] max-w-[190px]
      transition-all duration-150 cursor-pointer hover:shadow-md
      ${isBlocked ? 'border-red-400 bg-red-50/40 ring-2 ring-red-200' : 'border-slate-200 hover:border-slate-300'}
    `}>
      <Handle type="target" position={Position.Top} style={{ background: '#94a3b8', border: 'none', width: 6, height: 6 }} />

      <div className="flex items-center justify-between mb-1.5">
        <span className="text-xs font-semibold text-slate-900 truncate">{data.label}</span>
        {isBlocked ? (
          <span className="w-2 h-2 rounded-full bg-red-600" />
        ) : (
          <span className="w-2 h-2 rounded-full bg-emerald-600" />
        )}
      </div>

      <div className="flex flex-wrap gap-1">
        {data.trust && (
          <span className={`text-[10px] font-mono px-1.5 py-0.2 rounded border ${
            data.trust === 'high' ? 'bg-emerald-50 text-emerald-800 border-emerald-200' :
            data.trust === 'untrusted' ? 'bg-red-50 text-red-800 border-red-200 font-bold' :
            'bg-slate-100 text-slate-700 border-slate-200'
          }`}>
            {data.trust}
          </span>
        )}
        {data.taint === 'TAINTED' && (
          <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-amber-50 text-amber-800 border-amber-200 font-bold">
            TAINTED
          </span>
        )}
        {isBlocked && (
          <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-red-100 text-red-800 border-red-300 font-bold">
            BLOCKED
          </span>
        )}
      </div>

      <Handle type="source" position={Position.Bottom} style={{ background: '#94a3b8', border: 'none', width: 6, height: 6 }} />
    </div>
  );
}

const nodeTypes = { graphNode: GraphNode };

export default function AttackGraphPage() {
  const [nodes, , onNodesChange] = useNodesState<any>(
    ATTACK_FLOW_NODES.map(n => ({ ...n, type: 'graphNode' }))
  );
  const [edges, , onEdgesChange] = useEdgesState<any>(
    ATTACK_FLOW_EDGES.map((e: any) => ({
      ...e,
      style: {
        stroke: e.data?.blocked ? '#dc2626' : '#94a3b8',
        strokeWidth: e.data?.blocked ? 2.5 : 1.5,
        strokeDasharray: e.data?.blocked ? '5 5' : undefined,
      },
    }))
  );

  const [selectedNode, setSelectedNode] = useState<any>(null);

  const onNodeClick = useCallback((_: any, node: Node) => {
    setSelectedNode(node.data);
  }, []);

  return (
    <div className="p-8 space-y-6 max-w-7xl mx-auto">
      <PageHeader
        title="Attack Graph & Taint Flow"
        subtitle="Visual directed acyclic graph mapping provenance, untrusted inputs, taint propagation, and policy block points"
        badge="Provenance DAG"
      />

      {/* Graph Area */}
      <div className="bg-white border border-slate-200 rounded-lg shadow-xs overflow-hidden">
        <div className="p-4 border-b border-slate-200 flex items-center justify-between text-xs text-slate-600 bg-slate-50/50">
          <div className="flex items-center gap-4">
            <span className="font-semibold text-slate-900">DAG Legend:</span>
            <div className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-emerald-500" />
              <span>Verified Clean</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-amber-500" />
              <span>Tainted State</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-red-600" />
              <span>Policy Intercept / Block</span>
            </div>
          </div>
          <span className="text-[11px] text-slate-500 font-mono">Scroll to zoom • Drag to pan</span>
        </div>

        <div className="h-[520px] w-full bg-slate-50/30">
          <ReactFlow
            nodes={nodes}
            edges={edges}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            onNodeClick={onNodeClick}
            nodeTypes={nodeTypes}
            fitView
          >
            <Background variant={BackgroundVariant.Dots} gap={16} size={1} color="#cbd5e1" />
            <Controls className="!bg-white !border !border-slate-200 !shadow-xs !rounded-md" />
            <MiniMap
              className="!bg-white !border !border-slate-200 !rounded-md"
              nodeColor={(n: any) => {
                if (n.data?.status === 'blocked') return '#ef4444';
                if (n.data?.taint === 'TAINTED') return '#f59e0b';
                return '#10b981';
              }}
            />
          </ReactFlow>
        </div>
      </div>

      {/* Selected Node Inspector */}
      {selectedNode && (
        <div className="p-4 bg-white border border-slate-200 rounded-lg shadow-xs space-y-2">
          <div className="text-xs font-semibold uppercase tracking-wider text-slate-500">Node Inspector</div>
          <div className="flex items-center justify-between text-xs">
            <div>
              <span className="font-bold text-slate-900 text-sm">{selectedNode.label}</span>
              <span className="text-slate-500 ml-2 font-mono">type: {selectedNode.type}</span>
            </div>
            <div className="flex items-center gap-2">
              {selectedNode.trust && <span className="font-mono text-slate-700 bg-slate-100 px-2 py-0.5 rounded border border-slate-200">{selectedNode.trust}</span>}
              <StatusBadge status={selectedNode.status === 'blocked' ? 'BLOCK' : 'ALLOW'} />
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
