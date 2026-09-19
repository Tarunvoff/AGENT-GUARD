'use client';

import { useState } from 'react';
import { DEMO_TASKS } from '@/data/demo';
import { DecisionBadge, TrustBadge, SeverityBadge } from '@/components/ui/security';
import { CheckSquare, Clock, CheckCircle2, XCircle, AlertTriangle, ArrowRight, GitBranch } from 'lucide-react';
import Link from 'next/link';

const STATUS_COLORS: Record<string, string> = {
  COMPLETED: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20',
  IN_PROGRESS: 'text-sky-400 bg-sky-500/10 border-sky-500/20',
  PENDING: 'text-amber-400 bg-amber-500/10 border-amber-500/20',
  BLOCKED: 'text-red-400 bg-red-500/10 border-red-500/20',
  FAILED: 'text-red-400 bg-red-500/10 border-red-500/20',
};

const STATUS_ICONS: Record<string, React.ElementType> = {
  COMPLETED: CheckCircle2,
  IN_PROGRESS: Clock,
  PENDING: Clock,
  BLOCKED: AlertTriangle,
  FAILED: XCircle,
};

export default function TasksPage() {
  const [filter, setFilter] = useState('all');

  const tasks = DEMO_TASKS || [
    {
      task_id: 'task_001', agent_id: 'orchestrator_v2', description: 'Analyze Q3 financial reports and generate summary', status: 'COMPLETED',
      started_at: '2026-09-19T08:00:00Z', completed_at: '2026-09-19T08:05:32Z', actions_taken: 12, actions_blocked: 0,
      tool_calls: ['read_file', 'query_db', 'generate_summary'], delegated_to: ['analyst_agent'],
    },
    {
      task_id: 'task_002', agent_id: 'data_agent', description: 'Export customer PII to external S3 bucket', status: 'BLOCKED',
      started_at: '2026-09-19T09:11:00Z', completed_at: null, actions_taken: 3, actions_blocked: 1,
      tool_calls: ['read_db', 'upload_s3'], delegated_to: [],
    },
    {
      task_id: 'task_003', agent_id: 'orchestrator_v2', description: 'Generate weekly security posture report', status: 'IN_PROGRESS',
      started_at: '2026-09-19T11:00:00Z', completed_at: null, actions_taken: 7, actions_blocked: 0,
      tool_calls: ['query_logs', 'aggregate_metrics', 'format_report'], delegated_to: ['report_agent'],
    },
    {
      task_id: 'task_004', agent_id: 'escalation_agent', description: 'Escalate billing dispute to supervisor with customer data', status: 'BLOCKED',
      started_at: '2026-09-19T10:30:00Z', completed_at: null, actions_taken: 2, actions_blocked: 2,
      tool_calls: ['read_customer', 'send_email'], delegated_to: [],
    },
    {
      task_id: 'task_005', agent_id: 'report_agent', description: 'Compile monthly compliance audit log', status: 'COMPLETED',
      started_at: '2026-09-19T07:00:00Z', completed_at: '2026-09-19T07:22:11Z', actions_taken: 34, actions_blocked: 0,
      tool_calls: ['read_audit_log', 'validate_policies', 'export_pdf'], delegated_to: [],
    },
    {
      task_id: 'task_006', agent_id: 'data_agent', description: 'Sync internal user preferences database', status: 'COMPLETED',
      started_at: '2026-09-19T06:00:00Z', completed_at: '2026-09-19T06:04:55Z', actions_taken: 8, actions_blocked: 0,
      tool_calls: ['read_prefs', 'write_prefs'], delegated_to: [],
    },
  ];

  const filtered = filter === 'all' ? tasks : tasks.filter(t => t.status === filter);

  const counts = {
    total: tasks.length,
    COMPLETED: tasks.filter(t => t.status === 'COMPLETED').length,
    IN_PROGRESS: tasks.filter(t => t.status === 'IN_PROGRESS').length,
    BLOCKED: tasks.filter(t => t.status === 'BLOCKED').length,
  };

  return (
    <div className="p-6 space-y-5 min-h-screen bg-[#090d16]">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-white flex items-center gap-2">
            <CheckSquare size={18} className="text-sky-400" />
            Tasks
          </h1>
          <p className="text-sm text-zinc-500 mt-1">Agent task execution with authority tracking and block evidence</p>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-4 gap-3">
        {[
          { label: 'Total Tasks', value: counts.total, color: 'text-zinc-200', border: 'border-zinc-700/30', bg: 'bg-zinc-800/40' },
          { label: 'Completed', value: counts.COMPLETED, color: 'text-emerald-400', border: 'border-emerald-500/20', bg: 'bg-emerald-500/5' },
          { label: 'In Progress', value: counts.IN_PROGRESS, color: 'text-sky-400', border: 'border-sky-500/20', bg: 'bg-sky-500/5' },
          { label: 'Blocked', value: counts.BLOCKED, color: 'text-red-400', border: 'border-red-500/20', bg: 'bg-red-500/5' },
        ].map(s => (
          <div key={s.label} className={`rounded-xl border ${s.border} ${s.bg} p-4 text-center`}>
            <div className="text-[10px] text-zinc-500 uppercase tracking-wider mb-1">{s.label}</div>
            <div className={`text-2xl font-bold font-mono ${s.color}`}>{s.value}</div>
          </div>
        ))}
      </div>

      {/* Filters */}
      <div className="flex gap-2">
        {['all', 'COMPLETED', 'IN_PROGRESS', 'BLOCKED', 'PENDING'].map(f => (
          <button key={f} onClick={() => setFilter(f)}
            className={`px-2.5 py-1 text-[11px] rounded font-medium uppercase tracking-wider transition-colors ${
              filter === f ? 'bg-sky-500/15 border border-sky-500/30 text-sky-300' : 'text-zinc-500 hover:text-zinc-300'
            }`}>
            {f}
          </button>
        ))}
      </div>

      {/* Task List */}
      <div className="space-y-3">
        {filtered.map(task => {
          const StatusIcon = STATUS_ICONS[task.status] || Clock;
          const statusClass = STATUS_COLORS[task.status] || 'text-zinc-400 bg-zinc-800/40 border-zinc-700/30';
          return (
            <div key={task.task_id} className="rounded-xl border border-zinc-800/50 bg-zinc-900/30 p-4 hover:border-zinc-700/50 transition-colors">
              <div className="flex items-start gap-3">
                <StatusIcon size={16} className={statusClass.split(' ')[0] + ' mt-0.5 flex-shrink-0'} />
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-3 flex-wrap mb-1.5">
                    <span className="font-mono text-[10px] text-zinc-500">{task.task_id}</span>
                    <span className={`text-[10px] font-semibold px-1.5 py-0.5 rounded border ${statusClass}`}>
                      {task.status}
                    </span>
                    <span className="text-xs text-zinc-400 font-mono bg-zinc-800/60 px-2 py-0.5 rounded">{task.agent_id}</span>
                  </div>
                  <p className="text-sm text-zinc-200 mb-2">{task.description}</p>
                  <div className="flex items-center gap-4 text-xs text-zinc-500">
                    <span>{task.actions_taken} actions</span>
                    {task.actions_blocked > 0 && (
                      <span className="text-red-400 font-semibold">{task.actions_blocked} blocked</span>
                    )}
                    {task.tool_calls && (
                      <span>{task.tool_calls.length} tools</span>
                    )}
                    {task.delegated_to && task.delegated_to.length > 0 && (
                      <span className="flex items-center gap-1">
                        <GitBranch size={10} />
                        delegated to {task.delegated_to.join(', ')}
                      </span>
                    )}
                    <span className="ml-auto font-mono text-zinc-600">
                      {new Date(task.started_at).toLocaleTimeString()}
                    </span>
                  </div>
                  {task.tool_calls && (
                    <div className="flex gap-1.5 mt-2 flex-wrap">
                      {task.tool_calls.map((t: string) => (
                        <span key={t} className="font-mono text-[10px] px-1.5 py-0.5 rounded bg-zinc-800/60 text-zinc-400">{t}</span>
                      ))}
                    </div>
                  )}
                </div>
                {task.status === 'BLOCKED' && (
                  <Link href="/forensics" className="flex-shrink-0 flex items-center gap-1 text-[11px] text-sky-400 hover:text-sky-300 transition-colors">
                    Investigate <ArrowRight size={11} />
                  </Link>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
