'use client';

import React, { useState, useMemo } from 'react';
import { PageHeader } from '@/components/ui/PageHeader';
import { FilterBar } from '@/components/ui/FilterBar';
import { DataTable, Column } from '@/components/ui/DataTable';
import { DetailDrawer } from '@/components/ui/DetailDrawer';
import { CheckSquare, CheckCircle2, Clock, AlertTriangle, XCircle, User, Wrench, Share2 } from 'lucide-react';

interface TaskItem {
  task_id: string;
  agent_id: string;
  description: string;
  status: 'COMPLETED' | 'IN_PROGRESS' | 'BLOCKED' | 'PENDING' | 'FAILED';
  started_at: string;
  completed_at?: string | null;
  actions_taken: number;
  actions_blocked: number;
  tool_calls: string[];
  delegated_to: string[];
}

const INITIAL_TASKS: TaskItem[] = [
  {
    task_id: 'tsk_8891',
    agent_id: 'orchestrator-001',
    description: 'Coordinate multi-agent quarterly financial report pipeline',
    status: 'COMPLETED',
    started_at: '15:10:00',
    completed_at: '15:15:32',
    actions_taken: 14,
    actions_blocked: 0,
    tool_calls: ['read_file', 'query_db', 'generate_summary'],
    delegated_to: ['research-agent-001', 'analysis-agent-001'],
  },
  {
    task_id: 'tsk_8892',
    agent_id: 'research-agent-001',
    description: 'Perform financial market public query and SEC 10-K search',
    status: 'IN_PROGRESS',
    started_at: '15:16:00',
    completed_at: null,
    actions_taken: 5,
    actions_blocked: 0,
    tool_calls: ['sec_edgar.fetch_filing', 'web_search'],
    delegated_to: [],
  },
  {
    task_id: 'tsk_8893',
    agent_id: 'data-sync-002',
    description: 'Attempt bulk export of customer PII to external cloud endpoint',
    status: 'BLOCKED',
    started_at: '15:18:10',
    completed_at: '15:18:11',
    actions_taken: 1,
    actions_blocked: 1,
    tool_calls: ['customer_db.read', 'http_post'],
    delegated_to: [],
  },
  {
    task_id: 'tsk_8894',
    agent_id: 'analysis-agent-001',
    description: 'Compute risk metrics and render PDF executive summary',
    status: 'COMPLETED',
    started_at: '15:20:00',
    completed_at: '15:22:45',
    actions_taken: 8,
    actions_blocked: 0,
    tool_calls: ['finance_extract', 'pdf_render'],
    delegated_to: [],
  },
];

export default function TasksPage() {
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [selectedTask, setSelectedTask] = useState<TaskItem | null>(INITIAL_TASKS[0]);
  const [isDrawerOpen, setIsDrawerOpen] = useState(false);

  const filteredData = useMemo(() => {
    return INITIAL_TASKS.filter((item) => {
      if (search) {
        const q = search.toLowerCase();
        const match =
          item.task_id.toLowerCase().includes(q) ||
          item.agent_id.toLowerCase().includes(q) ||
          item.description.toLowerCase().includes(q);
        if (!match) return false;
      }
      if (statusFilter !== 'ALL' && item.status !== statusFilter) return false;
      return true;
    });
  }, [search, statusFilter]);

  const columns: Column<TaskItem>[] = [
    {
      key: 'task_id',
      header: 'Task ID',
      mono: true,
      width: '120px',
      render: (row) => (
        <span className="font-semibold text-slate-900 hover:text-sky-700 underline decoration-slate-300">
          {row.task_id}
        </span>
      ),
    },
    {
      key: 'status',
      header: 'Status',
      width: '120px',
      render: (row) => {
        const style =
          row.status === 'COMPLETED'
            ? 'bg-emerald-50 text-emerald-800 border-emerald-200'
            : row.status === 'IN_PROGRESS'
            ? 'bg-blue-50 text-blue-800 border-blue-200'
            : row.status === 'BLOCKED'
            ? 'bg-red-50 text-red-800 border-red-200'
            : 'bg-slate-100 text-slate-700 border-slate-200';
        return (
          <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${style}`}>
            {row.status}
          </span>
        );
      },
    },
    {
      key: 'description',
      header: 'Task Intent & Description',
      render: (row) => <span className="font-medium text-slate-800">{row.description}</span>,
    },
    {
      key: 'agent_id',
      header: 'Bound Agent',
      render: (row) => (
        <span className="font-mono text-[11px] text-slate-800 bg-slate-100 px-1.5 py-0.5 rounded">
          {row.agent_id}
        </span>
      ),
    },
    {
      key: 'actions_taken',
      header: 'Actions Taken',
      align: 'center',
      width: '110px',
      render: (row) => <span className="font-mono text-slate-700">{row.actions_taken}</span>,
    },
    {
      key: 'actions_blocked',
      header: 'Blocked',
      align: 'center',
      width: '90px',
      render: (row) => (
        <span className={`font-mono font-semibold ${row.actions_blocked > 0 ? 'text-red-700' : 'text-slate-400'}`}>
          {row.actions_blocked}
        </span>
      ),
    },
    {
      key: 'started_at',
      header: 'Started',
      mono: true,
      align: 'right',
      width: '90px',
      render: (row) => <span className="text-slate-400">{row.started_at}</span>,
    },
  ];

  return (
    <div className="max-w-[1600px] mx-auto">
      <PageHeader
        title="Agent Tasks"
        description="Active and completed agent task lifecycles, intent bindings, and causal tool invocation telemetry."
        breadcrumbs={[
          { label: 'Operations', href: '/dashboard' },
          { label: 'Tasks' },
        ]}
      />

      <FilterBar
        searchQuery={search}
        onSearchChange={setSearch}
        searchPlaceholder="Search task ID, agent, intent…"
        totalCount={INITIAL_TASKS.length}
        activeCount={filteredData.length}
        onReset={() => {
          setSearch('');
          setStatusFilter('ALL');
        }}
        dropdowns={[
          {
            name: 'status',
            label: 'Status',
            value: statusFilter,
            onChange: setStatusFilter,
            options: [
              { label: 'All Statuses', value: 'ALL' },
              { label: 'COMPLETED', value: 'COMPLETED' },
              { label: 'IN_PROGRESS', value: 'IN_PROGRESS' },
              { label: 'BLOCKED', value: 'BLOCKED' },
            ],
          },
        ]}
      />

      <DataTable
        columns={columns}
        data={filteredData}
        keyExtractor={(item) => item.task_id}
        onRowClick={(item) => {
          setSelectedTask(item);
          setIsDrawerOpen(true);
        }}
        selectedKey={selectedTask?.task_id}
      />

      <DetailDrawer
        isOpen={isDrawerOpen}
        onClose={() => setIsDrawerOpen(false)}
        title={`Task: ${selectedTask?.task_id}`}
        subtitle={selectedTask?.description}
      >
        {selectedTask && (
          <div className="space-y-4 text-xs">
            <div className="grid grid-cols-2 gap-3 p-3 bg-slate-50 border border-slate-200 rounded-lg">
              <div>
                <span className="text-[10px] font-bold text-slate-400 uppercase block">STATUS</span>
                <span className="font-semibold text-slate-900">{selectedTask.status}</span>
              </div>
              <div>
                <span className="text-[10px] font-bold text-slate-400 uppercase block">AGENT</span>
                <span className="font-mono text-slate-900">{selectedTask.agent_id}</span>
              </div>
              <div>
                <span className="text-[10px] font-bold text-slate-400 uppercase block">STARTED AT</span>
                <span className="text-slate-700">{selectedTask.started_at}</span>
              </div>
              <div>
                <span className="text-[10px] font-bold text-slate-400 uppercase block">COMPLETED AT</span>
                <span className="text-slate-700">{selectedTask.completed_at || 'In execution'}</span>
              </div>
            </div>

            <div>
              <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block mb-1.5">
                Invoked Tools
              </span>
              <div className="flex flex-wrap gap-1.5">
                {selectedTask.tool_calls.map((t) => (
                  <span key={t} className="px-2 py-1 bg-slate-100 border border-slate-200 text-slate-800 font-mono text-[11px] rounded">
                    {t}
                  </span>
                ))}
              </div>
            </div>

            {selectedTask.delegated_to.length > 0 && (
              <div>
                <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block mb-1.5">
                  Delegated Sub-Agents
                </span>
                <div className="space-y-1">
                  {selectedTask.delegated_to.map((sub) => (
                    <div key={sub} className="p-2 rounded bg-slate-50 border border-slate-200 font-mono text-slate-800">
                      {sub}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </DetailDrawer>
    </div>
  );
}
