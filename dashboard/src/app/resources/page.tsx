'use client';

import { useState } from 'react';
import { Database, Lock, AlertTriangle, Shield, Eye, Filter, FileText, Cloud, Globe } from 'lucide-react';
import { PageHeader } from '@/components/ui/PageHeader';
import { MetricCard } from '@/components/ui/MetricCard';
import { FilterBar } from '@/components/ui/FilterBar';
import { DataTable } from '@/components/ui/DataTable';
import { StatusBadge } from '@/components/ui/StatusBadge';
import { DetailDrawer } from '@/components/ui/DetailDrawer';

interface ResourceItem {
  resource_id: string;
  name: string;
  type: string;
  sensitivity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  description: string;
  access_count_24h: number;
  blocked_attempts_24h: number;
  agents_with_access: string[];
  requires_hitl: boolean;
  taint_level: 'HIGH' | 'MEDIUM' | 'LOW';
}

const DEMO_RESOURCES: ResourceItem[] = [
  {
    resource_id: 'res_db_customers',
    name: 'customers',
    type: 'database_table',
    sensitivity: 'CRITICAL',
    description: 'PII: customer names, emails, addresses, billing info',
    access_count_24h: 47,
    blocked_attempts_24h: 3,
    agents_with_access: ['orchestrator_v2', 'data_agent'],
    requires_hitl: true,
    taint_level: 'HIGH',
  },
  {
    resource_id: 'res_db_orders',
    name: 'orders',
    type: 'database_table',
    sensitivity: 'HIGH',
    description: 'Order records, amounts, statuses — no direct PII',
    access_count_24h: 128,
    blocked_attempts_24h: 0,
    agents_with_access: ['orchestrator_v2', 'data_agent', 'report_agent', 'analyst_agent'],
    requires_hitl: false,
    taint_level: 'MEDIUM',
  },
  {
    resource_id: 'res_file_financials',
    name: '/data/reports/q3_financials.xlsx',
    type: 'file',
    sensitivity: 'HIGH',
    description: 'Q3 financial report — confidential internal document',
    access_count_24h: 5,
    blocked_attempts_24h: 0,
    agents_with_access: ['orchestrator_v2', 'analyst_agent'],
    requires_hitl: false,
    taint_level: 'MEDIUM',
  },
  {
    resource_id: 'res_s3_exports',
    name: 's3://company-exports/',
    type: 'cloud_storage',
    sensitivity: 'CRITICAL',
    description: 'External S3 export bucket — egress to external systems',
    access_count_24h: 0,
    blocked_attempts_24h: 2,
    agents_with_access: [],
    requires_hitl: true,
    taint_level: 'HIGH',
  },
  {
    resource_id: 'res_api_email',
    name: 'email_api',
    type: 'external_api',
    sensitivity: 'HIGH',
    description: 'Email sending API — external communications channel',
    access_count_24h: 0,
    blocked_attempts_24h: 1,
    agents_with_access: [],
    requires_hitl: true,
    taint_level: 'HIGH',
  },
  {
    resource_id: 'res_db_audit',
    name: 'audit_log',
    type: 'database_table',
    sensitivity: 'MEDIUM',
    description: 'Internal audit trail — read access for reporting',
    access_count_24h: 22,
    blocked_attempts_24h: 0,
    agents_with_access: ['report_agent', 'analyst_agent'],
    requires_hitl: false,
    taint_level: 'LOW',
  },
];

const SENSITIVITY_CLASSES: Record<string, string> = {
  CRITICAL: 'bg-red-50 text-red-700 border-red-200 font-semibold',
  HIGH: 'bg-amber-50 text-amber-700 border-amber-200 font-medium',
  MEDIUM: 'bg-blue-50 text-blue-700 border-blue-200',
  LOW: 'bg-slate-50 text-slate-700 border-slate-200',
};

const TYPE_ICONS: Record<string, React.ElementType> = {
  database_table: Database,
  file: FileText,
  cloud_storage: Cloud,
  external_api: Globe,
};

export default function ResourcesPage() {
  const [search, setSearch] = useState('');
  const [sensitFilter, setSensitFilter] = useState('ALL');
  const [selectedResource, setSelectedResource] = useState<ResourceItem | null>(null);

  const totalAccesses = DEMO_RESOURCES.reduce((s, r) => s + r.access_count_24h, 0);
  const totalBlocked = DEMO_RESOURCES.reduce((s, r) => s + r.blocked_attempts_24h, 0);
  const criticalCount = DEMO_RESOURCES.filter(r => r.sensitivity === 'CRITICAL').length;

  const filtered = DEMO_RESOURCES.filter(r => {
    const matchSearch =
      r.name.toLowerCase().includes(search.toLowerCase()) ||
      r.description.toLowerCase().includes(search.toLowerCase()) ||
      r.resource_id.toLowerCase().includes(search.toLowerCase());

    const matchSensit = sensitFilter === 'ALL' || r.sensitivity === sensitFilter;
    return matchSearch && matchSensit;
  });

  const columns = [
    {
      key: 'name',
      header: 'Resource',
      render: (row: ResourceItem) => {
        const Icon = TYPE_ICONS[row.type] || Database;
        return (
          <div className="flex items-center gap-2.5">
            <div className="w-7 h-7 rounded-md bg-slate-100 flex items-center justify-center text-slate-600 border border-slate-200">
              <Icon size={14} />
            </div>
            <div>
              <div className="font-mono text-xs font-semibold text-slate-900">{row.name}</div>
              <div className="text-[11px] text-slate-500">{row.description}</div>
            </div>
          </div>
        );
      },
    },
    {
      key: 'type',
      header: 'Type',
      width: '130px',
      render: (row: ResourceItem) => (
        <span className="text-xs font-mono text-slate-600 uppercase bg-slate-50 px-2 py-0.5 rounded border border-slate-200">
          {row.type.replace('_', ' ')}
        </span>
      ),
    },
    {
      key: 'sensitivity',
      header: 'Sensitivity',
      width: '110px',
      render: (row: ResourceItem) => (
        <span className={`text-[11px] px-2 py-0.5 rounded border ${SENSITIVITY_CLASSES[row.sensitivity]}`}>
          {row.sensitivity}
        </span>
      ),
    },
    {
      key: 'requires_hitl',
      header: 'HITL Gated',
      width: '110px',
      render: (row: ResourceItem) => (
        <span className={`text-[11px] font-medium px-2 py-0.5 rounded border ${
          row.requires_hitl ? 'bg-amber-50 text-amber-800 border-amber-200' : 'bg-slate-50 text-slate-500 border-slate-200'
        }`}>
          {row.requires_hitl ? 'Required' : 'Automated'}
        </span>
      ),
    },
    {
      key: 'access_count_24h',
      header: 'Accesses (24h)',
      width: '120px',
      render: (row: ResourceItem) => (
        <span className="font-mono text-xs text-slate-700">{row.access_count_24h}</span>
      ),
    },
    {
      key: 'blocked_attempts_24h',
      header: 'Blocked (24h)',
      width: '120px',
      render: (row: ResourceItem) => (
        <span className={`font-mono text-xs font-semibold ${row.blocked_attempts_24h > 0 ? 'text-red-600' : 'text-slate-400'}`}>
          {row.blocked_attempts_24h}
        </span>
      ),
    },
  ];

  return (
    <div className="p-8 space-y-6 max-w-7xl mx-auto">
      <PageHeader
        title="Protected Resources"
        subtitle="Catalog of protected data sinks, databases, APIs, and sensitivity classifications"
        badge="Asset Inventory"
      />

      {/* KPI Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <MetricCard label="Total Resources" value={DEMO_RESOURCES.length} />
        <MetricCard label="Critical Sensitivity" value={criticalCount} status={criticalCount > 0 ? 'BLOCK' : 'ALLOW'} />
        <MetricCard label="Blocked Attempts (24h)" value={totalBlocked} status={totalBlocked > 0 ? 'BLOCK' : 'ALLOW'} />
        <MetricCard label="Access Events (24h)" value={totalAccesses} status="ALLOW" />
      </div>

      {/* Table & Filter */}
      <div className="bg-white border border-slate-200 rounded-lg p-5 shadow-xs space-y-4">
        <FilterBar
          searchQuery={search}
          onSearchChange={setSearch}
          searchPlaceholder="Search resources by name, ID, or description..."
          filters={[
            {
              key: 'sensitivity',
              label: 'Sensitivity',
              options: [
                { label: 'All Levels', value: 'ALL' },
                { label: 'Critical', value: 'CRITICAL' },
                { label: 'High', value: 'HIGH' },
                { label: 'Medium', value: 'MEDIUM' },
                { label: 'Low', value: 'LOW' },
              ],
              value: sensitFilter,
              onChange: setSensitFilter,
            },
          ]}
          activeCount={sensitFilter !== 'ALL' || search ? 1 : 0}
          onReset={() => {
            setSearch('');
            setSensitFilter('ALL');
          }}
        />

        <DataTable
          columns={columns}
          data={filtered}
          keyField="resource_id"
          onRowClick={(row) => setSelectedResource(row)}
          emptyMessage="No resources matched your search criteria."
        />
      </div>

      {/* Resource Detail Drawer */}
      <DetailDrawer
        isOpen={!!selectedResource}
        onClose={() => setSelectedResource(null)}
        title={selectedResource ? selectedResource.name : ''}
        subtitle={selectedResource ? selectedResource.resource_id : ''}
        badge={selectedResource ? (
          <span className={`text-xs px-2 py-0.5 rounded border ${SENSITIVITY_CLASSES[selectedResource.sensitivity]}`}>
            {selectedResource.sensitivity}
          </span>
        ) : null}
      >
        {selectedResource && (
          <div className="space-y-6">
            {/* Overview */}
            <div className="bg-slate-50 border border-slate-200 rounded-lg p-3.5 space-y-2">
              <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">Description & Classification</div>
              <p className="text-xs text-slate-800 leading-relaxed">{selectedResource.description}</p>
            </div>

            {/* Security Profile */}
            <div>
              <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-500 mb-2">Security Attributes</div>
              <div className="grid grid-cols-2 gap-3 text-xs">
                <div className="p-3 bg-white border border-slate-200 rounded-lg">
                  <span className="text-slate-500 block mb-1">Taint Classification</span>
                  <span className={`font-mono font-semibold ${
                    selectedResource.taint_level === 'HIGH' ? 'text-red-700' : selectedResource.taint_level === 'MEDIUM' ? 'text-amber-700' : 'text-emerald-700'
                  }`}>
                    {selectedResource.taint_level} TAINT
                  </span>
                </div>
                <div className="p-3 bg-white border border-slate-200 rounded-lg">
                  <span className="text-slate-500 block mb-1">Human-in-the-Loop</span>
                  <span className="font-semibold text-slate-800">
                    {selectedResource.requires_hitl ? 'Mandatory HITL Gate' : 'Automated Policy Check'}
                  </span>
                </div>
              </div>
            </div>

            {/* Authorized Agents */}
            <div>
              <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-500 mb-2">Authorized Agents</div>
              {selectedResource.agents_with_access.length > 0 ? (
                <div className="flex flex-wrap gap-1.5">
                  {selectedResource.agents_with_access.map(agent => (
                    <span key={agent} className="font-mono text-xs px-2 py-0.5 rounded bg-blue-50 text-blue-800 border border-blue-200 font-medium">
                      {agent}
                    </span>
                  ))}
                </div>
              ) : (
                <div className="p-3 bg-slate-50 border border-slate-200 rounded-lg flex items-center gap-2 text-xs text-slate-600">
                  <Lock size={14} className="text-slate-500" />
                  <span>No agents currently have persistent access to this resource (Zero Trust quarantine).</span>
                </div>
              )}
            </div>

            {/* Access telemetry */}
            <div>
              <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-500 mb-2">24-Hour Telemetry</div>
              <div className="grid grid-cols-2 gap-3">
                <div className="p-3 bg-slate-50 border border-slate-200 rounded-lg text-center">
                  <div className="text-[10px] text-slate-500 uppercase">Access Events</div>
                  <div className="text-lg font-bold font-mono text-slate-800">{selectedResource.access_count_24h}</div>
                </div>
                <div className="p-3 bg-slate-50 border border-slate-200 rounded-lg text-center">
                  <div className="text-[10px] text-slate-500 uppercase">Blocked Invocations</div>
                  <div className={`text-lg font-bold font-mono ${selectedResource.blocked_attempts_24h > 0 ? 'text-red-700' : 'text-slate-800'}`}>
                    {selectedResource.blocked_attempts_24h}
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}
      </DetailDrawer>
    </div>
  );
}
