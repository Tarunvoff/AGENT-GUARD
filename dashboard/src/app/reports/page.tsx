'use client';

import { useState } from 'react';
import { Download, FileText, Shield, CheckCircle2, Clock, AlertTriangle, ExternalLink } from 'lucide-react';
import { PageHeader } from '@/components/ui/PageHeader';
import { MetricCard } from '@/components/ui/MetricCard';
import { StatusBadge } from '@/components/ui/StatusBadge';
import { FilterBar } from '@/components/ui/FilterBar';
import { DataTable } from '@/components/ui/DataTable';
import { DetailDrawer } from '@/components/ui/DetailDrawer';

interface ReportItem {
  report_id: string;
  title: string;
  type: 'OFFENSIVE' | 'POSTURE' | 'FORENSICS' | 'COMPLIANCE';
  generated_at: string;
  format: string;
  path: string;
  summary: string;
  status: 'READY' | 'GENERATING';
}

const REPORTS: ReportItem[] = [
  {
    report_id: 'rpt_phase5_adaptive',
    title: 'Phase 5 Adaptive Campaign Scorecard',
    type: 'OFFENSIVE',
    generated_at: '2026-09-19T11:00:00Z',
    format: 'JSON + Markdown',
    path: 'reports/phase5/adaptive_dashboard.json',
    summary: '70 attack variants tested across 10 seed trees. 100% empirical prevention rate. 0 bypasses. 0 sensitive DB calls.',
    status: 'READY',
  },
  {
    report_id: 'rpt_phase5_campaign_md',
    title: 'Phase 5 Campaign Summary (Markdown)',
    type: 'OFFENSIVE',
    generated_at: '2026-09-19T11:00:00Z',
    format: 'Markdown',
    path: 'reports/phase5/adaptive_campaign_summary.md',
    summary: 'Human-readable summary with mutation lineage, bypass evidence, and remediation verification.',
    status: 'READY',
  },
  {
    report_id: 'rpt_security_posture',
    title: 'Daily Security Posture Report',
    type: 'POSTURE',
    generated_at: '2026-09-19T09:00:00Z',
    format: 'Markdown',
    path: 'reports/daily/2026-09-19-posture.md',
    summary: '189 decisions. 100% enforcement uptime. 4 HITL escalations. 5 active agents. Policy engine nominal.',
    status: 'READY',
  },
  {
    report_id: 'rpt_forensics_export',
    title: 'Incident Forensics Export',
    type: 'FORENSICS',
    generated_at: '2026-09-19T10:50:00Z',
    format: 'JSON',
    path: 'reports/forensics/2026-09-19-incidents.json',
    summary: '2 active incidents exported with full evidence chains, delegation graphs, and provenance maps.',
    status: 'READY',
  },
  {
    report_id: 'rpt_compliance',
    title: 'Monthly Compliance Audit Log',
    type: 'COMPLIANCE',
    generated_at: '2026-09-19T07:22:00Z',
    format: 'PDF',
    path: 'reports/compliance/2026-09-audit.pdf',
    summary: 'All 174 passing tests verified. Zero policy violations in production. Audit trail complete.',
    status: 'READY',
  },
];

const TYPE_BADGES: Record<string, string> = {
  OFFENSIVE: 'bg-red-50 text-red-700 border-red-200',
  POSTURE: 'bg-blue-50 text-blue-700 border-blue-200',
  FORENSICS: 'bg-purple-50 text-purple-700 border-purple-200',
  COMPLIANCE: 'bg-emerald-50 text-emerald-700 border-emerald-200',
};

export default function ReportsPage() {
  const [search, setSearch] = useState('');
  const [typeFilter, setTypeFilter] = useState('ALL');
  const [selectedReport, setSelectedReport] = useState<ReportItem | null>(null);

  const filtered = REPORTS.filter(r => {
    const matchSearch =
      r.title.toLowerCase().includes(search.toLowerCase()) ||
      r.summary.toLowerCase().includes(search.toLowerCase()) ||
      r.report_id.toLowerCase().includes(search.toLowerCase());

    const matchType = typeFilter === 'ALL' || r.type === typeFilter;

    return matchSearch && matchType;
  });

  const columns = [
    {
      key: 'title',
      header: 'Report Title',
      render: (row: ReportItem) => (
        <div className="flex items-center gap-2.5">
          <div className="w-7 h-7 rounded bg-slate-100 flex items-center justify-center text-slate-600 border border-slate-200">
            <FileText size={13} />
          </div>
          <div>
            <div className="font-semibold text-xs text-slate-900">{row.title}</div>
            <div className="text-[11px] font-mono text-slate-500">{row.path}</div>
          </div>
        </div>
      ),
    },
    {
      key: 'type',
      header: 'Category',
      width: '130px',
      render: (row: ReportItem) => (
        <span className={`text-[11px] font-mono px-2 py-0.5 rounded border ${TYPE_BADGES[row.type]}`}>
          {row.type}
        </span>
      ),
    },
    {
      key: 'format',
      header: 'Format',
      width: '120px',
      render: (row: ReportItem) => (
        <span className="text-xs text-slate-600 font-mono bg-slate-50 px-2 py-0.5 rounded border border-slate-200">
          {row.format}
        </span>
      ),
    },
    {
      key: 'generated_at',
      header: 'Generated',
      width: '140px',
      render: (row: ReportItem) => (
        <span className="text-xs text-slate-500">{new Date(row.generated_at).toLocaleDateString()}</span>
      ),
    },
    {
      key: 'status',
      header: 'Status',
      width: '100px',
      render: (row: ReportItem) => (
        <span className="text-[11px] font-semibold text-emerald-700 bg-emerald-50 px-2 py-0.5 rounded border border-emerald-200">
          {row.status}
        </span>
      ),
    },
  ];

  return (
    <div className="p-8 space-y-6 max-w-7xl mx-auto">
      <PageHeader
        title="Security Reports & Artifacts"
        subtitle="Downloadable compliance audits, offensive campaign summaries, and forensic investigation exports"
        badge="Audit & Compliance"
      />

      {/* KPI Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <MetricCard label="Total Reports" value={REPORTS.length} />
        <MetricCard label="Offensive Scorecards" value={REPORTS.filter(r => r.type === 'OFFENSIVE').length} status="ALLOW" />
        <MetricCard label="Forensic Exports" value={REPORTS.filter(r => r.type === 'FORENSICS').length} status="ALLOW" />
        <MetricCard label="Compliance Audits" value={REPORTS.filter(r => r.type === 'COMPLIANCE').length} status="ALLOW" />
      </div>

      {/* Filter and Table */}
      <div className="bg-white border border-slate-200 rounded-lg p-5 shadow-xs space-y-4">
        <FilterBar
          searchQuery={search}
          onSearchChange={setSearch}
          searchPlaceholder="Search reports by title or path..."
          filters={[
            {
              key: 'type',
              label: 'Category',
              options: [
                { label: 'All Categories', value: 'ALL' },
                { label: 'Offensive', value: 'OFFENSIVE' },
                { label: 'Posture', value: 'POSTURE' },
                { label: 'Forensics', value: 'FORENSICS' },
                { label: 'Compliance', value: 'COMPLIANCE' },
              ],
              value: typeFilter,
              onChange: setTypeFilter,
            },
          ]}
          activeCount={typeFilter !== 'ALL' || search ? 1 : 0}
          onReset={() => {
            setSearch('');
            setTypeFilter('ALL');
          }}
        />

        <DataTable
          columns={columns}
          data={filtered}
          keyField="report_id"
          onRowClick={(row) => setSelectedReport(row)}
          emptyMessage="No reports matched your search criteria."
        />
      </div>

      {/* Detail Drawer */}
      <DetailDrawer
        isOpen={!!selectedReport}
        onClose={() => setSelectedReport(null)}
        title={selectedReport ? selectedReport.title : ''}
        subtitle={selectedReport ? `ID: ${selectedReport.report_id} • ${selectedReport.format}` : ''}
        badge={selectedReport ? (
          <span className={`text-xs px-2 py-0.5 rounded border ${TYPE_BADGES[selectedReport.type]}`}>
            {selectedReport.type}
          </span>
        ) : null}
      >
        {selectedReport && (
          <div className="space-y-6">
            <div className="p-3.5 bg-slate-50 border border-slate-200 rounded-lg space-y-1.5">
              <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">Executive Summary</div>
              <p className="text-xs text-slate-800 leading-relaxed">{selectedReport.summary}</p>
            </div>

            <div className="space-y-2 text-xs text-slate-600">
              <div className="flex justify-between py-1.5 border-b border-slate-100">
                <span className="text-slate-500">Filesystem Location</span>
                <span className="font-mono text-slate-900">{selectedReport.path}</span>
              </div>
              <div className="flex justify-between py-1.5 border-b border-slate-100">
                <span className="text-slate-500">Generated At</span>
                <span className="font-mono">{new Date(selectedReport.generated_at).toUTCString()}</span>
              </div>
              <div className="flex justify-between py-1.5">
                <span className="text-slate-500">Artifact Status</span>
                <span className="font-semibold text-emerald-700">{selectedReport.status}</span>
              </div>
            </div>
          </div>
        )}
      </DetailDrawer>
    </div>
  );
}
