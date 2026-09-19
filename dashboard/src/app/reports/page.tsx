'use client';

import { Map, Download, FileText, Shield, CheckCircle2, Clock, AlertTriangle } from 'lucide-react';
import Link from 'next/link';

const REPORTS = [
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

const TYPE_STYLES: Record<string, string> = {
  OFFENSIVE: 'text-red-400 border-red-500/20 bg-red-500/10',
  POSTURE: 'text-sky-400 border-sky-500/20 bg-sky-500/10',
  FORENSICS: 'text-purple-400 border-purple-500/20 bg-purple-500/10',
  COMPLIANCE: 'text-emerald-400 border-emerald-500/20 bg-emerald-500/10',
};

export default function ReportsPage() {
  return (
    <div className="p-6 space-y-5 min-h-screen bg-[#090d16]">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-white flex items-center gap-2">
            <Map size={18} className="text-sky-400" />
            Reports
          </h1>
          <p className="text-sm text-zinc-500 mt-1">Generated security reports — offensive campaigns, posture, forensics, and compliance</p>
        </div>
      </div>

      {/* Summary */}
      <div className="grid grid-cols-4 gap-3">
        {[
          { label: 'Total Reports', value: REPORTS.length.toString(), color: 'text-zinc-200', border: 'border-zinc-700/30', bg: 'bg-zinc-800/40' },
          { label: 'Offensive', value: REPORTS.filter(r => r.type === 'OFFENSIVE').length.toString(), color: 'text-red-400', border: 'border-red-500/20', bg: 'bg-red-500/5' },
          { label: 'Forensics', value: REPORTS.filter(r => r.type === 'FORENSICS').length.toString(), color: 'text-purple-400', border: 'border-purple-500/20', bg: 'bg-purple-500/5' },
          { label: 'Compliance', value: REPORTS.filter(r => r.type === 'COMPLIANCE').length.toString(), color: 'text-emerald-400', border: 'border-emerald-500/20', bg: 'bg-emerald-500/5' },
        ].map(s => (
          <div key={s.label} className={`rounded-xl border ${s.border} ${s.bg} p-3 text-center`}>
            <div className="text-[10px] text-zinc-500 uppercase tracking-wider mb-1">{s.label}</div>
            <div className={`text-xl font-bold font-mono ${s.color}`}>{s.value}</div>
          </div>
        ))}
      </div>

      {/* Report List */}
      <div className="space-y-3">
        {REPORTS.map(report => (
          <div key={report.report_id} className="rounded-xl border border-zinc-800/50 bg-zinc-900/30 p-4 hover:border-zinc-700/50 transition-colors">
            <div className="flex items-start gap-3">
              <FileText size={16} className="text-zinc-400 mt-0.5 flex-shrink-0" />
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 mb-1 flex-wrap">
                  <span className="font-semibold text-sm text-zinc-200">{report.title}</span>
                  <span className={`text-[10px] font-semibold px-1.5 py-0.5 rounded border ${TYPE_STYLES[report.type] || ''}`}>{report.type}</span>
                  <span className="text-[10px] text-zinc-600 bg-zinc-800/60 px-1.5 py-0.5 rounded">{report.format}</span>
                  <span className="flex items-center gap-1 text-[10px] text-emerald-400"><CheckCircle2 size={9} /> {report.status}</span>
                </div>
                <p className="text-xs text-zinc-500 mb-2">{report.summary}</p>
                <div className="flex items-center gap-4 text-[10px] text-zinc-600">
                  <span className="font-mono">{report.path}</span>
                  <span className="ml-auto">{new Date(report.generated_at).toLocaleString()}</span>
                </div>
              </div>
              <button className="flex-shrink-0 flex items-center gap-1 text-[11px] text-sky-400 hover:text-sky-300 transition-colors px-2 py-1 rounded border border-sky-500/20 hover:border-sky-500/40">
                <Download size={11} />
                Download
              </button>
            </div>
          </div>
        ))}
      </div>

      {/* CLI note */}
      <div className="rounded-xl border border-zinc-800/50 bg-black/40 p-3">
        <div className="text-[10px] uppercase tracking-wider text-zinc-500 mb-2">Generate Reports via CLI</div>
        <div className="font-mono text-[11px] space-y-1">
          <div className="text-emerald-400">python -m agentguard attack report</div>
          <div className="text-sky-400">python examples/phase5/adaptive_offensive_campaign.py</div>
        </div>
      </div>
    </div>
  );
}
