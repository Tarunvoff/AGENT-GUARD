'use client';

import { useState } from 'react';
import { DEMO_FORENSIC_EXPLANATION, DEMO_AGENTS, DEMO_AGENT_PROFILES } from '@/data/demo';
import { DecisionBadge, TrustBadge, TaintBadge, SensitivityBadge, CapabilityPill, AiVsPolicyNotice } from '@/components/ui/security';
import { Brain, Zap, Shield, AlertTriangle, CheckCircle2, XCircle, ArrowRight, ChevronRight } from 'lucide-react';
import Link from 'next/link';

type ForensicTab = 'agents' | 'resources' | 'authority' | 'why-blocked' | 'access';

export default function ForensicsPage() {
  const [tab, setTab] = useState<ForensicTab>('why-blocked');
  const exp = DEMO_FORENSIC_EXPLANATION;

  return (
    <div className="p-6 space-y-5 min-h-screen bg-[#090d16]">
      <div>
        <h1 className="text-xl font-bold text-white">Forensic Investigation Workspace</h1>
        <p className="text-sm text-zinc-500 mt-1">
          Evidence-backed, deterministic forensic analysis. No AI inference in enforcement decisions.
        </p>
      </div>

      {/* Tab bar */}
      <div className="flex gap-1 border-b border-zinc-800/50 pb-0">
        {([
          ['why-blocked', 'Why Was This Blocked?'],
          ['agents', 'Agent Forensics'],
          ['resources', 'Resource Forensics'],
          ['authority', 'Authority Forensics'],
          ['access', 'Access Forensics'],
        ] as [ForensicTab, string][]).map(([id, label]) => (
          <button
            key={id}
            onClick={() => setTab(id)}
            className={`px-4 py-2 text-xs font-medium border-b-2 transition-colors -mb-px ${
              tab === id
                ? 'border-sky-500 text-sky-300'
                : 'border-transparent text-zinc-500 hover:text-zinc-300'
            }`}
          >
            {label}
          </button>
        ))}
      </div>

      {/* Tab content */}
      {tab === 'why-blocked' && <WhyBlockedTab exp={exp} />}
      {tab === 'agents' && <AgentForensicsTab />}
      {tab === 'resources' && <ResourceForensicsTab />}
      {tab === 'authority' && <AuthorityForensicsTab />}
      {tab === 'access' && <AccessForensicsTab />}
    </div>
  );
}

// ─── Why Was This Blocked? ────────────────────────────────────────────────

function WhyBlockedTab({ exp }: { exp: typeof DEMO_FORENSIC_EXPLANATION }) {
  return (
    <div className="space-y-4">
      {/* Question */}
      <div className="rounded-xl border border-red-500/30 bg-red-500/5 px-5 py-4">
        <div className="text-lg font-bold text-red-300 mb-1">WHY WAS THIS ACTION BLOCKED?</div>
        <div className="text-sm text-zinc-400">
          <span className="font-mono font-semibold text-zinc-200">{exp.tool_name}</span>
          {' '}attempted by{' '}
          <span className="font-mono font-semibold text-zinc-200">{exp.agent_id}</span>
        </div>
      </div>

      {/* Causal chain visualization */}
      <div className="grid grid-cols-4 gap-3">
        {[
          { label: 'ACTION', value: exp.tool_name, sub: 'Attempted tool call', color: 'border-red-500/30 text-red-300 bg-red-500/5' },
          { label: 'REQUESTED BY', value: exp.agent_id, sub: 'Acting agent', color: 'border-zinc-700/50 text-zinc-300 bg-zinc-900/40' },
          { label: 'CONTEXT SOURCE', value: 'External MCP', sub: 'Origin of taint', color: 'border-red-500/30 text-red-300 bg-red-500/5' },
          { label: 'RESOURCE', value: exp.resource_name ?? '—', sub: `Sensitivity: ${exp.resource_sensitivity}`, color: 'border-red-600/40 text-red-400 bg-red-500/10' },
        ].map(({ label, value, sub, color }) => (
          <div key={label} className={`rounded-xl border px-4 py-3 ${color}`}>
            <div className="text-[10px] font-semibold uppercase tracking-widest opacity-60 mb-1">{label}</div>
            <div className="text-sm font-bold font-mono">{value}</div>
            <div className="text-[10px] opacity-60 mt-0.5">{sub}</div>
          </div>
        ))}
      </div>

      {/* Evidence chain */}
      <div className="rounded-xl border border-zinc-800/50 bg-zinc-900/30 p-5">
        <h3 className="text-sm font-semibold text-zinc-200 mb-4">Causal Evidence Chain</h3>
        <div className="space-y-0">
          {[
            {
              step: 1,
              title: 'Context received from UNTRUSTED source',
              detail: `Source: External MCP — trust_level: ${exp.context_trust}`,
              color: 'border-l-amber-500', badge: 'UNTRUSTED',
              badgeColor: 'bg-amber-500/10 border-amber-500/30 text-amber-400',
            },
            {
              step: 2,
              title: 'Context classified as TAINTED',
              detail: `taint_state: ${exp.taint_state} — propagated through agent chain`,
              color: 'border-l-red-500', badge: 'TAINTED',
              badgeColor: 'bg-red-500/10 border-red-500/30 text-red-400',
            },
            {
              step: 3,
              title: 'Request targeted CRITICAL resource',
              detail: `${exp.resource_name} — sensitivity: ${exp.resource_sensitivity}`,
              color: 'border-l-red-600', badge: 'CRITICAL',
              badgeColor: 'bg-red-500/15 border-red-600/30 text-red-300',
            },
            {
              step: 4,
              title: 'Effective authority did not contain requested capability',
              detail: `requested: customer_db.read — effective: [${exp.delegated_authority.join(', ')}]`,
              color: 'border-l-orange-500', badge: 'MISSING CAP',
              badgeColor: 'bg-orange-500/10 border-orange-500/30 text-orange-400',
            },
            {
              step: 5,
              title: 'Deterministic policy enforced BLOCK',
              detail: `reason_code: ${exp.policy_reason_code}`,
              color: 'border-l-red-600', badge: 'BLOCK',
              badgeColor: 'bg-red-500/10 border-red-500/30 text-red-400',
            },
            {
              step: 6,
              title: 'Tool NOT executed — 0 sensitive DB calls',
              detail: `execution_count: ${exp.execution_count} — sensitive_db_calls: ${exp.sensitive_db_calls}`,
              color: 'border-l-emerald-500', badge: 'NOT EXECUTED',
              badgeColor: 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400',
            },
          ].map(({ step, title, detail, color, badge, badgeColor }) => (
            <div key={step} className={`relative pl-5 pb-4 border-l-2 ml-3 ${color} last:pb-0`}>
              <div className={`absolute -left-2 top-0 w-4 h-4 rounded-full bg-zinc-900 border-2 ${color.replace('border-l-', 'border-')} flex items-center justify-center`}>
                <span className="text-[8px] font-bold text-zinc-400">{step}</span>
              </div>
              <div className="ml-2">
                <div className="flex items-center gap-2 mb-0.5">
                  <span className="text-xs font-semibold text-zinc-200">{title}</span>
                  <span className={`text-[9px] px-1.5 py-0.5 rounded border font-bold uppercase ${badgeColor}`}>{badge}</span>
                </div>
                <div className="text-[11px] font-mono text-zinc-500">{detail}</div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* AI Secura vs Policy */}
      <div className="grid grid-cols-2 gap-4">
        <div className="rounded-xl border border-violet-500/30 bg-violet-500/5 p-4">
          <div className="flex items-center gap-2 mb-2">
            <Brain size={14} className="text-violet-400" />
            <span className="text-xs font-semibold text-violet-300 uppercase tracking-wider">AI Secura Analysis</span>
            <span className="ml-auto text-[10px] text-violet-500 italic">Advisory only</span>
          </div>
          <div className="text-xs text-violet-200 leading-relaxed">{exp.ai_secura_summary}</div>
        </div>
        <div className="rounded-xl border border-sky-500/30 bg-sky-500/5 p-4">
          <div className="flex items-center gap-2 mb-2">
            <Shield size={14} className="text-sky-400" />
            <span className="text-xs font-semibold text-sky-300 uppercase tracking-wider">Deterministic Policy Decision</span>
            <span className="ml-auto text-[10px] text-sky-500 italic">Authoritative</span>
          </div>
          <div className="text-xs text-sky-200 leading-relaxed">{exp.policy_explanation}</div>
        </div>
      </div>

      {/* Execution truth */}
      <div className="rounded-xl border border-zinc-800/50 bg-zinc-900/30 p-4">
        <h3 className="text-xs font-semibold text-zinc-400 uppercase tracking-wider mb-3">Execution Truth</h3>
        <div className="grid grid-cols-5 gap-2">
          {[
            { label: 'INTENDED', value: 'NO', ok: false },
            { label: 'REQUESTED', value: 'YES', ok: false },
            { label: 'ALLOWED', value: 'NO', ok: false },
            { label: 'ATTEMPTED', value: 'YES', ok: false },
            { label: 'EXECUTED', value: 'NO', ok: true },
          ].map(({ label, value, ok }) => (
            <div key={label} className={`rounded-lg border px-3 py-2 text-center ${
              ok ? 'border-emerald-500/30 bg-emerald-500/5' : 'border-zinc-800/60 bg-zinc-900/40'
            }`}>
              <div className="text-[9px] text-zinc-600 uppercase tracking-wider mb-1">{label}</div>
              <div className={`text-sm font-bold ${
                value === 'YES' ? 'text-amber-400' : ok ? 'text-emerald-400' : 'text-zinc-400'
              }`}>{value}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ─── Agent Forensics ──────────────────────────────────────────────────────

function AgentForensicsTab() {
  const [selectedAgent, setSelectedAgent] = useState('agt_data');
  const profile = DEMO_AGENT_PROFILES[selectedAgent];

  return (
    <div className="grid grid-cols-3 gap-4">
      <div className="space-y-2">
        <div className="text-[10px] text-zinc-500 uppercase tracking-wider mb-2">Select Agent</div>
        {Object.values(DEMO_AGENT_PROFILES).map(p => (
          <button
            key={p.agent_id}
            onClick={() => setSelectedAgent(p.agent_id)}
            className={`w-full text-left px-3 py-2 rounded-lg border text-xs transition-colors ${
              selectedAgent === p.agent_id
                ? 'border-sky-500/30 bg-sky-500/10 text-sky-300'
                : 'border-zinc-800/50 bg-zinc-900/30 text-zinc-400 hover:text-zinc-200'
            }`}
          >
            <div className="font-semibold">{p.agent_name}</div>
            <div className="font-mono text-[10px] opacity-60">{p.agent_id}</div>
          </button>
        ))}
      </div>

      {profile && (
        <div className="col-span-2 space-y-4">
          <div className="rounded-xl border border-zinc-800/50 bg-zinc-900/30 p-4">
            <h3 className="text-sm font-semibold text-zinc-200 mb-3">{profile.agent_name} — Authority Breakdown</h3>
            {[
              { label: 'DECLARED', caps: profile.declared, color: 'text-sky-400', desc: 'Capabilities declared at registration' },
              { label: 'DELEGATED', caps: profile.delegated, color: 'text-violet-400', desc: 'Capabilities received via delegation' },
              { label: 'EFFECTIVE', caps: profile.effective, color: 'text-emerald-400', desc: 'declared ∪ delegated − restrictions' },
              { label: 'RESTRICTED', caps: profile.restricted, color: 'text-red-400', desc: 'Explicitly denied capabilities' },
            ].map(({ label, caps, color, desc }) => (
              <div key={label} className="flex items-start gap-3 py-2 border-b border-zinc-800/30 last:border-0">
                <div className="w-20 flex-shrink-0">
                  <div className={`text-[10px] font-bold uppercase tracking-wider ${color}`}>{label}</div>
                  <div className="text-[9px] text-zinc-600">{desc}</div>
                </div>
                <div className="flex flex-wrap gap-1">
                  {caps.length > 0
                    ? caps.map(c => <CapabilityPill key={c} name={c} />)
                    : <span className="text-[10px] text-zinc-700 italic">none</span>
                  }
                </div>
              </div>
            ))}
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div className="rounded-xl border border-zinc-800/50 bg-zinc-900/30 p-3">
              <div className="text-[10px] text-zinc-500 uppercase tracking-wider mb-2">Reachable Resources</div>
              {profile.reachable_resources.map(r => (
                <div key={r} className="text-xs text-emerald-400 flex items-center gap-1 py-0.5">
                  <CheckCircle2 size={10} /> {r}
                </div>
              ))}
              {profile.reachable_resources.length === 0 && (
                <div className="text-xs text-zinc-600 italic">No reachable resources</div>
              )}
            </div>
            <div className="rounded-xl border border-zinc-800/50 bg-zinc-900/30 p-3">
              <div className="text-[10px] text-zinc-500 uppercase tracking-wider mb-2">Access Stats</div>
              {[
                { label: 'Attempts', value: profile.total_attempts },
                { label: 'Blocked', value: profile.total_blocked, color: 'text-red-400' },
                { label: 'Allowed', value: profile.total_allowed, color: 'text-emerald-400' },
                { label: 'Executed', value: profile.total_executions, color: 'text-sky-400' },
              ].map(({ label, value, color }) => (
                <div key={label} className="flex justify-between text-xs py-0.5">
                  <span className="text-zinc-500">{label}</span>
                  <span className={`font-mono font-bold ${color ?? 'text-zinc-300'}`}>{value}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function ResourceForensicsTab() {
  return (
    <div className="space-y-4">
      <div className="text-sm text-zinc-400">Resource forensics — who could access, who attempted, who actually accessed.</div>
      {/* Minimal placeholder — real version would show resource profiles */}
      <div className="rounded-xl border border-zinc-800/50 bg-zinc-900/30 p-6 text-center">
        <div className="text-zinc-600 text-sm">Select a resource to inspect its forensic access profile.</div>
        <Link href="/resources" className="mt-3 inline-flex items-center gap-1 text-xs text-sky-400 hover:text-sky-300">
          View Resources <ArrowRight size={12} />
        </Link>
      </div>
    </div>
  );
}

function AuthorityForensicsTab() {
  return (
    <div className="space-y-4">
      <div className="rounded-xl border border-zinc-800/50 bg-zinc-900/30 p-4">
        <h3 className="text-sm font-semibold text-zinc-200 mb-3">Delegation Graph</h3>
        <div className="space-y-2 text-xs">
          {[
            { from: 'PlannerAgent (HIGH)', to: 'ResearchAgent', caps: ['public_search', 'mcp.read'], depth: 0 },
            { from: 'ResearchAgent', to: 'AnalysisAgent', caps: ['public_search'], depth: 1 },
            { from: 'PlannerAgent (HIGH)', to: 'DataAgent', caps: ['financial_extract'], depth: 0 },
          ].map(({ from, to, caps, depth }) => (
            <div key={`${from}-${to}`} className="flex items-center gap-2 py-2 border-b border-zinc-800/30 last:border-0">
              <div style={{ marginLeft: depth * 20 }} className="flex items-center gap-2">
                <span className="text-zinc-400">{from}</span>
                <ArrowRight size={10} className="text-zinc-600" />
                <span className="text-zinc-300 font-medium">{to}</span>
                <div className="flex gap-1">{caps.map(c => <CapabilityPill key={c} name={c} />)}</div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function AccessForensicsTab() {
  const exp = DEMO_FORENSIC_EXPLANATION;
  return (
    <div className="space-y-4">
      <div className="rounded-xl border border-zinc-800/50 bg-zinc-900/30 p-4">
        <h3 className="text-sm font-semibold text-zinc-200 mb-3">Access Forensics — customer_db_read</h3>
        <div className="space-y-2 text-xs">
          {[
            { label: 'Tool', value: exp.tool_name },
            { label: 'Resource', value: exp.resource_name },
            { label: 'Sensitivity', value: exp.resource_sensitivity },
            { label: 'Taint', value: exp.taint_state },
            { label: 'Decision', value: exp.policy_decision },
            { label: 'Executed', value: String(exp.tool_executed) },
            { label: 'Execution count', value: String(exp.execution_count) },
            { label: 'Sensitive DB calls', value: String(exp.sensitive_db_calls) },
          ].map(({ label, value }) => (
            <div key={label} className="flex justify-between border-b border-zinc-800/30 py-1.5 last:border-0">
              <span className="text-zinc-500">{label}</span>
              <span className="font-mono text-zinc-300">{value}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
