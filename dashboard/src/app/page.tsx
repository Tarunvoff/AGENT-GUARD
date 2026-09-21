'use client';

import React, { useState, useRef, useEffect, useCallback } from 'react';
import Link from 'next/link';
import {
  Shield, ArrowRight, CheckCircle2, Cpu,
  Activity, Zap, Search, Layers, FileText,
  Check, Copy, ChevronRight, Terminal, X,
} from 'lucide-react';

/* ─────────────────────────────────────────────────────────────────────────────
   SEARCH INDEX — every navigable destination on the platform
───────────────────────────────────────────────────────────────────────────── */
const SEARCH_INDEX = [
  // Capabilities
  { label:'Agent Security',         desc:'Identity, delegation, authority bounds and access control',  href:'/agents',         group:'Capability' },
  { label:'Context Security',       desc:'Provenance tracking, trust classification and taint propagation',href:'/context',   group:'Capability' },
  { label:'MCP & Tool Security',    desc:'Monitor and control external tools and MCP server interactions',href:'/tools',     group:'Capability' },
  { label:'Threat Modeling',        desc:'Map assets, trust boundaries, attack paths and threats',     href:'/threats',        group:'Capability' },
  { label:'AI Security',            desc:'AI Secura semantic intent analysis and LLM reasoning',       href:'/ai-secura',      group:'Capability' },
  { label:'API Intelligence',       desc:'APIRIS payload risk scoring and egress control',             href:'/apiris',         group:'Capability' },
  { label:'Forensics',              desc:'Understand who, what, why and what actually executed',       href:'/forensics',      group:'Capability' },
  { label:'Offensive Validation',   desc:'Attack your own security boundary and discover bypasses',   href:'/campaigns',      group:'Capability' },
  { label:'Security Gates',         desc:'Validate security invariants before each deployment',       href:'/security-gates', group:'Capability' },
  // Operate
  { label:'Command Center',         desc:'Real-time security overview dashboard',                     href:'/dashboard',      group:'Operate' },
  { label:'Agents Catalog',         desc:'Registered agent profiles and trust levels',                href:'/agents',         group:'Operate' },
  { label:'Tasks Execution',        desc:'Multi-agent task execution and sub-task monitoring',        href:'/tasks',          group:'Operate' },
  { label:'Tool & MCP Registry',    desc:'External tool registry and MCP server governance',         href:'/tools',          group:'Operate' },
  { label:'Context Provenance',     desc:'4-point execution state log and source taint tracking',    href:'/context',        group:'Operate' },
  { label:'Delegations',            desc:'Authority delegation lineage and scope containment',       href:'/delegations',    group:'Operate' },
  { label:'Access Matrix',          desc:'Agent × Resource access matrix with ALLOW/DENY indicators',href:'/access/matrix',  group:'Operate' },
  // Investigate
  { label:'Incidents',              desc:'7-state incident lifecycle and containment workspace',     href:'/incidents',      group:'Investigate' },
  { label:'Trace Explorer',         desc:'Causal execution trace with span-level decision evidence', href:'/traces',         group:'Investigate' },
  { label:'Causal Forensics',       desc:'Evidence-backed causal explanations and blast radius',    href:'/forensics',      group:'Investigate' },
  { label:'Activity Stream',        desc:'Real-time live decision event stream with filters',        href:'/activity',       group:'Investigate' },
  { label:'Attack Graph',           desc:'ReactFlow visual DAG of taint flow and intercept points', href:'/attack-graph',   group:'Investigate' },
  { label:'Drift Detection',        desc:'Behavioral drift anomaly detection vs baseline profiles', href:'/drift',          group:'Investigate' },
  // Validate
  { label:'Offensive Campaigns',    desc:'Automated adversarial mutation campaigns',                 href:'/campaigns',      group:'Validate' },
  { label:'Regression Library',     desc:'Replay regressions with before/after fix diffs',          href:'/regressions',    group:'Validate' },
  { label:'Security Gates',         desc:'CI/CD release gate evaluation',                           href:'/security-gates', group:'Validate' },
  { label:'Attack Simulator',       desc:'Step-through interactive attack simulation runner',       href:'/demo',           group:'Validate' },
  // Analyze
  { label:'Security Posture',       desc:'6-dimension posture scorecard and health grades',         href:'/posture',        group:'Analyze' },
  { label:'APIRIS Intelligence',    desc:'API risk intelligence and payload anomaly scoring',       href:'/apiris',         group:'Analyze' },
  { label:'AI Secura Reasoning',    desc:'Semantic intent analysis feed',                          href:'/ai-secura',      group:'Analyze' },
  { label:'Telemetry Metrics',      desc:'Decision volumes and enforcement latency percentiles',   href:'/metrics',        group:'Analyze' },
  { label:'Compliance Reports',     desc:'Audit reports and forensic exports',                     href:'/reports',        group:'Analyze' },
  // System
  { label:'Policies',               desc:'Deterministic policy rules and predicates',               href:'/policies',       group:'System' },
  { label:'Resources',              desc:'Protected databases, files and cloud sinks',              href:'/resources',      group:'System' },
  { label:'Settings',               desc:'Zero-trust configuration and fail-safe modes',           href:'/settings',       group:'System' },
  { label:'API Documentation',      desc:'REST API reference and OpenAPI schema',                  href:'/api',            group:'System' },
];

/* ─────────────────────────────────────────────────────────────────────────────
   DATA
───────────────────────────────────────────────────────────────────────────── */
const MAIN_NAV = [
  { label: 'Overview',             href: '/dashboard' },
  { label: 'Security',             href: '/policies' },
  { label: 'Threat Model',         href: '/threats' },
  { label: 'Agents',               href: '/agents' },
  { label: 'Incidents',            href: '/incidents' },
  { label: 'Forensics',            href: '/forensics' },
  { label: 'Offensive Validation', href: '/campaigns' },
  { label: 'Posture',              href: '/posture' },
];

const CAPABILITIES = [
  { no:'01', title:'Agent Security',       desc:'Identity, delegation, authority bounds and access control.',                              href:'/agents',         group:'Protect' },
  { no:'02', title:'Context Security',     desc:'Provenance tracking, trust classification and taint propagation.',                       href:'/context',        group:'Protect' },
  { no:'03', title:'MCP & Tool Security',  desc:'Monitor and control external tools and MCP server interactions.',                        href:'/tools',          group:'Protect' },
  { no:'04', title:'Threat Modeling',      desc:'Map assets, trust boundaries, attack paths and active threats.',                         href:'/threats',        group:'Protect' },
  { no:'05', title:'AI Security',          desc:'AI Secura semantic intent reasoning with pluggable LLM analysis.',                       href:'/ai-secura',      group:'Analyze' },
  { no:'06', title:'API Intelligence',     desc:'APIRIS payload risk scoring, schema validation and egress control.',                     href:'/apiris',         group:'Analyze' },
  { no:'07', title:'Forensics',            desc:'Understand who acted, what executed, why it was allowed, what actually ran.',            href:'/forensics',      group:'Investigate' },
  { no:'08', title:'Offensive Validation', desc:'Attack your own security boundary. Discover policy bypasses in local sandboxes.',        href:'/campaigns',      group:'Validate' },
  { no:'09', title:'Security Gates',       desc:'Continuously validate security invariants before each deployment.',                      href:'/security-gates', group:'Validate' },
];

const LAUNCHPAD = [
  { group:'Operate',     no:'01', links:[
    { label:'Command Center',     href:'/dashboard' },
    { label:'Agents',             href:'/agents' },
    { label:'Tasks',              href:'/tasks' },
    { label:'Tools & MCP',        href:'/tools' },
    { label:'Context Provenance', href:'/context' },
    { label:'Delegations',        href:'/delegations' },
  ]},
  { group:'Investigate', no:'02', links:[
    { label:'Incidents',          href:'/incidents' },
    { label:'Trace Explorer',     href:'/traces' },
    { label:'Forensics',          href:'/forensics' },
    { label:'Threat Model',       href:'/threats' },
    { label:'Activity Stream',    href:'/activity' },
    { label:'Attack Graph',       href:'/attack-graph' },
  ]},
  { group:'Validate',    no:'03', links:[
    { label:'Offensive Campaigns',href:'/campaigns' },
    { label:'Attack Graph',       href:'/attack-graph' },
    { label:'Regressions',        href:'/regressions' },
    { label:'Security Gates',     href:'/security-gates' },
    { label:'Strategy Coverage',  href:'/offensive' },
    { label:'Attack Simulator',   href:'/demo' },
  ]},
  { group:'Analyze',     no:'04', links:[
    { label:'Security Posture',   href:'/posture' },
    { label:'Behavioral Drift',   href:'/drift' },
    { label:'AI Secura',          href:'/ai-secura' },
    { label:'APIRIS',             href:'/apiris' },
    { label:'Telemetry Metrics',  href:'/metrics' },
    { label:'Compliance Reports', href:'/reports' },
  ]},
];

const KPI = [
  { label:'Security Posture',        value:'98/100', sub:'Grade A+',        accent:'text-emerald-600' },
  { label:'Active Agents',           value:'12',     sub:'100% bound',      accent:'text-slate-800' },
  { label:'Active Incidents',        value:'2',      sub:'Contained',       accent:'text-amber-600' },
  { label:'Blocked Actions',         value:'17',     sub:'Last 24 h',       accent:'text-red-600' },
  { label:'Unauthorized Executions', value:'0',      sub:'Zero leaks',      accent:'text-emerald-600' },
  { label:'Open Regressions',        value:'0',      sub:'All verified',    accent:'text-emerald-600' },
];

const PIPELINE = [
  { step:'01', name:'OBSERVE',   desc:'Captures tool invocations, prompts, MCP payloads and delegation requests in real-time.' },
  { step:'02', name:'CORRELATE', desc:'Binds identity, active delegations, context provenance and taint tags.' },
  { step:'03', name:'ANALYZE',   desc:'Evaluates APIRIS structural risk and AI Secura semantic intent alignment.' },
  { step:'04', name:'ENFORCE',   desc:'Deterministic policy engine applies mathematical invariants to produce a verifiable verdict.' },
];

/* ─────────────────────────────────────────────────────────────────────────────
   SEARCH PALETTE
───────────────────────────────────────────────────────────────────────────── */
const GROUP_ORDER = ['Capability','Operate','Investigate','Validate','Analyze','System'];
const GROUP_COLORS: Record<string,string> = {
  Capability: 'text-blue-700 bg-blue-50 border-blue-200',
  Operate:    'text-slate-700 bg-slate-100 border-slate-200',
  Investigate:'text-amber-700 bg-amber-50 border-amber-200',
  Validate:   'text-red-700 bg-red-50 border-red-200',
  Analyze:    'text-purple-700 bg-purple-50 border-purple-200',
  System:     'text-slate-600 bg-slate-50 border-slate-200',
};

function SearchPalette({ onClose }: { onClose: () => void }) {
  const [query, setQuery]       = useState('');
  const [cursor, setCursor]     = useState(0);
  const inputRef                = useRef<HTMLInputElement>(null);

  useEffect(() => { inputRef.current?.focus(); }, []);

  const results = query.trim().length === 0
    ? SEARCH_INDEX.slice(0, 8)
    : SEARCH_INDEX.filter(item =>
        item.label.toLowerCase().includes(query.toLowerCase()) ||
        item.desc.toLowerCase().includes(query.toLowerCase()) ||
        item.group.toLowerCase().includes(query.toLowerCase())
      ).slice(0, 12);

  // Group results
  const grouped: Record<string, typeof results> = {};
  for (const r of results) {
    if (!grouped[r.group]) grouped[r.group] = [];
    grouped[r.group].push(r);
  }
  const flat = GROUP_ORDER.flatMap(g => grouped[g] ?? []);

  useEffect(() => { setCursor(0); }, [query]);

  const handleKey = useCallback((e: React.KeyboardEvent) => {
    if (e.key === 'ArrowDown') { e.preventDefault(); setCursor(c => Math.min(c + 1, flat.length - 1)); }
    if (e.key === 'ArrowUp')   { e.preventDefault(); setCursor(c => Math.max(c - 1, 0)); }
    if (e.key === 'Escape')    { onClose(); }
    if (e.key === 'Enter' && flat[cursor]) {
      window.location.href = flat[cursor].href;
      onClose();
    }
  }, [flat, cursor, onClose]);

  return (
    <div className="fixed inset-0 z-[100] flex flex-col items-center pt-16 px-4" style={{ background:'rgba(15,23,42,0.5)' }}
      onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}>
      <div className="w-full max-w-xl bg-white rounded-xl border border-slate-200 shadow-2xl overflow-hidden">
        {/* Input */}
        <div className="flex items-center gap-3 px-4 py-3 border-b border-slate-200">
          <Search size={15} className="text-slate-400 shrink-0" />
          <input
            ref={inputRef}
            value={query}
            onChange={e => setQuery(e.target.value)}
            onKeyDown={handleKey}
            placeholder="Search pages, capabilities, settings…"
            className="flex-1 text-sm text-slate-900 placeholder:text-slate-400 outline-none bg-transparent"
          />
          {query && (
            <button onClick={() => setQuery('')} className="text-slate-400 hover:text-slate-700">
              <X size={13} />
            </button>
          )}
          <kbd className="text-[10px] font-mono bg-slate-100 border border-slate-200 text-slate-400 px-1.5 py-0.5 rounded">ESC</kbd>
        </div>

        {/* Results */}
        <div className="max-h-[400px] overflow-y-auto py-1">
          {flat.length === 0 && (
            <div className="px-4 py-6 text-center text-sm text-slate-400">No results for &ldquo;{query}&rdquo;</div>
          )}
          {GROUP_ORDER.map(g => {
            const items = grouped[g];
            if (!items?.length) return null;
            return (
              <div key={g}>
                <div className="px-4 py-1.5 text-[10px] font-bold uppercase tracking-widest text-slate-400">{g}</div>
                {items.map((item, i) => {
                  const idx = flat.indexOf(item);
                  return (
                    <Link key={item.href + item.label} href={item.href} onClick={onClose}
                      className={`flex items-center gap-3 px-4 py-2.5 transition-colors ${idx === cursor ? 'bg-blue-50' : 'hover:bg-slate-50'}`}>
                      <div className="flex-1 min-w-0">
                        <p className="text-sm font-semibold text-slate-900 truncate">{item.label}</p>
                        <p className="text-xs text-slate-500 truncate">{item.desc}</p>
                      </div>
                      <span className={`text-[10px] font-semibold px-1.5 py-0.5 rounded border shrink-0 ${GROUP_COLORS[g]}`}>{g}</span>
                    </Link>
                  );
                })}
              </div>
            );
          })}
        </div>

        {/* Footer */}
        <div className="px-4 py-2 border-t border-slate-100 flex items-center gap-4 text-[10px] font-mono text-slate-400">
          <span>↑↓ navigate</span><span>↵ open</span><span>esc close</span>
        </div>
      </div>
    </div>
  );
}

/* ─────────────────────────────────────────────────────────────────────────────
   MAIN PAGE
───────────────────────────────────────────────────────────────────────────── */
export default function LandingPage() {
  const [searchOpen,    setSearchOpen]    = useState(false);
  const [copiedInstall, setCopiedInstall] = useState(false);
  const [copiedSnippet, setCopiedSnippet] = useState(false);

  const copy = (text: string, set: (v: boolean) => void) => {
    navigator.clipboard.writeText(text);
    set(true);
    setTimeout(() => set(false), 2000);
  };

  // ⌘K / Ctrl+K opens palette
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        setSearchOpen(true);
      }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, []);

  return (
    <div className="min-h-screen bg-white text-slate-900" style={{ fontFamily:'Inter, system-ui, sans-serif' }}>

      {/* Search Palette Overlay */}
      {searchOpen && <SearchPalette onClose={() => setSearchOpen(false)} />}

      {/* ════ NAV ════════════════════════════════════════════════════════════ */}
      <header className="sticky top-0 z-50 bg-white border-b border-slate-200">
        <div className="max-w-screen-xl mx-auto px-6 h-[52px] flex items-center justify-between gap-4">
          <div className="flex items-center gap-8 min-w-0">
            <Link href="/" className="flex items-center gap-2 shrink-0">
              <div className="w-6 h-6 rounded bg-blue-600 flex items-center justify-center">
                <Shield size={13} strokeWidth={2.5} className="text-white" />
              </div>
              <span className="text-sm font-bold tracking-tight">AgentGuard</span>
            </Link>
            <nav className="hidden lg:flex items-center gap-0.5 text-[13px] font-medium text-slate-600 min-w-0 overflow-hidden">
              {MAIN_NAV.map(n => (
                <Link key={n.href} href={n.href}
                  className="whitespace-nowrap px-2.5 py-1.5 rounded hover:bg-slate-100 hover:text-slate-900 transition-colors">
                  {n.label}
                </Link>
              ))}
            </nav>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            {/* Search button — opens palette */}
            <button
              onClick={() => setSearchOpen(true)}
              className="hidden md:flex items-center gap-2 h-8 px-3 rounded border border-slate-200 bg-slate-50 hover:bg-white hover:border-slate-300 text-xs text-slate-500 hover:text-slate-800 transition-colors w-48"
            >
              <Search size={12} /><span className="flex-1 text-left">Search…</span>
              <kbd className="text-[10px] font-mono bg-white border border-slate-200 text-slate-400 px-1 rounded">⌘K</kbd>
            </button>
            <Link href="/api" className="hidden md:block h-8 px-3 rounded text-[13px] font-medium text-slate-600 hover:text-slate-900 hover:bg-slate-100 transition-colors leading-8">
              Documentation
            </Link>
            <Link href="/offensive" className="hidden md:block h-8 px-3 rounded text-[13px] font-medium text-slate-600 hover:text-slate-900 hover:bg-slate-100 transition-colors leading-8">
              CLI
            </Link>
            <Link href="/dashboard"
              className="h-8 px-4 rounded bg-blue-600 hover:bg-blue-700 text-white text-[13px] font-semibold transition-colors leading-8 flex items-center gap-1.5">
              Dashboard <ArrowRight size={12} />
            </Link>
            <div className="hidden sm:flex items-center gap-1.5 h-8 px-2.5 rounded border border-slate-200 bg-slate-50 text-[11px] font-mono text-slate-600">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 shrink-0" />
              Production: Strict
            </div>
          </div>
        </div>
      </header>

      {/* ════ HERO — two-column split ════════════════════════════════════════ */}
      <section className="border-b border-slate-200">
        <div className="max-w-screen-xl mx-auto px-6">
          <div className="grid grid-cols-1 lg:grid-cols-[1fr_400px] gap-0 divide-y lg:divide-y-0 lg:divide-x divide-slate-200">
            {/* Left */}
            <div className="py-14 pr-0 lg:pr-12">
              <div className="inline-flex items-center gap-1.5 text-[11px] font-mono font-semibold uppercase tracking-widest text-blue-700 bg-blue-50 border border-blue-200 px-2.5 py-1 rounded mb-6">
                <Shield size={11} /> Enterprise AI Security Control Plane
              </div>
              <h1 className="text-[44px] font-bold tracking-tight leading-[1.1] text-slate-900">AgentGuard</h1>
              <p className="text-xl font-semibold text-slate-500 mt-2">Security Control Plane for Autonomous AI</p>
              <div className="mt-6 pl-4 border-l-2 border-blue-500 space-y-1.5">
                {['Observe agent actions.','Correlate identity, authority and context.','Analyze threats.','Enforce deterministic security boundaries.']
                  .map(l => <p key={l} className="text-sm text-slate-600">{l}</p>)}
              </div>
              <div className="mt-8 flex flex-wrap gap-3">
                <Link href="/dashboard"
                  className="inline-flex items-center gap-2 bg-blue-600 hover:bg-blue-700 text-white text-sm font-semibold px-5 py-2.5 rounded transition-colors">
                  Open Security Console <ArrowRight size={14} />
                </Link>
                <Link href="/threats"
                  className="inline-flex items-center gap-2 text-sm font-medium text-slate-700 hover:text-slate-900 px-4 py-2.5 rounded border border-slate-300 hover:border-slate-400 bg-white hover:bg-slate-50 transition-colors">
                  Explore Architecture
                </Link>
              </div>
              <div className="mt-8 pt-6 border-t border-slate-100 flex flex-wrap gap-x-6 gap-y-2 text-[11px] font-mono text-slate-500">
                <span className="flex items-center gap-1.5 text-emerald-700 font-semibold">
                  <CheckCircle2 size={11} /> Deterministic Engine NOMINAL
                </span>
                <span>Mode: <strong className="text-slate-800">STRICT</strong></span>
                <span>P50: <strong className="text-slate-800">1.4ms</strong></span>
                <span>Bypasses: <strong className="text-slate-800">0</strong></span>
                <span>Tests: <strong className="text-slate-800">243/243</strong></span>
              </div>
            </div>
            {/* Right: Live Status Panel */}
            <div className="py-10 lg:pl-10 flex flex-col justify-center gap-6">
              <div className="flex items-center justify-between">
                <p className="text-[11px] font-semibold uppercase tracking-widest text-slate-400">Live Security Status</p>
                <Link href="/dashboard" className="text-[11px] font-semibold text-blue-700 hover:text-blue-800 flex items-center gap-0.5">
                  Command Center <ChevronRight size={10} />
                </Link>
              </div>
              <div className="grid grid-cols-2 gap-3">
                {KPI.map(k => (
                  <Link href="/dashboard" key={k.label}
                    className="border border-slate-200 rounded-lg p-3 hover:border-slate-300 hover:bg-slate-50 transition-all">
                    <p className="text-[10px] uppercase font-semibold tracking-wider text-slate-400 mb-1.5 leading-tight">{k.label}</p>
                    <p className={`text-2xl font-bold font-mono ${k.accent}`}>{k.value}</p>
                    <p className="text-[10px] text-slate-400 mt-0.5">{k.sub}</p>
                  </Link>
                ))}
              </div>
              <div className="border border-slate-200 rounded-lg p-3">
                <p className="text-[10px] font-semibold uppercase tracking-widest text-slate-400 mb-2">Enforcement Pipeline</p>
                <div className="flex items-center gap-1.5 flex-wrap">
                  {['OBSERVE','CORRELATE','ANALYZE','ENFORCE'].map((s, i, a) => (
                    <React.Fragment key={s}>
                      <span className="text-[11px] font-mono font-bold text-blue-700 bg-blue-50 border border-blue-200 px-2 py-0.5 rounded">{s}</span>
                      {i < a.length - 1 && <span className="text-slate-300 text-xs">→</span>}
                    </React.Fragment>
                  ))}
                </div>
                <p className="text-[10px] text-slate-400 mt-2">Every action intercepted before execution</p>
              </div>
              <div className="flex flex-wrap gap-2">
                {['ALLOW','MONITOR','HITL','QUARANTINE','BLOCK','REVOKE'].map(d => (
                  <span key={d} className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded border ${
                    d==='ALLOW'?'bg-emerald-50 text-emerald-700 border-emerald-200':
                    d==='BLOCK'||d==='REVOKE'?'bg-red-50 text-red-700 border-red-200':
                    d==='HITL'?'bg-amber-50 text-amber-700 border-amber-200':
                    d==='QUARANTINE'?'bg-orange-50 text-orange-700 border-orange-200':
                    'bg-blue-50 text-blue-700 border-blue-200'
                  }`}>{d}</span>
                ))}
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ════ CAPABILITIES ═══════════════════════════════════════════════════ */}
      <section className="border-b border-slate-200 py-14">
        <div className="max-w-screen-xl mx-auto px-6">
          <div className="flex items-end justify-between mb-6">
            <div>
              <p className="text-[11px] font-semibold uppercase tracking-widest text-blue-700 mb-1">Security Capabilities</p>
              <h2 className="text-2xl font-bold tracking-tight text-slate-900">Comprehensive Security Governance for Agentic Systems</h2>
            </div>
            <Link href="/dashboard" className="hidden md:flex items-center gap-1 text-[13px] font-semibold text-blue-700 hover:text-blue-800">
              Full Console <ArrowRight size={13} />
            </Link>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-px bg-slate-200 border border-slate-200 rounded-lg overflow-hidden">
            {CAPABILITIES.map(c => (
              <Link key={c.no} href={c.href}
                className="group bg-white flex items-start gap-4 px-5 py-4 hover:bg-slate-50 transition-colors">
                <span className="text-[11px] font-mono font-bold text-slate-400 tabular-nums mt-0.5 shrink-0 w-5">{c.no}</span>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center justify-between gap-2">
                    <h3 className="text-sm font-bold text-slate-900 group-hover:text-blue-700 transition-colors">{c.title}</h3>
                    <span className="text-[10px] font-semibold text-slate-400 bg-slate-100 border border-slate-200 px-1.5 py-0.5 rounded shrink-0">{c.group}</span>
                  </div>
                  <p className="text-xs text-slate-500 mt-0.5 leading-relaxed">{c.desc}</p>
                </div>
                <ChevronRight size={13} className="text-slate-300 group-hover:text-blue-500 mt-0.5 shrink-0 group-hover:translate-x-0.5 transition-all" />
              </Link>
            ))}
          </div>
        </div>
      </section>

      {/* ════ PIPELINE + CONTROL PLANE — side by side ════════════════════════ */}
      <section className="bg-slate-50 border-b border-slate-200 py-14">
        <div className="max-w-screen-xl mx-auto px-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-12">
            {/* Left: Pipeline */}
            <div>
              <p className="text-[11px] font-semibold uppercase tracking-widest text-blue-700 mb-1">Architecture Workflow</p>
              <h2 className="text-xl font-bold tracking-tight text-slate-900 mb-5">How AgentGuard Works</h2>
              <div className="space-y-3">
                {PIPELINE.map((s, i) => (
                  <div key={s.step} className="flex items-start gap-3">
                    <div className="flex flex-col items-center shrink-0">
                      <div className="w-7 h-7 rounded-full border-2 border-blue-200 bg-blue-50 flex items-center justify-center">
                        <span className="text-[10px] font-mono font-bold text-blue-700">{s.step}</span>
                      </div>
                      {i < PIPELINE.length - 1 && <div className="w-px h-5 bg-slate-200 my-1" />}
                    </div>
                    <div className="pb-4">
                      <p className="text-xs font-bold font-mono text-slate-900 tracking-wider">{s.name}</p>
                      <p className="text-xs text-slate-600 leading-relaxed mt-0.5">{s.desc}</p>
                    </div>
                  </div>
                ))}
              </div>
              <div className="mt-4 p-3 bg-white border border-slate-200 rounded-lg">
                <p className="text-[10px] font-semibold uppercase tracking-widest text-slate-400 mb-2">Remediation Lifecycle</p>
                <div className="flex flex-wrap items-center gap-1.5">
                  {[
                    { label:'Evidence',            cls:'bg-slate-100 text-slate-700 border-slate-200' },
                    null,
                    { label:'Forensics',           cls:'bg-slate-100 text-slate-700 border-slate-200' },
                    null,
                    { label:'Offensive Validation',cls:'bg-red-50 text-red-700 border-red-200' },
                    null,
                    { label:'Regression',          cls:'bg-purple-50 text-purple-700 border-purple-200' },
                    null,
                    { label:'Secured Replay ✓',    cls:'bg-emerald-50 text-emerald-700 border-emerald-200' },
                  ].map((item, i) => item === null
                    ? <span key={i} className="text-slate-300 text-xs shrink-0">→</span>
                    : <span key={item.label} className={`text-[10px] font-mono font-semibold px-2 py-0.5 rounded border ${item.cls}`}>{item.label}</span>
                  )}
                </div>
              </div>
            </div>
            {/* Right: Control Plane */}
            <div>
              <p className="text-[11px] font-semibold uppercase tracking-widest text-blue-700 mb-1">System Architecture</p>
              <h2 className="text-xl font-bold tracking-tight text-slate-900 mb-5">Security Control Plane</h2>
              <div className="space-y-0">
                {[
                  { label:'AI Agents',           sub:'LangChain · AutoGen · CrewAI',                            tier:'source' },
                  { label:'AgentGuard SDK',       sub:'Identity / Authority / Context / Tools',                  tier:'sdk' },
                  { label:'AI Secura + APIRIS',   sub:'Semantic Risk + Payload Intelligence',                    tier:'analysis' },
                  { label:'Deterministic Policy', sub:'Mathematical Invariants · Zero AI Override',              tier:'policy' },
                  { label:'Enforcement Decision', sub:'ALLOW · MONITOR · HITL · QUARANTINE · BLOCK · REVOKE',   tier:'enforcement' },
                  { label:'Evidence · Forensics · Incidents · Posture', sub:'Cryptographic proof chain · Auditable', tier:'output' },
                ].map((row, i, arr) => (
                  <div key={row.label}>
                    <div className={`px-4 py-3 rounded border text-xs flex items-center justify-between gap-3 ${
                      row.tier==='source'?'bg-white border-slate-200':
                      row.tier==='sdk'?'bg-blue-50 border-blue-200':
                      row.tier==='analysis'?'bg-purple-50 border-purple-200':
                      row.tier==='policy'?'bg-slate-900 border-slate-800 text-white':
                      row.tier==='enforcement'?'bg-red-50 border-red-200':
                      'bg-emerald-50 border-emerald-200'
                    }`}>
                      <div>
                        <p className={`font-bold ${
                          row.tier==='policy'?'text-emerald-400':
                          row.tier==='sdk'?'text-blue-800':
                          row.tier==='analysis'?'text-purple-800':
                          row.tier==='enforcement'?'text-red-800':
                          row.tier==='output'?'text-emerald-800':
                          'text-slate-800'
                        }`}>{row.label}</p>
                        <p className={`text-[11px] font-mono mt-0.5 ${row.tier==='policy'?'text-slate-400':'text-slate-500'}`}>{row.sub}</p>
                      </div>
                    </div>
                    {i < arr.length - 1 && <div className="flex justify-center py-0.5"><span className="text-slate-400 text-xs">↓</span></div>}
                  </div>
                ))}
              </div>
              <p className="text-[11px] text-slate-500 mt-3 font-mono">
                Invariant: AI Reasons → Policy Enforces. No AI model can override the deterministic engine.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* ════ LAUNCHPAD ══════════════════════════════════════════════════════ */}
      <section className="border-b border-slate-200 py-14">
        <div className="max-w-screen-xl mx-auto px-6">
          <div className="mb-6">
            <p className="text-[11px] font-semibold uppercase tracking-widest text-blue-700 mb-1">Platform Launchpad</p>
            <h2 className="text-2xl font-bold tracking-tight text-slate-900">Choose Where to Go</h2>
            <p className="text-sm text-slate-500 mt-1">Direct entry into all operational, security, validation and analysis workspaces.</p>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-0 border border-slate-200 rounded-lg overflow-hidden divide-y sm:divide-y-0 sm:divide-x divide-slate-200">
            {LAUNCHPAD.map(g => (
              <div key={g.group} className="bg-white">
                <div className="px-4 py-3 border-b border-slate-100 bg-slate-50 flex items-center justify-between">
                  <span className="text-[11px] font-bold uppercase tracking-widest text-slate-700">{g.group}</span>
                  <span className="text-[10px] font-mono text-slate-400">{g.no}</span>
                </div>
                <div className="p-1.5 space-y-0.5">
                  {g.links.map(l => (
                    <Link key={l.href} href={l.href}
                      className="flex items-center justify-between px-3 py-2 rounded text-[13px] text-slate-700 hover:bg-slate-50 hover:text-blue-700 transition-colors group">
                      <span>{l.label}</span>
                      <ChevronRight size={11} className="text-slate-300 group-hover:text-blue-500 shrink-0" />
                    </Link>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ════ DEVELOPER ENTRY ════════════════════════════════════════════════ */}
      <section className="bg-white border-b border-slate-200 py-14">
        <div className="max-w-screen-xl mx-auto px-6">
          <div className="grid grid-cols-1 lg:grid-cols-[1fr_380px] gap-12 items-start">
            <div>
              <p className="text-[11px] font-semibold uppercase tracking-widest text-blue-700 mb-1">Developer SDK</p>
              <h2 className="text-2xl font-bold tracking-tight text-slate-900 mb-1">Install AgentGuard</h2>
              <p className="text-sm text-slate-500 mb-6">
                Zero-dependency core. Install only what you need — extras are optional.
              </p>

              {/* Install variants */}
              <div className="space-y-3 mb-6">
                <div className="bg-slate-950 rounded-lg border border-slate-800 overflow-hidden">
                  <div className="flex items-center justify-between px-4 py-2 border-b border-slate-800">
                    <span className="text-[11px] font-mono text-slate-400">Core (zero deps)</span>
                    <button onClick={() => copy('pip install agentguard', setCopiedInstall)}
                      className="flex items-center gap-1 text-[11px] font-mono text-slate-500 hover:text-white transition-colors">
                      {copiedInstall ? <Check size={11} className="text-emerald-400" /> : <Copy size={11} />}
                      {copiedInstall ? 'Copied' : 'Copy'}
                    </button>
                  </div>
                  <div className="px-4 py-3 font-mono text-sm">
                    <span className="text-slate-500">$ </span>
                    <span className="text-emerald-400 font-semibold">pip install agentguard</span>
                  </div>
                </div>
                <div className="bg-slate-950 rounded-lg border border-slate-800 overflow-hidden">
                  <div className="flex items-center justify-between px-4 py-2 border-b border-slate-800">
                    <span className="text-[11px] font-mono text-slate-400">Initialize Control Plane</span>
                    <button onClick={() => copy('from agentguard import AgentGuard\n\nguard = AgentGuard(mode="strict")', setCopiedSnippet)}
                      className="flex items-center gap-1 text-[11px] font-mono text-slate-500 hover:text-white transition-colors">
                      {copiedSnippet ? <Check size={11} className="text-emerald-400" /> : <Copy size={11} />}
                      {copiedSnippet ? 'Copied' : 'Copy'}
                    </button>
                  </div>
                  <pre className="px-4 py-3 font-mono text-sm leading-relaxed">
                    <span className="text-blue-400">from</span>
                    <span className="text-slate-300"> agentguard </span>
                    <span className="text-blue-400">import</span>
                    <span className="text-emerald-300"> AgentGuard{'\n\n'}</span>
                    <span className="text-slate-300">guard = </span>
                    <span className="text-yellow-300">AgentGuard</span>
                    <span className="text-slate-300">(mode=</span>
                    <span className="text-orange-300">&quot;strict&quot;</span>
                    <span className="text-slate-300">)</span>
                  </pre>
                </div>
              </div>

              {/* Install extras */}
              <div className="border border-slate-200 rounded-lg overflow-hidden mb-5">
                <div className="px-4 py-2 bg-slate-50 border-b border-slate-200">
                  <p className="text-[11px] font-mono font-semibold text-slate-600">Optional Extras — install only what you need</p>
                </div>
                <div className="divide-y divide-slate-100">
                  {[
                    { extra:'[server]',    desc:'FastAPI + Uvicorn backend server',    cmd:'pip install agentguard[server]' },
                    { extra:'[dashboard]', desc:'Full dashboard + backend',             cmd:'pip install agentguard[dashboard]' },
                    { extra:'[openai]',    desc:'OpenAI LLM provider integration',     cmd:'pip install agentguard[openai]' },
                    { extra:'[gemini]',    desc:'Google Gemini integration',           cmd:'pip install agentguard[gemini]' },
                    { extra:'[anthropic]', desc:'Anthropic Claude integration',        cmd:'pip install agentguard[anthropic]' },
                    { extra:'[all]',       desc:'All providers and server components', cmd:'pip install agentguard[all]' },
                  ].map(row => (
                    <div key={row.extra} className="flex items-center gap-4 px-4 py-2.5">
                      <code className="text-[11px] font-mono font-semibold text-blue-700 bg-blue-50 border border-blue-200 px-2 py-0.5 rounded shrink-0">{row.extra}</code>
                      <span className="text-xs text-slate-500 flex-1">{row.desc}</span>
                      <code className="hidden md:block text-[11px] font-mono text-slate-500">{row.cmd}</code>
                    </div>
                  ))}
                </div>
              </div>

              <div className="flex flex-wrap items-center gap-3">
                <Link href="/api"
                  className="inline-flex items-center gap-2 bg-blue-600 hover:bg-blue-700 text-white text-sm font-semibold px-4 py-2.5 rounded transition-colors">
                  Get Started <ArrowRight size={13} />
                </Link>
                <Link href="/api" className="text-sm font-medium text-slate-600 hover:text-slate-900">Read the SDK docs →</Link>
              </div>
            </div>

            {/* Right: Quick Refs */}
            <div className="space-y-3">
              <p className="text-[11px] font-semibold uppercase tracking-widest text-slate-400 mb-4">Also Available</p>
              {[
                { label:'CLI',         cmd:'agentguard',       desc:'Run attack campaigns, inspect mutations and test gate criteria from terminal.',      href:'/offensive', cta:'CLI Guide' },
                { label:'Dashboard',   cmd:'agentguard serve', desc:'Launch the enterprise console and FastAPI backend on ports 3000 and 8000.',          href:'/dashboard', cta:'Open Console' },
                { label:'REST API',    cmd:'/api/v1/',         desc:'Full OpenAPI spec for streaming events, evaluating actions and querying evidence.',   href:'/api',       cta:'API Reference' },
              ].map(r => (
                <div key={r.label} className="border border-slate-200 rounded-lg p-4 bg-white flex flex-col gap-3">
                  <div className="flex items-center justify-between">
                    <span className="text-[11px] font-mono font-bold text-slate-700">{r.label}</span>
                    <code className="text-[11px] font-mono text-blue-700 bg-blue-50 border border-blue-200 px-2 py-0.5 rounded">{r.cmd}</code>
                  </div>
                  <p className="text-xs text-slate-500 leading-relaxed">{r.desc}</p>
                  <Link href={r.href} className="text-xs font-semibold text-blue-700 hover:text-blue-800 flex items-center gap-1">
                    {r.cta} <ChevronRight size={11} />
                  </Link>
                </div>
              ))}
            </div>
          </div>
        </div>
      </section>

      {/* ════ FINAL CTA ══════════════════════════════════════════════════════ */}
      <section className="bg-slate-900 py-12">
        <div className="max-w-screen-xl mx-auto px-6 flex flex-col sm:flex-row items-center justify-between gap-6">
          <div>
            <p className="text-lg font-bold text-white tracking-tight">AgentGuard</p>
            <p className="text-sm text-slate-400 mt-1 max-w-md">Security control for AI systems that can act.</p>
          </div>
          <div className="flex flex-wrap items-center gap-3 shrink-0">
            <Link href="/dashboard"
              className="inline-flex items-center gap-2 bg-blue-600 hover:bg-blue-500 text-white text-sm font-semibold px-5 py-2.5 rounded transition-colors">
              Open Security Console <ArrowRight size={14} />
            </Link>
            <Link href="/api"
              className="inline-flex items-center gap-2 bg-slate-800 hover:bg-slate-700 text-slate-200 text-sm font-medium px-4 py-2.5 rounded border border-slate-700 transition-colors">
              Read Documentation
            </Link>
          </div>
        </div>
      </section>

      {/* ════ FOOTER ═════════════════════════════════════════════════════════ */}
      <footer className="bg-white border-t border-slate-200 py-4">
        <div className="max-w-screen-xl mx-auto px-6 flex flex-col sm:flex-row items-center justify-between gap-3 text-[12px] text-slate-500">
          <div className="flex items-center gap-4">
            <span className="font-semibold text-slate-800">AgentGuard</span>
            <span>v1.0.0</span><span>·</span><span>Enterprise Security Control Plane</span>
          </div>
          <div className="flex items-center gap-5">
            {[
              {label:'Documentation',href:'/api'},
              {label:'Security Gates',href:'/security-gates'},
              {label:'Posture',href:'/posture'},
              {label:'Settings',href:'/settings'},
            ].map(l => <Link key={l.href} href={l.href} className="hover:text-slate-900 transition-colors">{l.label}</Link>)}
            <div className="flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
              <span className="font-mono">All Systems Operational</span>
            </div>
          </div>
        </div>
      </footer>

    </div>
  );
}
