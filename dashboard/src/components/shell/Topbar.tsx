'use client';

import { useState, useCallback, useEffect } from 'react';
import { Search, Bell, ChevronRight, Command, ShieldCheck, ShieldAlert, User, Activity } from 'lucide-react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';

const BREADCRUMB_MAP: Record<string, string> = {
  '/dashboard': 'Command Center',
  '/activity': 'Live Activity',
  '/agents': 'Agents',
  '/tasks': 'Tasks',
  '/delegations': 'Delegations',
  '/resources': 'Resources',
  '/access/matrix': 'Access Matrix',
  '/context': 'Context & Provenance',
  '/tools': 'Tool & MCP Security',
  '/threats': 'Threat Model',
  '/ai-secura': 'AI Security Intelligence',
  '/apiris': 'API Intelligence',
  '/attack-graph': 'Attack Graph',
  '/traces': 'Trace Explorer',
  '/incidents': 'Incidents',
  '/forensics': 'Forensics',
  '/drift': 'Behavioral Drift',
  '/campaigns': 'Attack Campaigns',
  '/offensive': 'Offensive Validation',
  '/regressions': 'Regressions',
  '/security-gates': 'Security Gates',
  '/posture': 'Security Posture',
  '/reports': 'Reports',
  '/settings': 'Settings',
  '/api': 'API Reference',
  '/demo': 'Attack & Defense Lab',
};

export default function Topbar() {
  const pathname = usePathname();
  const [search, setSearch] = useState('');
  const [isLiveBackend, setIsLiveBackend] = useState<boolean | null>(null);

  const checkBackend = useCallback(async () => {
    try {
      const url = typeof window !== 'undefined' ? '/api/v1/health' : 'http://127.0.0.1:8000/api/v1/health';
      const res = await fetch(url, {
        headers: { Accept: 'application/json' },
        signal: AbortSignal.timeout(2500),
      });
      setIsLiveBackend(res.ok);
    } catch {
      setIsLiveBackend(false);
    }
  }, []);

  useEffect(() => {
    checkBackend();
    const interval = setInterval(checkBackend, 20000);
    return () => clearInterval(interval);
  }, [checkBackend]);

  const segments = pathname.split('/').filter(Boolean);
  const currentTitle = BREADCRUMB_MAP[pathname] || (segments.length ? segments[segments.length - 1].replace(/-/g, ' ') : 'Command Center');

  return (
    <header className="h-14 bg-white border-b border-slate-200 flex items-center justify-between px-5 sticky top-0 z-40 shadow-xs">
      {/* Left: Breadcrumbs / Page Context */}
      <div className="flex items-center gap-2 text-xs text-slate-500 min-w-0">
        <Link href="/dashboard" className="font-semibold text-slate-800 hover:text-sky-700 transition-colors flex items-center gap-1.5 flex-shrink-0">
          <div className="w-5 h-5 rounded bg-sky-600 text-white flex items-center justify-center font-bold text-[10px]">
            AS
          </div>
          <span>ActShield</span>
        </Link>
        <ChevronRight size={12} className="text-slate-400 flex-shrink-0" />
        <span className="font-medium text-slate-900 truncate capitalize">
          {currentTitle}
        </span>
      </div>

      {/* Center: Global Search */}
      <div className="flex-1 max-w-md mx-6 hidden md:block">
        <div className="relative">
          <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search agents, traces, incidents, attacks…"
            className="w-full pl-9 pr-12 py-1.5 text-xs bg-slate-50 border border-slate-200 rounded-md text-slate-800 placeholder:text-slate-400 focus:bg-white focus:outline-none focus:border-sky-500 focus:ring-1 focus:ring-sky-500 transition-all"
          />
          <kbd className="absolute right-2.5 top-1/2 -translate-y-1/2 px-1.5 py-0.5 text-[9px] font-mono text-slate-400 bg-slate-100 border border-slate-200 rounded">
            ⌘K
          </kbd>
        </div>
      </div>

      {/* Right: Status & Controls */}
      <div className="flex items-center gap-3 flex-shrink-0">
        {/* Backend Connection Status */}
        <button
          onClick={checkBackend}
          className={`flex items-center gap-1.5 px-2.5 py-1 rounded text-[11px] font-mono border transition-colors cursor-pointer ${
            isLiveBackend === true
              ? 'bg-emerald-50 border-emerald-200 text-emerald-800'
              : isLiveBackend === false
              ? 'bg-amber-50 border-amber-200 text-amber-800'
              : 'bg-slate-50 border-slate-200 text-slate-500'
          }`}
          title={
            isLiveBackend === true
              ? 'Connected to live FastAPI SDK backend at localhost:8000 (Click to refresh)'
              : 'FastAPI backend offline — displaying cached/demo data (Click to recheck)'
          }
        >
          <span
            className={`w-1.5 h-1.5 rounded-full ${
              isLiveBackend === true
                ? 'bg-emerald-600 animate-pulse'
                : isLiveBackend === false
                ? 'bg-amber-600'
                : 'bg-slate-400'
            }`}
          />
          <span className="font-semibold">
            {isLiveBackend === true ? 'LIVE SDK' : isLiveBackend === false ? 'LOCAL DEMO' : 'CHECKING…'}
          </span>
        </button>

        {/* Environment Badge */}
        <div className="hidden sm:flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-semibold tracking-wider bg-slate-100 border border-slate-200 text-slate-700">
          <span>● LOCAL</span>
        </div>

        {/* Notifications */}
        <button className="relative p-1.5 rounded text-slate-500 hover:text-slate-800 hover:bg-slate-100 transition-colors">
          <Bell size={16} />
          <span className="absolute top-1 right-1 w-2 h-2 bg-sky-600 rounded-full" />
        </button>

        <div className="h-4 w-px bg-slate-200" />

        {/* User / Org profile */}
        <div className="flex items-center gap-2 pl-1 text-xs">
          <div className="w-7 h-7 rounded-full bg-slate-800 text-white flex items-center justify-center font-medium text-[11px]">
            TA
          </div>
          <div className="hidden lg:block text-left leading-tight">
            <div className="font-semibold text-slate-900 text-xs">Tarun</div>
            <div className="text-[10px] text-slate-500">Security Admin</div>
          </div>
        </div>
      </div>
    </header>
  );
}
