'use client';

import { useState, useCallback, useEffect } from 'react';
import { Search, Bell, ChevronRight, Command, Zap, Globe, AlertCircle, RefreshCw } from 'lucide-react';
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
  '/access/snapshots': 'Snapshots',
  '/context': 'Context & Provenance',
  '/tools': 'Tool / MCP Security',
  '/attack-graph': 'Attack Graph',
  '/traces': 'Trace Explorer',
  '/incidents': 'Incidents',
  '/forensics': 'Forensics',
  '/campaigns': 'Attack Campaigns',
  '/regressions': 'Regressions',
  '/policies': 'Policies',
  '/ai-secura': 'AI Secura',
  '/apiris': 'APIRIS',
  '/offensive': 'Offensive Validation',
  '/api': 'API Console',
  '/metrics': 'Metrics',
  '/reports': 'Reports',
  '/settings': 'Settings',
};

export default function Topbar() {
  const pathname = usePathname();
  const [search, setSearch] = useState('');
  const [isLiveBackend, setIsLiveBackend] = useState<boolean | null>(null);
  const [lastUpdate, setLastUpdate] = useState(new Date());

  const checkBackend = useCallback(async () => {
    try {
      const res = await fetch('/api/v1/health', {
        headers: { Accept: 'application/json' },
        signal: AbortSignal.timeout(3000),
      });
      setIsLiveBackend(res.ok);
    } catch {
      // Fallback direct check
      try {
        const directRes = await fetch('http://127.0.0.1:8000/api/v1/health', {
          headers: { Accept: 'application/json' },
          signal: AbortSignal.timeout(2000),
        });
        setIsLiveBackend(directRes.ok);
      } catch {
        setIsLiveBackend(false);
      }
    }
    setLastUpdate(new Date());
  }, []);

  useEffect(() => {
    checkBackend();
    const interval = setInterval(checkBackend, 25000); // Poll every 25 seconds
    return () => clearInterval(interval);
  }, [checkBackend]);

  const segments = pathname.split('/').filter(Boolean);
  const breadcrumbs = ['AgentGuard', ...(BREADCRUMB_MAP[pathname] ? [BREADCRUMB_MAP[pathname]] : segments.map(s => s.charAt(0).toUpperCase() + s.slice(1)))];

  return (
    <header className="h-12 bg-[#080c14] border-b border-zinc-800/50 flex items-center px-4 gap-4 sticky top-0 z-40">
      {/* Breadcrumb */}
      <nav className="flex items-center gap-1 text-xs text-zinc-500 flex-shrink-0">
        {breadcrumbs.map((crumb, i) => (
          <span key={i} className="flex items-center gap-1">
            {i > 0 && <ChevronRight size={10} className="text-zinc-700" />}
            <span className={i === breadcrumbs.length - 1 ? 'text-zinc-200 font-medium' : 'text-zinc-500'}>
              {crumb}
            </span>
          </span>
        ))}
      </nav>

      {/* Spacer */}
      <div className="flex-1" />

      {/* Live backend connection indicator */}
      <button
        onClick={checkBackend}
        className={`flex items-center gap-1.5 px-2.5 py-1 rounded-md border text-[10px] font-mono transition-colors cursor-pointer hover:opacity-80 ${
          isLiveBackend === true
            ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
            : isLiveBackend === false
            ? 'bg-amber-500/10 border-amber-500/30 text-amber-400'
            : 'bg-zinc-900/60 border-zinc-800/50 text-zinc-500'
        }`}
        title={
          isLiveBackend === true
            ? 'Connected to live FastAPI backend at http://localhost:8000 (Click to recheck)'
            : 'FastAPI backend offline — displaying demo fixture data (Click to recheck)'
        }
      >
        <div
          className={`w-1.5 h-1.5 rounded-full ${
            isLiveBackend === true
              ? 'bg-emerald-400 animate-pulse'
              : isLiveBackend === false
              ? 'bg-amber-400'
              : 'bg-zinc-500'
          }`}
        />
        <span>{isLiveBackend === true ? 'LIVE SDK (8000)' : isLiveBackend === false ? 'DEMO FIXTURES' : 'CONNECTING...'}</span>
      </button>

      {/* Search */}
      <div className="relative">
        <Search size={13} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-zinc-600" />
        <input
          type="text"
          value={search}
          onChange={e => setSearch(e.target.value)}
          placeholder="Search agents, traces, attacks…"
          className="w-64 pl-7 pr-20 py-1.5 text-xs bg-zinc-900/60 border border-zinc-800/50 rounded-md text-zinc-200 placeholder:text-zinc-600 focus:outline-none focus:border-sky-500/50 focus:bg-zinc-900"
        />
        <kbd className="absolute right-2 top-1/2 -translate-y-1/2 flex items-center gap-0.5 text-[9px] text-zinc-600 font-mono">
          <Command size={9} />K
        </kbd>
      </div>

      {/* Notifications */}
      <button className="relative w-8 h-8 flex items-center justify-center rounded-md text-zinc-500 hover:text-zinc-300 hover:bg-zinc-800/50">
        <Bell size={14} />
        <span className="absolute top-1 right-1 w-1.5 h-1.5 bg-red-500 rounded-full" />
      </button>

      {/* Environment badge */}
      <div className="px-2 py-1 rounded text-[10px] font-semibold tracking-wider bg-emerald-500/10 border border-emerald-500/20 text-emerald-400">
        LOCAL
      </div>

      {/* Version */}
      <div className="text-[10px] text-zinc-600 font-mono">v0.4.0</div>
    </header>
  );
}
