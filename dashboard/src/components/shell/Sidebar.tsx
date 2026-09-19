'use client';

import { useState, useEffect } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import {
  Shield, Activity, Users, CheckSquare, Share2, Database,
  Grid, FileText, Wrench, GitBranch, Search, AlertTriangle,
  Microscope, Swords, RotateCcw, ScrollText, Brain, Zap,
  BarChart2, Settings, Globe, ChevronRight, ChevronDown,
  Box, Lock, Network, Code, FlaskConical, Map, Clock, Eye,
  Target, Cpu
} from 'lucide-react';

interface NavItem {
  label: string;
  href?: string;
  icon?: React.ElementType;
  children?: NavItem[];
  badge?: string;
  badgeColor?: string;
}

const NAV: NavItem[] = [
  {
    label: 'COMMAND',
    children: [
      { label: 'Command Center', href: '/dashboard', icon: Shield },
      { label: 'Live Activity', href: '/activity', icon: Activity },
      { label: 'Agents', href: '/agents', icon: Users },
      { label: 'Tasks', href: '/tasks', icon: CheckSquare },
      { label: 'Delegations', href: '/delegations', icon: Share2 },
      { label: 'Resources', href: '/resources', icon: Database },
      { label: 'Access Matrix', href: '/access/matrix', icon: Grid },
      { label: 'Context & Provenance', href: '/context', icon: FileText },
      { label: 'Tool / MCP Security', href: '/tools', icon: Wrench },
    ],
  },
  {
    label: 'INVESTIGATION',
    children: [
      { label: 'Attack Graph', href: '/attack-graph', icon: Network },
      { label: 'Trace Explorer', href: '/traces', icon: Search },
      { label: 'Incidents', href: '/incidents', icon: AlertTriangle, badge: '2', badgeColor: 'bg-red-500' },
      { label: 'Forensics', href: '/forensics', icon: Microscope },
      { label: 'Attack Campaigns', href: '/campaigns', icon: Swords },
      { label: 'Regressions', href: '/regressions', icon: RotateCcw },
    ],
  },
  {
    label: 'SECURITY',
    children: [
      { label: 'Policies', href: '/policies', icon: ScrollText },
      { label: 'AI Secura', href: '/ai-secura', icon: Brain },
      { label: 'APIRIS', href: '/apiris', icon: Zap },
      { label: 'Offensive Validation', href: '/offensive', icon: FlaskConical },
    ],
  },
  {
    label: 'PLATFORM',
    children: [
      { label: 'API Console', href: '/api', icon: Code },
      { label: 'Metrics', href: '/metrics', icon: BarChart2 },
      { label: 'Reports', href: '/reports', icon: Map },
      { label: 'Settings', href: '/settings', icon: Settings },
    ],
  },
];

function NavSection({ section }: { section: NavItem }) {
  const pathname = usePathname();
  const [open, setOpen] = useState(true);

  return (
    <div className="mb-1">
      <button
        onClick={() => setOpen(!open)}
        className="w-full flex items-center justify-between px-3 py-1.5 text-[10px] font-semibold tracking-widest text-zinc-500 hover:text-zinc-400 uppercase"
      >
        {section.label}
        {open ? <ChevronDown size={10} /> : <ChevronRight size={10} />}
      </button>
      {open && section.children && (
        <div className="mt-0.5 space-y-0.5">
          {section.children.map((item) => {
            const Icon = item.icon;
            const active = pathname === item.href;
            return (
              <Link
                key={item.href}
                href={item.href!}
                className={`
                  flex items-center gap-2.5 px-3 py-2 mx-1 rounded-md text-sm font-medium
                  transition-all duration-150 group relative
                  ${active
                    ? 'bg-sky-500/10 text-sky-300 border border-sky-500/20'
                    : 'text-zinc-400 hover:text-zinc-200 hover:bg-white/[0.04]'
                  }
                `}
              >
                {active && (
                  <div className="absolute left-0 top-1/2 -translate-y-1/2 w-0.5 h-5 bg-sky-400 rounded-r-full" />
                )}
                {Icon && <Icon size={14} className={active ? 'text-sky-400' : 'text-zinc-500 group-hover:text-zinc-300'} />}
                <span className="flex-1 truncate">{item.label}</span>
                {item.badge && (
                  <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded-full text-white ${item.badgeColor}`}>
                    {item.badge}
                  </span>
                )}
              </Link>
            );
          })}
        </div>
      )}
      <div className="mx-3 mt-2 mb-1 border-t border-zinc-800/60" />
    </div>
  );
}

import Image from 'next/image';

export default function Sidebar() {
  const [time, setTime] = useState<string | null>(null);

  useEffect(() => {
    setTime(new Date().toLocaleTimeString());
    const interval = setInterval(() => setTime(new Date().toLocaleTimeString()), 1000);
    return () => clearInterval(interval);
  }, []);

  return (
    <aside className="w-60 min-h-screen bg-[#080c14] border-r border-zinc-800/50 flex flex-col">
      {/* Logo */}
      <div className="px-4 py-4 border-b border-zinc-800/50">
        <Link href="/dashboard" className="flex items-center gap-3 group">
          <div className="w-9 h-9 rounded-lg overflow-hidden flex-shrink-0 bg-black/40 border border-sky-500/30 flex items-center justify-center shadow-lg shadow-sky-500/10 group-hover:border-sky-500/60 transition-colors">
            <Image src="/logo.png" alt="AgentGuard Logo" width={36} height={36} className="w-full h-full object-contain" />
          </div>
          <div>
            <div className="text-sm font-bold text-white tracking-wide group-hover:text-sky-300 transition-colors">AgentGuard</div>
            <div className="text-[9px] text-zinc-500 tracking-wider">CONTROL PLANE</div>
          </div>
        </Link>
      </div>

      {/* Nav */}
      <nav className="flex-1 overflow-y-auto py-3 scrollbar-thin scrollbar-thumb-zinc-800 scrollbar-track-transparent">
        {NAV.map((section) => (
          <NavSection key={section.label} section={section} />
        ))}
      </nav>

      {/* System Status */}
      <div className="px-3 py-3 border-t border-zinc-800/50 space-y-2">
        <div className="text-[10px] font-semibold text-zinc-500 uppercase tracking-widest mb-2">System Status</div>
        {[
          { label: 'AgentGuard Core', ok: true },
          { label: 'AI Secura', ok: true },
          { label: 'APIRIS', ok: true },
          { label: 'Policy Engine', ok: true },
        ].map(({ label, ok }) => (
          <div key={label} className="flex items-center justify-between text-xs">
            <span className="text-zinc-400">{label}</span>
            <div className="flex items-center gap-1.5">
              <div className={`w-1.5 h-1.5 rounded-full ${ok ? 'bg-emerald-400 animate-pulse' : 'bg-red-400'}`} />
              <span className={ok ? 'text-emerald-400' : 'text-red-400'}>{ok ? 'ONLINE' : 'DOWN'}</span>
            </div>
          </div>
        ))}
        <div className="pt-2 border-t border-zinc-800/50 flex items-center justify-between text-[10px] text-zinc-600">
          <span className="flex items-center gap-1">
            <Lock size={9} />
            LOCAL / SAFE MODE
          </span>
          <span className="font-mono" suppressHydrationWarning>
            {time ?? '--:--:--'}
          </span>
        </div>
      </div>
    </aside>
  );
}
