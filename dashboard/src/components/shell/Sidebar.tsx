'use client';

import { useState } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import {
  Shield, Activity, Users, CheckSquare, Share2, Database,
  Grid, FileText, Wrench, ShieldAlert, Brain, Zap,
  Network, Search, AlertTriangle, Microscope, Compass,
  Swords, FlaskConical, RotateCcw, Lock, BarChart3,
  FileBarChart, Settings, Sliders, Code2, ChevronDown, ChevronRight
} from 'lucide-react';

interface NavItem {
  label: string;
  href: string;
  icon: React.ElementType;
  badge?: string;
}

interface NavSection {
  title: string;
  items: NavItem[];
}

const SECTIONS: NavSection[] = [
  {
    title: 'OVERVIEW',
    items: [
      { label: 'Command Center', href: '/dashboard', icon: Shield },
      { label: 'Live Activity', href: '/activity', icon: Activity },
    ],
  },
  {
    title: 'OPERATIONS',
    items: [
      { label: 'Agents', href: '/agents', icon: Users },
      { label: 'Tasks', href: '/tasks', icon: CheckSquare },
      { label: 'Delegations', href: '/delegations', icon: Share2 },
      { label: 'Resources', href: '/resources', icon: Database },
      { label: 'Access Matrix', href: '/access/matrix', icon: Grid },
    ],
  },
  {
    title: 'SECURITY',
    items: [
      { label: 'Context & Provenance', href: '/context', icon: FileText },
      { label: 'Tool / MCP Security', href: '/tools', icon: Wrench },
      { label: 'Policies', href: '/policies', icon: Lock },
      { label: 'Threat Model', href: '/threats', icon: ShieldAlert },
      { label: 'AI Security', href: '/ai-secura', icon: Brain },
      { label: 'API Intelligence', href: '/apiris', icon: Zap },
    ],
  },
  {
    title: 'INVESTIGATION',
    items: [
      { label: 'Attack Graph', href: '/attack-graph', icon: Network },
      { label: 'Trace Explorer', href: '/traces', icon: Search },
      { label: 'Incidents', href: '/incidents', icon: AlertTriangle, badge: '0 OPEN' },
      { label: 'Forensics', href: '/forensics', icon: Microscope },
      { label: 'Behavioral Drift', href: '/drift', icon: Compass },
    ],
  },
  {
    title: 'VALIDATION',
    items: [
      { label: 'Attack Campaigns', href: '/campaigns', icon: Swords },
      { label: 'Offensive Validation', href: '/offensive', icon: FlaskConical },
      { label: 'Regressions', href: '/regressions', icon: RotateCcw },
      { label: 'Security Gates', href: '/security-gates', icon: Lock, badge: 'PASS' },
    ],
  },
  {
    title: 'REPORTING',
    items: [
      { label: 'Security Posture', href: '/posture', icon: BarChart3 },
      { label: 'Reports', href: '/reports', icon: FileBarChart },
    ],
  },
  {
    title: 'SYSTEM',
    items: [
      { label: 'Settings', href: '/settings', icon: Settings },
      { label: 'Integrations', href: '/demo', icon: Sliders },
      { label: 'API Reference', href: '/api', icon: Code2 },
    ],
  },
];

export default function Sidebar() {
  const pathname = usePathname();
  const [collapsedSections, setCollapsedSections] = useState<Record<string, boolean>>({});

  const toggleSection = (title: string) => {
    setCollapsedSections(prev => ({ ...prev, [title]: !prev[title] }));
  };

  return (
    <aside className="w-64 min-h-screen bg-white border-r border-slate-200 flex flex-col flex-shrink-0 select-none">
      {/* Brand Header */}
      <div className="h-14 px-5 border-b border-slate-200 flex items-center justify-between">
        <Link href="/dashboard" className="flex items-center gap-2.5">
          <div className="w-7 h-7 rounded-md bg-slate-900 text-white flex items-center justify-center font-bold text-xs shadow-xs">
            🛡️
          </div>
          <div>
            <div className="text-sm font-bold text-slate-900 tracking-tight leading-none">
              ActShield
            </div>
            <div className="text-[10px] text-slate-500 font-medium tracking-wider mt-0.5">
              SECURITY CONTROL PLANE
            </div>
          </div>
        </Link>
      </div>

      {/* Navigation List */}
      <nav className="flex-1 overflow-y-auto py-3 px-3 space-y-4">
        {SECTIONS.map((section) => {
          const isCollapsed = collapsedSections[section.title];
          return (
            <div key={section.title}>
              <button
                type="button"
                onClick={() => toggleSection(section.title)}
                className="w-full flex items-center justify-between px-2 py-1 text-[10px] font-bold tracking-wider text-slate-400 hover:text-slate-600 uppercase"
              >
                <span>{section.title}</span>
                {isCollapsed ? <ChevronRight size={10} /> : <ChevronDown size={10} />}
              </button>

              {!isCollapsed && (
                <div className="mt-1 space-y-0.5">
                  {section.items.map((item) => {
                    const Icon = item.icon;
                    const isActive = pathname === item.href;
                    return (
                      <Link
                        key={item.href}
                        href={item.href}
                        className={`flex items-center justify-between px-2.5 py-1.5 rounded-md text-xs font-medium transition-colors ${
                          isActive
                            ? 'bg-sky-50 text-sky-900 border border-sky-200/80 font-semibold'
                            : 'text-slate-600 hover:bg-slate-100/80 hover:text-slate-900'
                        }`}
                      >
                        <div className="flex items-center gap-2.5 min-w-0">
                          <Icon
                            size={15}
                            className={isActive ? 'text-sky-700' : 'text-slate-400'}
                          />
                          <span className="truncate">{item.label}</span>
                        </div>

                        {item.badge && (
                          <span
                            className={`text-[9px] font-bold px-1.5 py-0.2 rounded ${
                              item.badge === 'PASS'
                                ? 'bg-emerald-50 text-emerald-700 border border-emerald-200'
                                : 'bg-slate-100 text-slate-600 border border-slate-200'
                            }`}
                          >
                            {item.badge}
                          </span>
                        )}
                      </Link>
                    );
                  })}
                </div>
              )}
            </div>
          );
        })}
      </nav>

      {/* Footer Status Panel */}
      <div className="p-3 border-t border-slate-200 bg-slate-50/50 space-y-1.5 text-xs text-slate-600">
        <div className="flex items-center justify-between text-[11px]">
          <span className="font-medium text-slate-700">Enforcement Mode</span>
          <span className="font-mono font-semibold text-emerald-800 bg-emerald-50 border border-emerald-200 px-1.5 py-0.5 rounded text-[10px]">
            STRICT
          </span>
        </div>
        <div className="flex items-center justify-between text-[11px]">
          <span className="text-slate-500">Engine Invariants</span>
          <span className="text-emerald-700 font-semibold text-[10px]">✓ FAIL-SAFE</span>
        </div>
      </div>
    </aside>
  );
}
