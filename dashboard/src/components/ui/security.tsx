// Badge component for security decisions, trust levels, taint, etc.
import { cn } from '@/lib/utils';
import type { AccessDecision, TrustLevel, TaintState, IncidentSeverity, SensitivityLevel } from '@/types';
import { DECISION_BG, TRUST_BG, TAINT_BG, SEVERITY_BG, SENSITIVITY_BG } from '@/lib/colors';
import {
  CheckCircle2, XCircle, Clock, Eye, HelpCircle,
  ShieldAlert, Shield, AlertTriangle, Zap, Lock
} from 'lucide-react';

// ─── Decision Badge ───────────────────────────────────────────────────────

const DECISION_ICONS: Record<string, React.ElementType> = {
  ALLOW: CheckCircle2,
  BLOCK: XCircle,
  HITL: Clock,
  HUMAN_APPROVAL: Clock,
  MONITOR: Eye,
  QUARANTINE: AlertTriangle,
  REVOKE: ShieldAlert,
  UNKNOWN: HelpCircle,
};

interface DecisionBadgeProps {
  decision?: string;
  size?: 'sm' | 'md' | 'lg';
  className?: string;
}

export function DecisionBadge({ decision = 'UNKNOWN', size = 'sm', className }: DecisionBadgeProps) {
  const norm = String(decision || 'UNKNOWN').toUpperCase();
  const Icon = DECISION_ICONS[norm] || HelpCircle;
  const sizeClass = size === 'sm' ? 'text-[10px] px-1.5 py-0.5 gap-1' : size === 'lg' ? 'text-sm px-3 py-1.5 gap-2' : 'text-xs px-2 py-1 gap-1.5';
  const iconSize = size === 'sm' ? 10 : size === 'lg' ? 16 : 12;
  const bgStyle = DECISION_BG[norm as AccessDecision] || 'bg-zinc-500/10 border-zinc-500/30 text-zinc-400';

  return (
    <span className={cn(
      'inline-flex items-center border rounded font-semibold font-mono uppercase tracking-wider',
      bgStyle,
      sizeClass,
      className,
    )}>
      {Icon && <Icon size={iconSize} />}
      {decision}
    </span>
  );
}

// ─── Trust Badge ──────────────────────────────────────────────────────────

export function TrustBadge({ level = 'medium', className }: { level?: string; className?: string }) {
  const norm = String(level || 'medium').toLowerCase() as TrustLevel;
  const bgStyle = TRUST_BG[norm] || 'bg-zinc-500/10 border-zinc-500/30 text-zinc-400';
  return (
    <span className={cn(
      'inline-flex items-center gap-1 border rounded text-[10px] px-1.5 py-0.5 font-semibold uppercase tracking-wider',
      bgStyle,
      className,
    )}>
      <Shield size={9} />
      {level}
    </span>
  );
}

// ─── Taint Badge ──────────────────────────────────────────────────────────

export function TaintBadge({ state = 'CLEAN', className }: { state?: string; className?: string }) {
  const norm = String(state || 'CLEAN').toUpperCase() as TaintState;
  const bgStyle = TAINT_BG[norm] || 'bg-zinc-500/10 border-zinc-500/30 text-zinc-400';
  const isTainted = norm === 'TAINTED';
  return (
    <span className={cn(
      'inline-flex items-center gap-1 border rounded text-[10px] px-1.5 py-0.5 font-semibold uppercase tracking-wider',
      bgStyle,
      className,
    )}>
      {isTainted ? <AlertTriangle size={9} /> : <CheckCircle2 size={9} />}
      {state}
    </span>
  );
}

// ─── Severity Badge ───────────────────────────────────────────────────────

export function SeverityBadge({ severity = 'LOW', className }: { severity?: string; className?: string }) {
  const norm = String(severity || 'LOW').toUpperCase() as IncidentSeverity;
  const bgStyle = SEVERITY_BG[norm] || 'bg-zinc-500/10 border-zinc-500/30 text-zinc-400';
  return (
    <span className={cn(
      'inline-flex items-center gap-1 border rounded text-[10px] px-1.5 py-0.5 font-bold uppercase tracking-widest',
      bgStyle,
      className,
    )}>
      <Zap size={9} />
      {severity}
    </span>
  );
}

// ─── Sensitivity Badge ────────────────────────────────────────────────────

export function SensitivityBadge({ level = 'MEDIUM', className }: { level?: string; className?: string }) {
  const norm = String(level || 'MEDIUM').toUpperCase() as SensitivityLevel;
  const bgStyle = SENSITIVITY_BG[norm] || 'bg-zinc-500/10 border-zinc-500/30 text-zinc-400';
  return (
    <span className={cn(
      'inline-flex items-center gap-1 border rounded text-[10px] px-1.5 py-0.5 font-semibold uppercase tracking-wider',
      bgStyle,
      className,
    )}>
      <Lock size={9} />
      {level}
    </span>
  );
}

// ─── Stat Card ────────────────────────────────────────────────────────────

interface StatCardProps {
  label: string;
  value: number | string;
  icon?: React.ElementType;
  change?: number;
  color?: string;
  critical?: boolean;
  sublabel?: string;
}

export function StatCard({ label, value, icon: Icon, color = 'text-zinc-200', critical, sublabel }: StatCardProps) {
  return (
    <div className={cn(
      'rounded-xl border p-4 bg-zinc-900/40 backdrop-blur-sm transition-all duration-200 hover:border-zinc-700/70',
      critical ? 'border-red-500/30 bg-red-500/5 shadow-lg shadow-red-500/10' : 'border-zinc-800/50',
    )}>
      <div className="flex items-start justify-between mb-3">
        <div className="text-xs text-zinc-500 font-medium uppercase tracking-wider">{label}</div>
        {Icon && (
          <div className={cn('p-1.5 rounded-md bg-zinc-800/60', critical && 'bg-red-500/10')}>
            <Icon size={12} className={critical ? 'text-red-400' : 'text-zinc-500'} />
          </div>
        )}
      </div>
      <div className={cn('text-2xl font-bold font-mono tracking-tight', color)}>{value}</div>
      {sublabel && <div className="text-[10px] text-zinc-600 mt-1">{sublabel}</div>}
    </div>
  );
}

// ─── Section header ───────────────────────────────────────────────────────

export function SectionHeader({ title, subtitle, children }: {
  title: string;
  subtitle?: string;
  children?: React.ReactNode;
}) {
  return (
    <div className="flex items-start justify-between mb-4">
      <div>
        <h2 className="text-sm font-semibold text-zinc-200">{title}</h2>
        {subtitle && <p className="text-xs text-zinc-500 mt-0.5">{subtitle}</p>}
      </div>
      {children && <div className="flex items-center gap-2">{children}</div>}
    </div>
  );
}

// ─── Empty state ──────────────────────────────────────────────────────────

export function EmptyState({ icon: Icon, title, description, positive = false }: {
  icon: React.ElementType;
  title: string;
  description: string;
  positive?: boolean;
}) {
  return (
    <div className="flex flex-col items-center justify-center py-16 px-8 text-center">
      <div className={cn(
        'w-12 h-12 rounded-full flex items-center justify-center mb-4',
        positive ? 'bg-emerald-500/10' : 'bg-zinc-800/60',
      )}>
        <Icon size={20} className={positive ? 'text-emerald-400' : 'text-zinc-600'} />
      </div>
      <h3 className={cn('text-sm font-medium mb-1', positive ? 'text-emerald-300' : 'text-zinc-400')}>{title}</h3>
      <p className="text-xs text-zinc-600 max-w-sm">{description}</p>
    </div>
  );
}

// ─── Loading state ────────────────────────────────────────────────────────

export function LoadingState({ rows = 5 }: { rows?: number }) {
  return (
    <div className="space-y-2">
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} className="h-10 bg-zinc-800/40 rounded-lg animate-pulse" style={{ opacity: 1 - i * 0.15 }} />
      ))}
    </div>
  );
}

// ─── Generic error state ──────────────────────────────────────────────────

export function ErrorState({ message }: { message: string }) {
  return (
    <div className="flex items-center gap-3 p-4 rounded-lg bg-red-500/5 border border-red-500/20">
      <XCircle size={16} className="text-red-400 flex-shrink-0" />
      <div>
        <div className="text-sm font-medium text-red-300">Error</div>
        <div className="text-xs text-red-400/70">{message}</div>
      </div>
    </div>
  );
}

// ─── Capability pill ──────────────────────────────────────────────────────

export function CapabilityPill({ name, active = true }: { name: string; active?: boolean }) {
  return (
    <span className={cn(
      'inline-flex items-center px-2 py-0.5 rounded-md text-[10px] font-mono border',
      active
        ? 'bg-sky-500/10 border-sky-500/30 text-sky-300'
        : 'bg-zinc-800/40 border-zinc-700/30 text-zinc-500',
    )}>
      {name}
    </span>
  );
}

// ─── AI vs Policy notice ──────────────────────────────────────────────────

export function AiVsPolicyNotice() {
  return (
    <div className="flex gap-3 mt-4">
      <div className="flex-1 rounded-lg bg-violet-500/5 border border-violet-500/20 p-3">
        <div className="text-[10px] font-semibold text-violet-400 uppercase tracking-widest mb-1">AI Recommendation</div>
        <div className="text-xs text-violet-300 leading-relaxed">
          AI Secura provides threat analysis and recommendations. This is advisory only.
        </div>
      </div>
      <div className="flex-1 rounded-lg bg-sky-500/5 border border-sky-500/20 p-3">
        <div className="text-[10px] font-semibold text-sky-400 uppercase tracking-widest mb-1">Deterministic Policy Decision</div>
        <div className="text-xs text-sky-300 leading-relaxed">
          The Policy Engine makes the final enforcement decision. It is fully deterministic.
        </div>
      </div>
    </div>
  );
}
