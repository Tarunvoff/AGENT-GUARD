// Security state colour + icon utilities
import type { AccessDecision, TrustLevel, TaintState, IncidentSeverity, SensitivityLevel } from '@/types';

export const DECISION_COLORS: Record<AccessDecision, string> = {
  ALLOW: 'text-emerald-400',
  HITL: 'text-amber-400',
  BLOCK: 'text-red-400',
  MONITOR: 'text-sky-400',
  UNKNOWN: 'text-zinc-500',
};

export const DECISION_BG: Record<AccessDecision, string> = {
  ALLOW: 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400',
  HITL: 'bg-amber-500/10 border-amber-500/30 text-amber-400',
  BLOCK: 'bg-red-500/10 border-red-500/30 text-red-400',
  MONITOR: 'bg-sky-500/10 border-sky-500/30 text-sky-400',
  UNKNOWN: 'bg-zinc-500/10 border-zinc-500/30 text-zinc-400',
};

export const DECISION_GLOW: Record<AccessDecision, string> = {
  ALLOW: 'shadow-emerald-500/20',
  HITL: 'shadow-amber-500/20',
  BLOCK: 'shadow-red-500/30',
  MONITOR: 'shadow-sky-500/20',
  UNKNOWN: 'shadow-zinc-500/10',
};

export const TRUST_COLORS: Record<TrustLevel, string> = {
  high: 'text-emerald-400',
  medium: 'text-sky-400',
  low: 'text-amber-400',
  untrusted: 'text-red-400',
};

export const TRUST_BG: Record<TrustLevel, string> = {
  high: 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400',
  medium: 'bg-sky-500/10 border-sky-500/30 text-sky-400',
  low: 'bg-amber-500/10 border-amber-500/30 text-amber-400',
  untrusted: 'bg-red-500/10 border-red-500/30 text-red-400',
};

export const TAINT_COLORS: Record<TaintState, string> = {
  CLEAN: 'text-emerald-400',
  TAINTED: 'text-red-400',
  SANITIZED: 'text-sky-400',
  UNKNOWN: 'text-zinc-500',
};

export const TAINT_BG: Record<TaintState, string> = {
  CLEAN: 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400',
  TAINTED: 'bg-red-500/10 border-red-500/30 text-red-400',
  SANITIZED: 'bg-sky-500/10 border-sky-500/30 text-sky-400',
  UNKNOWN: 'bg-zinc-500/10 border-zinc-500/30 text-zinc-400',
};

export const SEVERITY_COLORS: Record<IncidentSeverity, string> = {
  CRITICAL: 'text-red-400',
  HIGH: 'text-orange-400',
  MEDIUM: 'text-amber-400',
  LOW: 'text-sky-400',
  INFO: 'text-zinc-400',
};

export const SEVERITY_BG: Record<IncidentSeverity, string> = {
  CRITICAL: 'bg-red-500/10 border-red-500/30 text-red-400',
  HIGH: 'bg-orange-500/10 border-orange-500/30 text-orange-400',
  MEDIUM: 'bg-amber-500/10 border-amber-500/30 text-amber-400',
  LOW: 'bg-sky-500/10 border-sky-500/30 text-sky-400',
  INFO: 'bg-zinc-500/10 border-zinc-500/30 text-zinc-400',
};

export const SENSITIVITY_BG: Record<SensitivityLevel, string> = {
  CRITICAL: 'bg-red-500/10 border-red-500/30 text-red-400',
  HIGH: 'bg-orange-500/10 border-orange-500/30 text-orange-400',
  MEDIUM: 'bg-amber-500/10 border-amber-500/30 text-amber-400',
  LOW: 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400',
  NONE: 'bg-zinc-500/10 border-zinc-500/30 text-zinc-400',
};

export function formatTimestamp(iso: string): string {
  const d = new Date(iso);
  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

export function formatRelative(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  if (diff < 60000) return `${Math.floor(diff / 1000)}s ago`;
  if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
  return `${Math.floor(diff / 3600000)}h ago`;
}

export function shortId(id: string): string {
  return id.length > 16 ? `${id.slice(0, 8)}…${id.slice(-4)}` : id;
}

export function agentInitials(name: string): string {
  return name.replace(/Agent/gi, '').trim().slice(0, 2).toUpperCase() || 'AG';
}
