import React from 'react';
import { LucideIcon } from 'lucide-react';

interface MetricCardProps {
  label: string;
  value: string | number;
  subtext?: string;
  trend?: {
    value: string;
    isPositive?: boolean;
    isNeutral?: boolean;
  };
  status?: 'healthy' | 'warning' | 'critical' | 'neutral' | 'ALLOW' | 'BLOCK' | 'HITL' | 'MONITOR';
  icon?: LucideIcon;
  badge?: string;
}

export function MetricCard({
  label,
  value,
  subtext,
  trend,
  status = 'neutral',
  icon: Icon,
  badge,
}: MetricCardProps) {
  const normStatus = (() => {
    if (status === 'ALLOW' || status === 'MONITOR' || status === 'healthy') return 'healthy';
    if (status === 'HITL' || status === 'warning') return 'warning';
    if (status === 'BLOCK' || status === 'critical') return 'critical';
    return 'neutral';
  })();

  const statusBorder = {
    healthy: 'border-l-4 border-l-emerald-500',
    warning: 'border-l-4 border-l-amber-500',
    critical: 'border-l-4 border-l-red-500',
    neutral: 'border-l-4 border-l-slate-300',
  }[normStatus];

  return (
    <div className={`bg-white rounded-lg border border-slate-200 p-4 shadow-sm ${statusBorder} flex flex-col justify-between`}>
      <div className="flex items-center justify-between gap-2 mb-2">
        <span className="text-[11px] font-medium tracking-wider uppercase text-slate-500">
          {label}
        </span>
        {Icon && <Icon size={16} className="text-slate-400" />}
        {badge && (
          <span className="text-[10px] font-semibold px-1.5 py-0.5 rounded bg-slate-100 text-slate-700">
            {badge}
          </span>
        )}
      </div>

      <div className="flex items-baseline justify-between gap-2 mt-1">
        <div className="text-2xl font-bold tracking-tight text-slate-900 font-mono">
          {value}
        </div>
        {trend && (
          <span
            className={`text-xs font-medium ${
              trend.isNeutral
                ? 'text-slate-500'
                : trend.isPositive
                ? 'text-emerald-700'
                : 'text-red-700'
            }`}
          >
            {trend.value}
          </span>
        )}
      </div>

      {subtext && (
        <div className="mt-2 text-xs text-slate-500 truncate">
          {subtext}
        </div>
      )}
    </div>
  );
}
