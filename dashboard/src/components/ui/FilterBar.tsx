import React from 'react';
import { Search, Filter, RotateCcw } from 'lucide-react';

export interface FilterOption {
  label: string;
  value: string;
}

export interface FilterDropdown {
  name?: string;
  key?: string;
  label?: string;
  value: string;
  options: FilterOption[];
  onChange: (value: string) => void;
}

export interface FilterBarProps {
  searchQuery?: string;
  onSearchChange?: (query: string) => void;
  searchPlaceholder?: string;
  dropdowns?: FilterDropdown[];
  filters?: FilterDropdown[];
  onReset?: () => void;
  activeCount?: number;
  totalCount?: number;
  actions?: React.ReactNode;
}

export function FilterBar({
  searchQuery,
  onSearchChange,
  searchPlaceholder = 'Search records…',
  dropdowns,
  filters,
  onReset,
  activeCount,
  totalCount,
  actions,
}: FilterBarProps) {
  const activeFilters = filters || dropdowns;

  return (
    <div className="bg-white border border-slate-200 rounded-lg p-3 mb-4 shadow-sm flex flex-col md:flex-row md:items-center justify-between gap-3">
      <div className="flex flex-wrap items-center gap-2.5 flex-1">
        {/* Search */}
        {onSearchChange && (
          <div className="relative flex-1 min-w-[200px] max-w-sm">
            <Search
              size={14}
              className="absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-400"
            />
            <input
              type="text"
              value={searchQuery ?? ''}
              onChange={(e) => onSearchChange(e.target.value)}
              placeholder={searchPlaceholder}
              className="w-full pl-8 pr-3 py-1.5 text-xs bg-slate-50 border border-slate-200 rounded-md text-slate-800 placeholder:text-slate-400 focus:bg-white focus:outline-none focus:border-sky-500 focus:ring-1 focus:ring-sky-500 transition-all"
            />
          </div>
        )}

        {/* Dropdown Filters */}
        {activeFilters &&
          activeFilters.map((filter) => (
            <div key={filter.key || filter.name || filter.label} className="flex items-center gap-1.5">
              <select
                value={filter.value}
                onChange={(e) => filter.onChange(e.target.value)}
                className="text-xs bg-slate-50 border border-slate-200 rounded-md px-2.5 py-1.5 text-slate-700 font-medium focus:bg-white focus:outline-none focus:border-sky-500 focus:ring-1 focus:ring-sky-500 transition-all cursor-pointer"
              >
                {filter.options.map((opt) => (
                  <option key={opt.value} value={opt.value}>
                    {opt.label}
                  </option>
                ))}
              </select>
            </div>
          ))}

        {/* Reset */}
        {onReset && (
          <button
            onClick={onReset}
            className="flex items-center gap-1 text-xs text-slate-500 hover:text-slate-800 px-2 py-1.5 rounded hover:bg-slate-100 transition-colors"
            title="Reset Filters"
          >
            <RotateCcw size={12} />
            <span>Reset</span>
          </button>
        )}
      </div>

      {/* Counts & Custom Actions */}
      <div className="flex items-center gap-3 self-end md:self-auto text-xs text-slate-500">
        {totalCount !== undefined && (
          <span className="font-mono text-slate-600">
            {activeCount !== undefined && activeCount !== totalCount ? (
              <>
                <strong className="text-slate-900">{activeCount}</strong> of {totalCount}
              </>
            ) : (
              <>
                <strong className="text-slate-900">{totalCount}</strong> total
              </>
            )}
          </span>
        )}
        {actions}
      </div>
    </div>
  );
}
