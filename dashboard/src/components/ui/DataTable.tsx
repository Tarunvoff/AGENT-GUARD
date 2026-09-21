import React from 'react';
import { ChevronLeft, ChevronRight, Inbox } from 'lucide-react';

export interface Column<T = any> {
  key: string;
  header: string;
  render?: (row: T, index?: number) => React.ReactNode;
  width?: string;
  align?: 'left' | 'center' | 'right';
  mono?: boolean;
}

export interface DataTableProps<T = any> {
  columns: Column<T>[];
  data: T[];
  keyExtractor?: (row: T, index: number) => string;
  keyField?: string;
  onRowClick?: (row: T) => void;
  selectedKey?: string | null;
  emptyMessage?: string;
  emptySubtext?: string;
  pageSize?: number;
  isLoading?: boolean;
}

export function DataTable<T = any>({
  columns,
  data,
  keyExtractor,
  keyField,
  onRowClick,
  selectedKey,
  emptyMessage = 'No records found',
  emptySubtext = 'Try adjusting your filters or search query.',
  pageSize = 15,
  isLoading = false,
}: DataTableProps<T>) {
  const [currentPage, setCurrentPage] = React.useState(1);

  const totalPages = Math.max(1, Math.ceil(data.length / pageSize));
  const paginatedData = data.slice(
    (currentPage - 1) * pageSize,
    currentPage * pageSize
  );

  React.useEffect(() => {
    setCurrentPage(1);
  }, [data.length]);

  const getRowKey = (row: T, idx: number): string => {
    if (keyExtractor) return keyExtractor(row, idx);
    if (keyField && (row as any)[keyField]) return String((row as any)[keyField]);
    return String((row as any).id || (row as any).key || idx);
  };

  return (
    <div className="bg-white border border-slate-200 rounded-lg shadow-sm overflow-hidden flex flex-col">
      <div className="overflow-x-auto">
        <table className="w-full text-left border-collapse text-xs">
          <thead>
            <tr className="bg-slate-50 border-b border-slate-200">
              {columns.map((col) => (
                <th
                  key={col.key}
                  style={{ width: col.width }}
                  className={`px-3.5 py-2.5 font-semibold text-slate-600 uppercase tracking-wider text-[10px] ${
                    col.align === 'right'
                      ? 'text-right'
                      : col.align === 'center'
                      ? 'text-center'
                      : 'text-left'
                  }`}
                >
                  {col.header}
                </th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100">
            {isLoading ? (
              <tr>
                <td colSpan={columns.length} className="py-12 text-center text-slate-400">
                  <div className="inline-block animate-spin rounded-full h-5 w-5 border-2 border-slate-300 border-t-sky-600 mb-2" />
                  <div className="text-xs">Loading telemetry records…</div>
                </td>
              </tr>
            ) : paginatedData.length === 0 ? (
              <tr>
                <td colSpan={columns.length} className="py-12 text-center">
                  <Inbox size={28} className="mx-auto text-slate-300 mb-2" />
                  <div className="text-sm font-semibold text-slate-700">{emptyMessage}</div>
                  <div className="text-xs text-slate-400 mt-0.5">{emptySubtext}</div>
                </td>
              </tr>
            ) : (
              paginatedData.map((row, idx) => {
                const rowKey = getRowKey(row, idx);
                const isSelected = selectedKey === rowKey;
                return (
                  <tr
                    key={rowKey}
                    onClick={() => onRowClick && onRowClick(row)}
                    className={`transition-colors ${
                      isSelected
                        ? 'bg-sky-50/80 font-medium'
                        : 'hover:bg-slate-50/80'
                    } ${onRowClick ? 'cursor-pointer' : ''}`}
                  >
                    {columns.map((col) => {
                      const val = (row as Record<string, unknown>)[col.key];
                      const rendered = col.render ? col.render(row, idx) : (val as React.ReactNode);
                      return (
                        <td
                          key={col.key}
                          className={`px-3.5 py-2.5 text-slate-700 ${
                            col.mono ? 'font-mono text-[11px]' : ''
                          } ${
                            col.align === 'right'
                              ? 'text-right'
                              : col.align === 'center'
                              ? 'text-center'
                              : 'text-left'
                          }`}
                        >
                          {rendered}
                        </td>
                      );
                    })}
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination Footer */}
      {data.length > pageSize && (
        <div className="px-4 py-2.5 border-t border-slate-200 bg-slate-50 flex items-center justify-between text-xs text-slate-500">
          <div>
            Showing <span className="font-medium text-slate-800">{(currentPage - 1) * pageSize + 1}</span> to{' '}
            <span className="font-medium text-slate-800">
              {Math.min(currentPage * pageSize, data.length)}
            </span>{' '}
            of <span className="font-medium text-slate-800">{data.length}</span> records
          </div>
          <div className="flex items-center gap-1">
            <button
              onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
              disabled={currentPage === 1}
              className="p-1 rounded border border-slate-200 bg-white text-slate-600 disabled:opacity-40 disabled:cursor-not-allowed hover:bg-slate-50 transition-colors"
            >
              <ChevronLeft size={14} />
            </button>
            <span className="px-2 font-mono text-[11px]">
              {currentPage} / {totalPages}
            </span>
            <button
              onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
              disabled={currentPage === totalPages}
              className="p-1 rounded border border-slate-200 bg-white text-slate-600 disabled:opacity-40 disabled:cursor-not-allowed hover:bg-slate-50 transition-colors"
            >
              <ChevronRight size={14} />
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
