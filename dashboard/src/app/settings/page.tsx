'use client';

import { useState } from 'react';
import { Settings, Shield, Bell, Database, Cpu, Key, Save, CheckCircle2, Sliders } from 'lucide-react';
import { PageHeader } from '@/components/ui/PageHeader';
import { StatusBadge } from '@/components/ui/StatusBadge';

const SECTIONS = [
  {
    id: 'general',
    label: 'General & Runtime',
    icon: Settings,
    settings: [
      { key: 'enforcement_mode', label: 'Enforcement Mode', type: 'select', value: 'STRICT', options: ['STRICT', 'MONITOR', 'AUDIT'] },
      { key: 'fail_safe', label: 'Fail-Safe on AI Unavailability', type: 'toggle', value: true, desc: 'Fail-safe block all tainted actions if semantic reasoning is unreachable' },
      { key: 'audit_all', label: 'Audit All Decision Events', type: 'toggle', value: true, desc: 'Persist cryptographically signed nonces for every action request' },
      { key: 'dashboard_refresh_ms', label: 'Dashboard Polling Interval (ms)', type: 'number', value: 2500 },
    ],
  },
  {
    id: 'policy',
    label: 'Policy Engine',
    icon: Shield,
    settings: [
      { key: 'max_delegation_depth', label: 'Max Delegation Depth before HITL', type: 'number', value: 3 },
      { key: 'hitl_timeout_s', label: 'HITL Review Timeout (seconds)', type: 'number', value: 300 },
      { key: 'taint_propagation', label: 'Taint Propagation Enabled', type: 'toggle', value: true, desc: 'Track context taint across agent memory and tool outputs' },
      { key: 'block_on_unknown_tool', label: 'Block Unregistered Tools', type: 'toggle', value: true, desc: 'Zero trust enforcement on unverified tool identifiers' },
    ],
  },
  {
    id: 'ai_secura',
    label: 'AI Secura Intelligence',
    icon: Cpu,
    settings: [
      { key: 'ai_provider', label: 'AI Reasoning Provider', type: 'select', value: 'ollama', options: ['ollama', 'openai', 'anthropic', 'none'] },
      { key: 'ai_model', label: 'Local Model Reference', type: 'text', value: 'agentguard-threat-v1' },
      { key: 'ai_timeout_ms', label: 'Reasoning Timeout (ms)', type: 'number', value: 5000 },
      { key: 'ai_override_policy', label: 'AI Can Override Policy', type: 'toggle', value: false, readonly: true, desc: 'LOCKED: Architectural Invariant prohibits AI from bypassing policy rules' },
    ],
  },
  {
    id: 'apiris',
    label: 'APIRIS Scoring',
    icon: Database,
    settings: [
      { key: 'apiris_enabled', label: 'APIRIS Engine Enabled', type: 'toggle', value: true, desc: 'Real-time structural payload scoring' },
      { key: 'apiris_block_threshold', label: 'Deterministic Block Threshold', type: 'number', value: 0.8 },
      { key: 'apiris_hitl_threshold', label: 'HITL Escalation Threshold', type: 'number', value: 0.5 },
      { key: 'apiris_timeout_ms', label: 'Scoring Timeout (ms)', type: 'number', value: 3000 },
    ],
  },
  {
    id: 'alerts',
    label: 'Alerts & Webhooks',
    icon: Bell,
    settings: [
      { key: 'alert_on_block', label: 'Alert on Every Policy Block', type: 'toggle', value: true },
      { key: 'alert_on_bypass', label: 'Alert on Red-Team Bypass Detection', type: 'toggle', value: true },
      { key: 'alert_on_hitl', label: 'Alert on HITL Escalation Queue', type: 'toggle', value: true },
      { key: 'webhook_url', label: 'Webhook Notification Endpoint', type: 'text', value: 'https://security-ops.internal/hooks/agentguard' },
    ],
  },
];

export default function SettingsPage() {
  const [activeSection, setActiveSection] = useState('general');
  const [saved, setSaved] = useState(false);
  const section = SECTIONS.find(s => s.id === activeSection)!;

  const handleSave = () => {
    setSaved(true);
    setTimeout(() => setSaved(false), 2500);
  };

  return (
    <div className="p-8 space-y-6 max-w-7xl mx-auto">
      <PageHeader
        title="Runtime Configuration & Settings"
        subtitle="Manage zero-trust policies, fail-safe rules, intelligence thresholds, and webhook endpoints"
        badge="Settings"
        actions={
          <button
            onClick={handleSave}
            className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-md bg-blue-600 hover:bg-blue-700 text-white text-xs font-medium transition-colors shadow-2xs"
          >
            {saved ? <CheckCircle2 size={13} /> : <Save size={13} />}
            <span>{saved ? 'Saved Successfully' : 'Save Changes'}</span>
          </button>
        }
      />

      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        {/* Navigation Sidebar */}
        <div className="space-y-1">
          {SECTIONS.map(s => {
            const Icon = s.icon;
            const isActive = activeSection === s.id;
            return (
              <button
                key={s.id}
                onClick={() => setActiveSection(s.id)}
                className={`w-full flex items-center gap-2.5 px-3 py-2.5 rounded-lg text-xs font-medium text-left transition-colors ${
                  isActive
                    ? 'bg-blue-50 text-blue-800 font-semibold border border-blue-200'
                    : 'text-slate-600 hover:bg-slate-100 border border-transparent'
                }`}
              >
                <Icon size={14} className={isActive ? 'text-blue-700' : 'text-slate-400'} />
                <span>{s.label}</span>
              </button>
            );
          })}
        </div>

        {/* Form Area */}
        <div className="md:col-span-3 bg-white border border-slate-200 rounded-lg p-6 shadow-xs space-y-6">
          <div className="flex items-center justify-between pb-4 border-b border-slate-200">
            <h2 className="text-sm font-bold text-slate-900">{section.label} Settings</h2>
            <span className="text-[11px] text-slate-500 font-mono">Scope: runtime_active</span>
          </div>

          <div className="space-y-5">
            {section.settings.map(st => (
              <div key={st.key} className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-slate-100 last:border-0 last:pb-0">
                <div className="max-w-md">
                  <label className="text-xs font-semibold text-slate-900 block">{st.label}</label>
                  {(st as any).desc && (
                    <p className="text-[11px] text-slate-500 mt-0.5 leading-relaxed">{(st as any).desc}</p>
                  )}
                </div>

                <div className="flex-shrink-0">
                  {st.type === 'toggle' && (
                    <div className="flex items-center gap-2">
                      <span className={`text-[11px] font-medium ${(st as any).readonly ? 'text-slate-400' : st.value ? 'text-blue-700' : 'text-slate-500'}`}>
                        {st.value ? 'Enabled' : 'Disabled'}
                      </span>
                      {(st as any).readonly && (
                        <span className="text-[10px] bg-slate-100 text-slate-600 px-1.5 py-0.5 rounded border border-slate-200 font-mono">
                          LOCKED
                        </span>
                      )}
                    </div>
                  )}

                  {st.type === 'select' && (
                    <select
                      defaultValue={String(st.value)}
                      className="px-3 py-1.5 bg-slate-50 border border-slate-200 rounded-md text-xs text-slate-800 focus:outline-none focus:border-blue-500"
                    >
                      {(st as any).options.map((opt: string) => (
                        <option key={opt} value={opt}>{opt}</option>
                      ))}
                    </select>
                  )}

                  {st.type === 'number' && (
                    <input
                      type="number"
                      defaultValue={Number(st.value)}
                      className="w-24 px-3 py-1.5 bg-slate-50 border border-slate-200 rounded-md text-xs font-mono text-slate-800 focus:outline-none focus:border-blue-500 text-right"
                    />
                  )}

                  {st.type === 'text' && (
                    <input
                      type="text"
                      defaultValue={String(st.value)}
                      className="w-64 px-3 py-1.5 bg-slate-50 border border-slate-200 rounded-md text-xs font-mono text-slate-800 focus:outline-none focus:border-blue-500"
                    />
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
