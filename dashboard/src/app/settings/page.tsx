'use client';

import { useState } from 'react';
import { Settings, Shield, Bell, Database, Cpu, Key, Save, CheckCircle2 } from 'lucide-react';

const SECTIONS = [
  {
    id: 'general',
    label: 'General',
    icon: Settings,
    settings: [
      { key: 'enforcement_mode', label: 'Enforcement Mode', type: 'select', value: 'STRICT', options: ['STRICT', 'MONITOR', 'AUDIT'] },
      { key: 'fail_safe', label: 'Fail-Safe on AI Unavailability', type: 'toggle', value: true },
      { key: 'audit_all', label: 'Audit All Decisions', type: 'toggle', value: true },
      { key: 'dashboard_refresh_ms', label: 'Dashboard Refresh (ms)', type: 'number', value: 2200 },
    ],
  },
  {
    id: 'policy',
    label: 'Policy Engine',
    icon: Shield,
    settings: [
      { key: 'max_delegation_depth', label: 'Max Delegation Depth before HITL', type: 'number', value: 3 },
      { key: 'hitl_timeout_s', label: 'HITL Review Timeout (s)', type: 'number', value: 300 },
      { key: 'taint_propagation', label: 'Taint Propagation Enabled', type: 'toggle', value: true },
      { key: 'block_on_unknown_tool', label: 'Block Unknown Tools', type: 'toggle', value: true },
    ],
  },
  {
    id: 'ai_secura',
    label: 'AI Secura',
    icon: Cpu,
    settings: [
      { key: 'ai_provider', label: 'AI Provider', type: 'select', value: 'ollama', options: ['ollama', 'openai', 'anthropic', 'none'] },
      { key: 'ai_model', label: 'Local Model', type: 'text', value: 'agentguard-threat-v1' },
      { key: 'ai_timeout_ms', label: 'AI Analysis Timeout (ms)', type: 'number', value: 5000 },
      { key: 'ai_override_policy', label: 'AI Can Override Policy', type: 'toggle', value: false, readonly: true },
    ],
  },
  {
    id: 'apiris',
    label: 'APIRIS',
    icon: Database,
    settings: [
      { key: 'apiris_enabled', label: 'APIRIS Enabled', type: 'toggle', value: true },
      { key: 'apiris_block_threshold', label: 'Block Threshold', type: 'number', value: 0.8 },
      { key: 'apiris_hitl_threshold', label: 'HITL Threshold', type: 'number', value: 0.5 },
      { key: 'apiris_timeout_ms', label: 'APIRIS Timeout (ms)', type: 'number', value: 3000 },
    ],
  },
  {
    id: 'alerts',
    label: 'Alerts',
    icon: Bell,
    settings: [
      { key: 'alert_on_block', label: 'Alert on Every Block', type: 'toggle', value: true },
      { key: 'alert_on_bypass', label: 'Alert on Bypass Detection', type: 'toggle', value: true },
      { key: 'alert_on_hitl', label: 'Alert on HITL Escalation', type: 'toggle', value: true },
      { key: 'webhook_url', label: 'Webhook URL (optional)', type: 'text', value: '' },
    ],
  },
];

export default function SettingsPage() {
  const [activeSection, setActiveSection] = useState('general');
  const [saved, setSaved] = useState(false);
  const section = SECTIONS.find(s => s.id === activeSection)!;

  const handleSave = () => {
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  };

  return (
    <div className="p-6 space-y-5 min-h-screen bg-[#090d16]">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-white flex items-center gap-2">
            <Settings size={18} className="text-zinc-400" />
            Settings
          </h1>
          <p className="text-sm text-zinc-500 mt-1">AgentGuard runtime configuration</p>
        </div>
        <button onClick={handleSave} className="flex items-center gap-2 px-4 py-2 rounded-lg bg-sky-600 hover:bg-sky-500 text-white text-sm font-medium transition-colors">
          {saved ? <CheckCircle2 size={14} /> : <Save size={14} />}
          {saved ? 'Saved!' : 'Save Changes'}
        </button>
      </div>

      <div className="grid grid-cols-4 gap-4">
        {/* Sidebar */}
        <div className="space-y-1">
          {SECTIONS.map(s => {
            const Icon = s.icon;
            return (
              <button
                key={s.id}
                onClick={() => setActiveSection(s.id)}
                className={`w-full flex items-center gap-2.5 px-3 py-2.5 rounded-lg text-sm font-medium text-left transition-all ${
                  activeSection === s.id
                    ? 'bg-sky-500/10 text-sky-300 border border-sky-500/20'
                    : 'text-zinc-400 hover:text-zinc-200 hover:bg-white/[0.04]'
                }`}
              >
                <Icon size={14} className={activeSection === s.id ? 'text-sky-400' : 'text-zinc-500'} />
                {s.label}
              </button>
            );
          })}
        </div>

        {/* Settings Panel */}
        <div className="col-span-3 rounded-xl border border-zinc-800/50 bg-zinc-900/30 p-5 space-y-5">
          <div className="flex items-center gap-2 mb-2">
            {(() => { const Icon = section.icon; return <Icon size={16} className="text-zinc-400" />; })()}
            <h2 className="text-base font-semibold text-zinc-200">{section.label}</h2>
          </div>

          <div className="space-y-4">
            {section.settings.map(setting => (
              <div key={setting.key} className="flex items-center justify-between py-3 border-b border-zinc-800/50 last:border-0">
                <div>
                  <div className="text-sm text-zinc-200 font-medium">{setting.label}</div>
                  <div className="text-[11px] text-zinc-600 font-mono mt-0.5">{setting.key}</div>
                  {(setting as any).readonly && (
                    <div className="text-[10px] text-red-400 mt-0.5">⚠ Cannot be changed — security invariant</div>
                  )}
                </div>
                <div className="flex-shrink-0 ml-4">
                  {setting.type === 'toggle' && (
                    <div className={`relative w-10 h-5 rounded-full transition-colors ${(setting as any).readonly ? 'cursor-not-allowed opacity-50' : 'cursor-pointer'} ${setting.value ? 'bg-sky-500' : 'bg-zinc-700'}`}>
                      <div className={`absolute top-0.5 left-0.5 w-4 h-4 bg-white rounded-full shadow transition-transform ${setting.value ? 'translate-x-5' : 'translate-x-0'}`} />
                    </div>
                  )}
                  {setting.type === 'select' && (
                    <select
                      defaultValue={setting.value as string}
                      className="bg-zinc-800/80 border border-zinc-700/50 text-zinc-200 text-sm rounded-lg px-3 py-1.5 focus:outline-none focus:border-sky-500/50"
                    >
                      {(setting as any).options?.map((o: string) => <option key={o}>{o}</option>)}
                    </select>
                  )}
                  {setting.type === 'number' && (
                    <input
                      type="number"
                      defaultValue={setting.value as number}
                      className="bg-zinc-800/80 border border-zinc-700/50 text-zinc-200 text-sm rounded-lg px-3 py-1.5 w-24 focus:outline-none focus:border-sky-500/50 text-right"
                    />
                  )}
                  {setting.type === 'text' && (
                    <input
                      type="text"
                      defaultValue={setting.value as string}
                      placeholder="Not set"
                      className="bg-zinc-800/80 border border-zinc-700/50 text-zinc-200 text-sm rounded-lg px-3 py-1.5 w-48 focus:outline-none focus:border-sky-500/50"
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
