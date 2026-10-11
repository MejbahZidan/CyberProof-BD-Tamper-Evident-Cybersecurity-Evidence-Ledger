import React from 'react';
import { ShieldAlert, X, PlusCircle } from 'lucide-react';
import type { EventSeverity, EventCategory } from '../types/ledger';

interface NewEventModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSubmit: (e: React.FormEvent) => void;
  isDark: boolean;
  isSubmitting: boolean;
  title: string;
  setTitle: (v: string) => void;
  severity: EventSeverity;
  setSeverity: (v: EventSeverity) => void;
  category: EventCategory;
  setCategory: (v: EventCategory) => void;
  sourceHost: string;
  setSourceHost: (v: string) => void;
  sourceIp: string;
  setSourceIp: (v: string) => void;
  description: string;
  setDescription: (v: string) => void;
  evidenceRef: string;
  setEvidenceRef: (v: string) => void;
}

export const NewEventModal: React.FC<NewEventModalProps> = ({
  isOpen,
  onClose,
  onSubmit,
  isDark,
  isSubmitting,
  title,
  setTitle,
  severity,
  setSeverity,
  category,
  setCategory,
  sourceHost,
  setSourceHost,
  sourceIp,
  setSourceIp,
  description,
  setDescription,
  evidenceRef,
  setEvidenceRef,
}) => {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm flex items-center justify-center p-4">
      <div
        className={`rounded-2xl max-w-lg w-full p-6 space-y-4 shadow-2xl border transition-all ${
          isDark
            ? 'bg-slate-900 border-slate-700/80 text-slate-100'
            : 'bg-white border-slate-200 text-slate-900'
        }`}
      >
        <div className="flex items-center justify-between border-b pb-3 border-slate-200 dark:border-slate-800">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-rose-500/10 border border-rose-500/30 flex items-center justify-center text-rose-500">
              <ShieldAlert className="w-4 h-4" />
            </div>
            <h3 className="font-bold text-sm">Record Security Incident</h3>
          </div>
          <button
            onClick={onClose}
            className={`p-1.5 rounded-lg transition ${
              isDark
                ? 'text-slate-400 hover:text-white hover:bg-slate-800'
                : 'text-slate-500 hover:text-slate-900 hover:bg-slate-100'
            }`}
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <form onSubmit={onSubmit} className="space-y-3.5 text-xs">
          <div>
            <label className="block text-slate-500 dark:text-slate-400 mb-1 font-semibold">
              Incident Title
            </label>
            <input
              type="text"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              className={`w-full rounded-xl border px-3 py-2 text-xs focus:outline-none focus:ring-2 focus:ring-cyan-500/40 transition ${
                isDark
                  ? 'bg-slate-950 border-slate-800 text-slate-200'
                  : 'bg-slate-50 border-slate-200 text-slate-800'
              }`}
              required
            />
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-slate-500 dark:text-slate-400 mb-1 font-semibold">
                Severity
              </label>
              <select
                value={severity}
                onChange={(e) => setSeverity(e.target.value as EventSeverity)}
                className={`w-full rounded-xl border px-3 py-2 text-xs focus:outline-none focus:ring-2 focus:ring-cyan-500/40 transition ${
                  isDark
                    ? 'bg-slate-950 border-slate-800 text-slate-200'
                    : 'bg-slate-50 border-slate-200 text-slate-800'
                }`}
              >
                <option value="CRITICAL">CRITICAL</option>
                <option value="HIGH">HIGH</option>
                <option value="MEDIUM">MEDIUM</option>
                <option value="LOW">LOW</option>
                <option value="INFORMATIONAL">INFORMATIONAL</option>
              </select>
            </div>
            <div>
              <label className="block text-slate-500 dark:text-slate-400 mb-1 font-semibold">
                Category
              </label>
              <select
                value={category}
                onChange={(e) => setCategory(e.target.value as EventCategory)}
                className={`w-full rounded-xl border px-3 py-2 text-xs focus:outline-none focus:ring-2 focus:ring-cyan-500/40 transition ${
                  isDark
                    ? 'bg-slate-950 border-slate-800 text-slate-200'
                    : 'bg-slate-50 border-slate-200 text-slate-800'
                }`}
              >
                <option value="UNAUTHORIZED_ACCESS">UNAUTHORIZED_ACCESS</option>
                <option value="MALWARE_DETECTION">MALWARE_DETECTION</option>
                <option value="DATA_EXFILTRATION">DATA_EXFILTRATION</option>
                <option value="PRIVILEGE_ESCALATION">PRIVILEGE_ESCALATION</option>
                <option value="INTEGRITY_VIOLATION">INTEGRITY_VIOLATION</option>
              </select>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-slate-500 dark:text-slate-400 mb-1 font-semibold">
                Source Host
              </label>
              <input
                type="text"
                value={sourceHost}
                onChange={(e) => setSourceHost(e.target.value)}
                className={`w-full rounded-xl border px-3 py-2 text-xs focus:outline-none focus:ring-2 focus:ring-cyan-500/40 transition ${
                  isDark
                    ? 'bg-slate-950 border-slate-800 text-slate-200'
                    : 'bg-slate-50 border-slate-200 text-slate-800'
                }`}
              />
            </div>
            <div>
              <label className="block text-slate-500 dark:text-slate-400 mb-1 font-semibold">
                Source IP
              </label>
              <input
                type="text"
                value={sourceIp}
                onChange={(e) => setSourceIp(e.target.value)}
                className={`w-full rounded-xl border px-3 py-2 text-xs focus:outline-none focus:ring-2 focus:ring-cyan-500/40 transition ${
                  isDark
                    ? 'bg-slate-950 border-slate-800 text-slate-200'
                    : 'bg-slate-50 border-slate-200 text-slate-800'
                }`}
              />
            </div>
          </div>

          <div>
            <label className="block text-slate-500 dark:text-slate-400 mb-1 font-semibold">
              Description & Evidence Log
            </label>
            <textarea
              rows={3}
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              className={`w-full rounded-xl border p-2.5 text-xs resize-none focus:outline-none focus:ring-2 focus:ring-cyan-500/40 transition ${
                isDark
                  ? 'bg-slate-950 border-slate-800 text-slate-200'
                  : 'bg-slate-50 border-slate-200 text-slate-800'
              }`}
              required
            />
          </div>

          <div className="pt-2 flex justify-end gap-2 border-t border-slate-200 dark:border-slate-800">
            <button
              type="button"
              onClick={onClose}
              className={`px-4 py-2 rounded-xl font-semibold cursor-pointer ${
                isDark
                  ? 'bg-slate-800 hover:bg-slate-700 text-slate-300'
                  : 'bg-slate-100 hover:bg-slate-200 text-slate-700'
              }`}
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={isSubmitting}
              className="px-4 py-2 rounded-xl bg-gradient-to-r from-cyan-600 to-emerald-600 hover:from-cyan-500 hover:to-emerald-500 text-white font-semibold flex items-center gap-2 cursor-pointer shadow-md shadow-cyan-950/40"
            >
              <PlusCircle className="w-4 h-4" />
              {isSubmitting ? 'Hashing...' : 'Commit to Ledger'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
