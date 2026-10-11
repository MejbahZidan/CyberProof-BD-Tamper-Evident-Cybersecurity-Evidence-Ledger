import React from 'react';
import {
  ShieldAlert,
  HardDrive,
  Layers,
  Gauge,
  Sparkles,
  Award,
  Flame,
  FileCode2,
  UserCheck,
  ShieldCheck,
  RefreshCw,
  X,
  ChevronRight,
  Fingerprint,
} from 'lucide-react';
import { CyberProofLogo } from './CyberProofLogo';
import { ThemeToggle } from './ThemeToggle';
import type { UserSession, UserRole } from '../types/ledger';

export type TabKey = 'events' | 'evidence' | 'benchmarks' | 'ai' | 'checkpoints' | 'attacks' | 'ledger' | 'sandbox';

interface SidebarNavProps {
  activeTab: TabKey;
  onSelectTab: (tab: TabKey) => void;
  isDark: boolean;
  onToggleTheme: () => void;
  currentUser: UserSession | null;
  seedUsers: UserSession[];
  onSelectUser: (user: UserSession) => void;
  onOpenTeamModal: () => void;
  counts: {
    events: number;
    evidence: number;
    blocks: number;
    checkpoints: number;
  };
  isLoading: boolean;
  onRefresh: () => void;
  isOpenMobile: boolean;
  onCloseMobile: () => void;
}

export const SidebarNav: React.FC<SidebarNavProps> = ({
  activeTab,
  onSelectTab,
  isDark,
  onToggleTheme,
  currentUser,
  seedUsers,
  onSelectUser,
  onOpenTeamModal,
  counts,
  isLoading,
  onRefresh,
  isOpenMobile,
  onCloseMobile,
}) => {
  const navItems = [
    {
      key: 'events' as TabKey,
      label: 'Security Incidents',
      subtitle: 'Real-time Triage & Threats',
      icon: ShieldAlert,
      count: counts.events,
      color: 'cyan',
    },
    {
      key: 'evidence' as TabKey,
      label: 'Evidence Vault',
      subtitle: 'SHA-256 Byte Verification',
      icon: HardDrive,
      count: counts.evidence,
      color: 'cyan',
    },
    {
      key: 'ledger' as TabKey,
      label: 'Ledger Explorer',
      subtitle: 'Hash-Linked Blocks',
      icon: Layers,
      count: counts.blocks,
      color: 'cyan',
    },
    {
      key: 'benchmarks' as TabKey,
      label: 'Benchmarks & Proofs',
      subtitle: 'Throughput & Comparison',
      icon: Gauge,
      color: 'emerald',
    },
    {
      key: 'ai' as TabKey,
      label: 'AI Threat Analytics',
      subtitle: 'Forensic Anomaly Radar',
      icon: Sparkles,
      color: 'indigo',
    },
    {
      key: 'checkpoints' as TabKey,
      label: 'Trust Checkpoints',
      subtitle: 'Ed25519 External Anchor',
      icon: Award,
      count: counts.checkpoints,
      color: 'amber',
    },
    {
      key: 'attacks' as TabKey,
      label: '10 Attack Lab',
      subtitle: 'Adversarial Defense Proofs',
      icon: Flame,
      color: 'rose',
    },
    {
      key: 'sandbox' as TabKey,
      label: 'RFC 8785 Sandbox',
      subtitle: 'Canonical Hash Playground',
      icon: FileCode2,
      color: 'purple',
    },
  ];

  const getRoleBadgeColor = (role: UserRole) => {
    switch (role) {
      case 'admin':
        return isDark ? 'bg-rose-500/10 text-rose-400 border-rose-500/30' : 'bg-rose-50 text-rose-700 border-rose-300';
      case 'investigator':
        return isDark ? 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30' : 'bg-cyan-50 text-cyan-700 border-cyan-300';
      case 'auditor':
        return isDark ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30' : 'bg-emerald-50 text-emerald-700 border-emerald-300';
      default:
        return isDark ? 'bg-slate-800 text-slate-300 border-slate-700' : 'bg-slate-100 text-slate-700 border-slate-300';
    }
  };

  const getInitials = (name: string) => {
    const parts = name.replace(/Md\.\s*/i, '').trim().split(' ');
    if (parts.length >= 2) return `${parts[0][0]}${parts[1][0]}`.toUpperCase();
    return (name[0] || 'U').toUpperCase();
  };

  return (
    <>
      {/* Mobile Backdrop */}
      {isOpenMobile && (
        <div
          onClick={onCloseMobile}
          className="fixed inset-0 z-40 bg-black/60 backdrop-blur-sm lg:hidden"
        />
      )}

      {/* Left Sidebar Container */}
      <aside
        className={`fixed top-0 bottom-0 left-0 z-40 w-72 flex flex-col border-r transition-transform duration-300 lg:translate-x-0 ${
          isOpenMobile ? 'translate-x-0' : '-translate-x-full'
        } ${
          isDark
            ? 'bg-[#0b1120] border-slate-800/80 text-slate-200'
            : 'bg-white border-slate-200 text-slate-800 shadow-sm'
        }`}
      >
        {/* Brand Header */}
        <div className="p-5 border-b border-slate-200 dark:border-slate-800/80 flex items-center justify-between">
          <CyberProofLogo isDark={isDark} size="md" />
          <button
            onClick={onCloseMobile}
            className="lg:hidden p-1.5 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800/50"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Live System Status Pill */}
        <div className="px-5 pt-4 pb-2">
          <div
            className={`p-2.5 rounded-xl border flex items-center justify-between text-xs transition-all ${
              isDark
                ? 'bg-slate-950/70 border-slate-800/80'
                : 'bg-slate-50 border-slate-200'
            }`}
          >
            <div className="flex items-center gap-2">
              <span className="relative flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
              </span>
              <span className="font-mono text-[11px] font-semibold text-emerald-600 dark:text-emerald-400">
                100% INTACT
              </span>
            </div>
            <button
              onClick={onRefresh}
              title="Refresh ledger state"
              className={`p-1 rounded-md transition cursor-pointer ${
                isDark
                  ? 'hover:bg-slate-800 text-slate-400 hover:text-slate-200'
                  : 'hover:bg-slate-200 text-slate-600 hover:text-slate-900'
              }`}
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin text-cyan-400' : ''}`} />
            </button>
          </div>
        </div>

        {/* Vertical Navigation Links */}
        <nav className="flex-1 overflow-y-auto px-3 py-2 space-y-1">
          <div className="px-3 py-1.5 text-[10px] font-mono uppercase tracking-wider text-slate-400 dark:text-slate-500 font-semibold">
            Forensic Command Navigation
          </div>

          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.key;

            return (
              <button
                key={item.key}
                onClick={() => {
                  onSelectTab(item.key);
                  onCloseMobile();
                }}
                className={`w-full group flex items-center justify-between px-3.5 py-2.5 rounded-xl text-xs font-semibold transition-all duration-200 cursor-pointer ${
                  isActive
                    ? isDark
                      ? 'bg-gradient-to-r from-cyan-950/80 to-slate-900 text-cyan-300 border border-cyan-500/40 shadow-sm shadow-cyan-950'
                      : 'bg-cyan-50 text-cyan-900 border border-cyan-200 shadow-sm'
                    : isDark
                    ? 'text-slate-400 hover:text-slate-100 hover:bg-slate-900/60'
                    : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
                }`}
              >
                <div className="flex items-center gap-3">
                  <div
                    className={`w-8 h-8 rounded-lg flex items-center justify-center transition-colors ${
                      isActive
                        ? isDark
                          ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30'
                          : 'bg-cyan-100 text-cyan-700 border border-cyan-300'
                        : isDark
                        ? 'bg-slate-900 text-slate-400 group-hover:text-slate-200'
                        : 'bg-slate-100 text-slate-500 group-hover:text-slate-800'
                    }`}
                  >
                    <Icon className="w-4 h-4" />
                  </div>
                  <div className="text-left">
                    <div className="leading-tight">{item.label}</div>
                    <div className={`text-[10px] font-normal leading-tight ${isDark ? 'text-slate-500' : 'text-slate-400'}`}>
                      {item.subtitle}
                    </div>
                  </div>
                </div>

                {item.count !== undefined ? (
                  <span
                    className={`text-[11px] font-mono font-semibold px-2 py-0.5 rounded-full border ${
                      isActive
                        ? isDark
                          ? 'bg-cyan-500/20 text-cyan-300 border-cyan-500/30'
                          : 'bg-cyan-100 text-cyan-800 border-cyan-300'
                        : isDark
                        ? 'bg-slate-900 text-slate-400 border-slate-800'
                        : 'bg-slate-100 text-slate-600 border-slate-200'
                    }`}
                  >
                    {item.count}
                  </span>
                ) : (
                  <ChevronRight
                    className={`w-3.5 h-3.5 opacity-0 group-hover:opacity-100 transition-opacity ${
                      isActive ? 'opacity-100 text-cyan-400' : 'text-slate-400'
                    }`}
                  />
                )}
              </button>
            );
          })}
        </nav>

        {/* Bottom Section: Theme Toggle & Team Attribution */}
        <div className="p-4 border-t border-slate-200 dark:border-slate-800/80 space-y-3">
          {/* Light / Dark Mode Toggle Button */}
          <div
            className={`p-2.5 rounded-xl border flex items-center justify-between ${
              isDark ? 'bg-slate-950/60 border-slate-800/80' : 'bg-slate-50 border-slate-200'
            }`}
          >
            <ThemeToggle isDark={isDark} onToggle={onToggleTheme} showLabel={true} />
          </div>

          {/* Active Contributor Dropdown & Card */}
          {currentUser && (
            <div
              className={`p-3 rounded-xl border space-y-2 ${
                isDark ? 'bg-slate-950/80 border-slate-800/90' : 'bg-slate-50 border-slate-200'
              }`}
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <div
                    className={`w-7 h-7 rounded-lg flex items-center justify-center font-bold text-xs font-mono border ${
                      isDark
                        ? 'bg-slate-900 text-cyan-400 border-cyan-500/30'
                        : 'bg-white text-cyan-700 border-slate-200'
                    }`}
                  >
                    {getInitials(currentUser.username)}
                  </div>
                  <div className="text-left">
                    <div className="text-xs font-bold leading-tight truncate max-w-[130px]">
                      {currentUser.username}
                    </div>
                    <div className="text-[10px] text-cyan-600 dark:text-cyan-400 font-semibold leading-tight truncate max-w-[130px]">
                      {currentUser.organization}
                    </div>
                  </div>
                </div>

                <span className={`text-[9px] font-mono font-bold px-1.5 py-0.5 rounded border ${getRoleBadgeColor(currentUser.role)}`}>
                  {currentUser.role.toUpperCase()}
                </span>
              </div>

              {/* Selector to switch between the 4 team members */}
              <select
                aria-label="Switch contributor"
                className={`w-full text-xs font-medium px-2 py-1.5 rounded-lg border focus:outline-none cursor-pointer transition ${
                  isDark
                    ? 'bg-slate-900 border-slate-700 text-slate-200 focus:border-cyan-500'
                    : 'bg-white border-slate-300 text-slate-800 focus:border-cyan-500'
                }`}
                value={currentUser.userId}
                onChange={(e) => {
                  const target = seedUsers.find((u) => u.userId === e.target.value);
                  if (target) onSelectUser(target);
                }}
              >
                {seedUsers.map((u) => (
                  <option key={u.userId} value={u.userId}>
                    {u.username} • {u.organization}
                  </option>
                ))}
              </select>
            </div>
          )}

          {/* Forensic Systems Division Attribution Badge Button */}
          <button
            onClick={onOpenTeamModal}
            className={`w-full py-2 px-3 rounded-xl border text-[11px] font-semibold flex items-center justify-center gap-2 transition cursor-pointer ${
              isDark
                ? 'bg-cyan-950/40 border-cyan-500/30 text-cyan-400 hover:bg-cyan-900/50 hover:border-cyan-400'
                : 'bg-cyan-50 border-cyan-300 text-cyan-800 hover:bg-cyan-100 hover:border-cyan-400'
            }`}
          >
            <ShieldCheck className="w-3.5 h-3.5" />
            <span>Forensic Systems Division (4)</span>
          </button>
        </div>
      </aside>
    </>
  );
};
