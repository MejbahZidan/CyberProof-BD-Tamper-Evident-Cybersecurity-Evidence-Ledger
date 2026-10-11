import React from 'react';
import { ShieldCheck, X, Award, CheckCircle2, Lock } from 'lucide-react';
import { CyberProofLogo } from './CyberProofLogo';

interface TeamModalProps {
  isOpen: boolean;
  onClose: () => void;
  isDark: boolean;
}

export const TeamModal: React.FC<TeamModalProps> = ({ isOpen, onClose, isDark }) => {
  if (!isOpen) return null;

  const team = [
    {
      name: 'Md. Mejbaul Islam Zidan',
      role: 'Lead Blockchain Architect',
      initials: 'MZ',
      badge: 'ARCHITECT',
      badgeColor: isDark ? 'text-cyan-400 bg-cyan-950/80 border-cyan-500/30' : 'text-cyan-700 bg-cyan-100 border-cyan-300',
      description:
        'Architected deterministic RFC 8785 JSON canonicalization, Proof-of-Work difficulty target algorithms, Merkle tree commitments, and hash-chain linkage invariants.',
    },
    {
      name: 'Md. Mainul Islam',
      role: 'Cryptographic Security Analyst',
      initials: 'MI',
      badge: 'CRYPTO',
      badgeColor: isDark ? 'text-indigo-400 bg-indigo-950/80 border-indigo-500/30' : 'text-indigo-700 bg-indigo-100 border-indigo-300',
      description:
        'Engineered SHA-256 byte digest pipelines, collision-resistant evidence commitments, zero-knowledge verification proofs, and Edwards-curve Ed25519 authentication keys.',
    },
    {
      name: 'Kamrun Nahar',
      role: 'Compliance & Forensic Auditor',
      initials: 'KN',
      badge: 'AUDITOR',
      badgeColor: isDark ? 'text-emerald-400 bg-emerald-950/80 border-emerald-500/30' : 'text-emerald-700 bg-emerald-100 border-emerald-300',
      description:
        'Formulated court-admissible chain-of-custody verification rules, statutory compliance auditing, ISO/IEC 27037 digital evidence standards, and witness checkpoint protocols.',
    },
    {
      name: 'Anzuman Islam',
      role: 'SOC Lead & Incident Responder',
      initials: 'AI',
      badge: 'SOC-LEAD',
      badgeColor: isDark ? 'text-rose-400 bg-rose-950/80 border-rose-500/30' : 'text-rose-700 bg-rose-100 border-rose-300',
      description:
        'Standardized security incident categorization (C2, Exfiltration, Privilege Escalation), threat telemetry correlation, and real-time adversarial attack detection.',
    },
  ];

  return (
    <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm flex items-center justify-center p-4 transition-all">
      <div
        className={`rounded-2xl max-w-2xl w-full p-6 shadow-2xl relative space-y-5 border transition-all ${
          isDark
            ? 'bg-slate-900 border-slate-700/80 text-slate-100 shadow-cyan-950/30'
            : 'bg-white border-slate-200 text-slate-900 shadow-slate-300'
        }`}
      >
        {/* Header */}
        <div className="flex items-center justify-between pb-4 border-b border-slate-200 dark:border-slate-800">
          <div className="flex items-center gap-3">
            <CyberProofLogo size="sm" isDark={isDark} showWordmark={false} />
            <div>
              <h3 className="text-base font-bold flex items-center gap-2">
                Forensic Systems Division
                <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-cyan-500/10 text-cyan-500 border border-cyan-500/30 font-semibold">
                  CORE TEAM
                </span>
              </h3>
              <p className={`text-xs ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>
                Core Architecture, Cryptography & Forensic Ledger Engineering
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            aria-label="Close modal"
            className={`p-1.5 rounded-lg transition cursor-pointer ${
              isDark
                ? 'text-slate-400 hover:text-white hover:bg-slate-800'
                : 'text-slate-500 hover:text-slate-900 hover:bg-slate-100'
            }`}
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Contributor Cards */}
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3.5">
          {team.map((member) => (
            <div
              key={member.name}
              className={`p-4 rounded-xl border transition-all hover:scale-[1.01] ${
                isDark
                  ? 'bg-slate-950/70 border-slate-800/80 hover:border-cyan-500/40'
                  : 'bg-slate-50 border-slate-200 hover:border-cyan-400 hover:shadow-sm'
              }`}
            >
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-2.5">
                  <div
                    className={`w-8 h-8 rounded-lg flex items-center justify-center font-mono font-bold text-xs border ${
                      isDark
                        ? 'bg-slate-800 text-cyan-300 border-slate-700'
                        : 'bg-white text-cyan-700 border-slate-200 shadow-sm'
                    }`}
                  >
                    {member.initials}
                  </div>
                  <div>
                    <div className="text-xs font-bold leading-tight">{member.name}</div>
                    <div className="text-[11px] font-semibold text-cyan-600 dark:text-cyan-400 leading-tight">
                      {member.role}
                    </div>
                  </div>
                </div>
                <span className={`text-[9px] font-mono font-bold px-1.5 py-0.5 rounded border ${member.badgeColor}`}>
                  {member.badge}
                </span>
              </div>
              <p className={`text-[11px] leading-relaxed ${isDark ? 'text-slate-400' : 'text-slate-600'}`}>
                {member.description}
              </p>
            </div>
          ))}
        </div>

        {/* Footer info & close */}
        <div className="pt-2 flex items-center justify-between border-t border-slate-200 dark:border-slate-800 text-xs">
          <div className="flex items-center gap-1.5 text-[11px] font-mono text-slate-500 dark:text-slate-400">
            <Lock className="w-3.5 h-3.5 text-emerald-500" />
            <span>Zero-Trust Cryptographic Immutability Guaranteed</span>
          </div>
          <button
            onClick={onClose}
            className={`px-4 py-2 rounded-lg font-semibold transition cursor-pointer text-xs ${
              isDark
                ? 'bg-slate-800 hover:bg-slate-700 text-slate-200'
                : 'bg-slate-100 hover:bg-slate-200 text-slate-800'
            }`}
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
