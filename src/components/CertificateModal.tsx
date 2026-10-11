import React from 'react';
import { Award, Download, X, ShieldCheck, CheckCircle2 } from 'lucide-react';
import type { ForensicEvidenceCertificate } from '../types/ledger';

interface CertificateModalProps {
  certificate: ForensicEvidenceCertificate | null;
  onClose: () => void;
  onDownload: () => void;
  isDark: boolean;
}

export const CertificateModal: React.FC<CertificateModalProps> = ({
  certificate,
  onClose,
  onDownload,
  isDark,
}) => {
  if (!certificate) return null;

  return (
    <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm flex items-center justify-center p-4">
      <div
        className={`rounded-2xl max-w-xl w-full p-6 shadow-2xl relative space-y-4 border transition-all ${
          isDark
            ? 'bg-slate-900 border-slate-700/80 text-slate-100'
            : 'bg-white border-slate-200 text-slate-900'
        }`}
      >
        <div className="flex items-center justify-between border-b pb-3 border-slate-200 dark:border-slate-800">
          <div className="flex items-center gap-2.5">
            <div className="w-9 h-9 rounded-xl bg-indigo-500/10 border border-indigo-500/30 flex items-center justify-center text-indigo-500">
              <Award className="w-5 h-5" />
            </div>
            <div>
              <h3 className="font-bold text-sm leading-tight">Court-Admissible Evidence Certificate</h3>
              <div className="text-[11px] font-mono text-indigo-500 dark:text-indigo-400">
                {certificate.certificateId}
              </div>
            </div>
          </div>
          <button
            onClick={onClose}
            className={`p-1 rounded-lg transition ${
              isDark
                ? 'text-slate-400 hover:text-white hover:bg-slate-800'
                : 'text-slate-500 hover:text-slate-900 hover:bg-slate-100'
            }`}
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        <div
          className={`p-4 rounded-xl border text-xs space-y-1.5 ${
            isDark ? 'bg-slate-950 border-slate-800' : 'bg-slate-50 border-slate-200'
          }`}
        >
          <div className="flex items-center justify-between">
            <span className="font-bold">{certificate.issuingAuthority.name}</span>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-500 border border-emerald-500/30">
              VERIFIED CUSTODY
            </span>
          </div>
          <div className="text-slate-500 dark:text-slate-400">
            Issuing Organization: <strong>{certificate.issuingAuthority.organization}</strong>
          </div>
          <div className="text-slate-500 dark:text-slate-400 truncate">
            Authority Key Fingerprint:{' '}
            <span className="font-mono text-cyan-600 dark:text-cyan-300">
              {certificate.issuingAuthority.publicKeyFingerprint}
            </span>
          </div>
        </div>

        <div
          className={`p-4 rounded-xl border text-xs font-mono space-y-1.5 ${
            isDark ? 'bg-slate-950 border-slate-800' : 'bg-slate-50 border-slate-200'
          }`}
        >
          <div>
            Subject File: <strong className="text-cyan-600 dark:text-cyan-300">{certificate.evidenceSubject.filename}</strong>
          </div>
          <div className="break-all text-[11px]">
            SHA-256 Digest: <span className="text-emerald-600 dark:text-emerald-400">{certificate.evidenceSubject.sha256Fingerprint}</span>
          </div>
          <div className="flex items-center justify-between pt-1">
            <span>
              Committed to Ledger Block:{' '}
              <strong className="text-cyan-500">#{certificate.ledgerAnchorProof.blockIndex}</strong>
            </span>
            <span className="text-[11px] text-slate-500">
              {new Date(certificate.issuedAt).toLocaleTimeString()}
            </span>
          </div>
        </div>

        <div className="flex justify-end gap-2 pt-2 border-t border-slate-200 dark:border-slate-800">
          <button
            onClick={onClose}
            className={`px-3.5 py-2 rounded-xl text-xs font-semibold cursor-pointer ${
              isDark ? 'bg-slate-800 hover:bg-slate-700 text-slate-300' : 'bg-slate-100 hover:bg-slate-200 text-slate-700'
            }`}
          >
            Close
          </button>
          <button
            onClick={onDownload}
            className="px-4 py-2 rounded-xl bg-gradient-to-r from-indigo-600 to-cyan-600 hover:from-indigo-500 hover:to-cyan-500 text-white font-semibold text-xs flex items-center gap-2 cursor-pointer shadow-md shadow-indigo-950/40"
          >
            <Download className="w-4 h-4" />
            Download Proof Package (.json)
          </button>
        </div>
      </div>
    </div>
  );
};
