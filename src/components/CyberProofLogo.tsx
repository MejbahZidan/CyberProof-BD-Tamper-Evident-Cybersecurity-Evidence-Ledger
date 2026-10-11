import React from 'react';

interface LogoProps {
  className?: string;
  size?: 'sm' | 'md' | 'lg' | 'xl';
  showWordmark?: boolean;
  isDark?: boolean;
}

export const CyberProofLogo: React.FC<LogoProps> = ({
  className = '',
  size = 'md',
  showWordmark = true,
  isDark = true,
}) => {
  const sizeMap = {
    sm: { icon: 'w-7 h-7', text: 'text-base', badge: 'text-[9px] px-1 py-0.2' },
    md: { icon: 'w-9 h-9', text: 'text-lg', badge: 'text-[10px] px-1.5 py-0.5' },
    lg: { icon: 'w-11 h-11', text: 'text-xl', badge: 'text-[11px] px-2 py-0.5' },
    xl: { icon: 'w-14 h-14', text: 'text-2xl', badge: 'text-xs px-2.5 py-1' },
  };

  const { icon, text, badge } = sizeMap[size];

  return (
    <div className={`flex items-center gap-3 select-none ${className}`}>
      {/* Shield Icon based on reference logo */}
      <div className={`relative ${icon} flex-shrink-0 group`}>
        <svg
          viewBox="0 0 120 120"
          fill="none"
          xmlns="http://www.w3.org/2000/svg"
          className="w-full h-full drop-shadow-sm transition-transform duration-300 group-hover:scale-105"
        >
          <defs>
            <linearGradient id="shieldGradRef" x1="10%" y1="10%" x2="95%" y2="95%">
              <stop offset="0%" stop-color="#06b6d4" />
              <stop offset="50%" stop-color="#0ea5e9" />
              <stop offset="100%" stop-color="#10b981" />
            </linearGradient>
            <linearGradient id="shieldRimRef" x1="0%" y1="0%" x2="0%" y2="100%">
              <stop offset="0%" stop-color="#ffffff" stop-opacity="0.4" />
              <stop offset="100%" stop-color="#ffffff" stop-opacity="0.05" />
            </linearGradient>
            <filter id="shieldGlowRef" x="-20%" y="-20%" width="140%" height="140%">
              <feGaussianBlur stdDeviation="6" result="blur" />
              <feComposite in="SourceGraphic" in2="blur" operator="over" />
            </filter>
          </defs>

          {/* Ambient Glow */}
          <path
            d="M60 14 C82 14 98 22 98 42 C98 76 74 97 60 106 C46 97 22 76 22 42 C22 22 38 14 60 14 Z"
            fill="url(#shieldGradRef)"
            opacity="0.4"
            filter="url(#shieldGlowRef)"
          />

          {/* Main Shield */}
          <path
            d="M60 14 C82 14 98 22 98 42 C98 76 74 97 60 106 C46 97 22 76 22 42 C22 22 38 14 60 14 Z"
            fill="url(#shieldGradRef)"
          />

          {/* Inner Highlight Rim */}
          <path
            d="M60 18 C79 18 93 25 93 42 C93 73 72 92 60 100 C48 92 27 73 27 42 C27 25 41 18 60 18 Z"
            fill="none"
            stroke="url(#shieldRimRef)"
            stroke-width="2.5"
          />

          {/* Verification Checkmark */}
          <path
            d="M44 58 L54 68 L77 45"
            stroke="#ffffff"
            stroke-width="8.5"
            stroke-linecap="round"
            stroke-linejoin="round"
          />
        </svg>
      </div>

      {/* Wordmark */}
      {showWordmark && (
        <div className="flex flex-col leading-tight">
          <div className="flex items-center gap-1.5">
            <span className={`font-extrabold tracking-tight ${text} ${isDark ? 'text-white' : 'text-slate-900'}`}>
              Cyber<span className="text-cyan-500">Proof</span>
            </span>
            <span
              className={`font-mono font-bold rounded-full uppercase tracking-wider ${badge} ${
                isDark
                  ? 'bg-emerald-950/80 text-emerald-400 border border-emerald-500/40 shadow-sm shadow-emerald-950/50'
                  : 'bg-emerald-100 text-emerald-700 border border-emerald-300'
              }`}
            >
              BD
            </span>
          </div>
          <span className={`text-[10px] font-medium tracking-wide ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>
            Forensic Evidence Ledger
          </span>
        </div>
      )}
    </div>
  );
};
