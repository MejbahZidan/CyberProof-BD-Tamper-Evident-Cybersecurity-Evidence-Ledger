import React from 'react';
import { Sun, Moon } from 'lucide-react';

interface ThemeToggleProps {
  isDark: boolean;
  onToggle: () => void;
  className?: string;
  showLabel?: boolean;
}

export const ThemeToggle: React.FC<ThemeToggleProps> = ({
  isDark,
  onToggle,
  className = '',
  showLabel = true,
}) => {
  return (
    <div className={`flex items-center justify-between gap-3 ${className}`}>
      {showLabel && (
        <span
          className={`text-xs font-semibold tracking-wide select-none ${
            isDark ? 'text-slate-300' : 'text-slate-700'
          }`}
        >
          {isDark ? 'Dark Mode' : 'Light Mode'}
        </span>
      )}

      <button
        type="button"
        onClick={onToggle}
        aria-label={isDark ? 'Switch to Light Mode' : 'Switch to Dark Mode'}
        title={isDark ? 'Switch to Light Mode' : 'Switch to Dark Mode'}
        className={`relative inline-flex h-8 w-15 flex-shrink-0 cursor-pointer rounded-full border-2 p-0.5 transition-colors duration-300 focus:outline-none focus:ring-2 focus:ring-cyan-500/50 shadow-inner ${
          isDark
            ? 'bg-slate-900 border-slate-700/80 shadow-black/40'
            : 'bg-slate-200 border-slate-300 shadow-slate-300'
        }`}
      >
        {/* Sliding knob with icon */}
        <span
          className={`pointer-events-none inline-flex h-6.5 w-6.5 transform items-center justify-center rounded-full shadow-md transition-all duration-300 ease-spring ${
            isDark
              ? 'translate-x-7 bg-gradient-to-tr from-cyan-600 to-cyan-400 text-slate-950 shadow-cyan-950/50'
              : 'translate-x-0 bg-white text-amber-500 shadow-slate-400/50'
          }`}
        >
          {isDark ? (
            <Moon className="w-3.5 h-3.5 transition-transform duration-300 rotate-0" />
          ) : (
            <Sun className="w-3.5 h-3.5 transition-transform duration-300 rotate-0" />
          )}
        </span>

        {/* Ambient background icons inside track */}
        <span
          className={`absolute left-1.5 top-1.5 text-amber-400/70 transition-opacity duration-200 ${
            isDark ? 'opacity-30' : 'opacity-0'
          }`}
        >
          <Sun className="w-3.5 h-3.5" />
        </span>
        <span
          className={`absolute right-1.5 top-1.5 text-cyan-400/70 transition-opacity duration-200 ${
            isDark ? 'opacity-0' : 'opacity-30'
          }`}
        >
          <Moon className="w-3.5 h-3.5" />
        </span>
      </button>
    </div>
  );
};
