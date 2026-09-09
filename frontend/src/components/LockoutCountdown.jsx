import React, { useState, useEffect } from 'react';
import { Clock, Lock, AlertTriangle } from 'lucide-react';

export function formatTimeRemaining(seconds) {
  if (seconds <= 0) return '00:00';
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const secs = seconds % 60;

  if (hours > 0) {
    return `${hours}h ${minutes.toString().padStart(2, '0')}m ${secs.toString().padStart(2, '0')}s`;
  }
  return `${minutes.toString().padStart(2, '0')}m ${secs.toString().padStart(2, '0')}s`;
}

export function LockoutCountdown({ lockedUntil, isPermanentlyLocked, onExpire, compact = false }) {
  const [remainingSeconds, setRemainingSeconds] = useState(() => {
    if (isPermanentlyLocked) return 0;
    if (!lockedUntil) return 0;
    const target = new Date(lockedUntil.includes('Z') ? lockedUntil : lockedUntil.replace(' ', 'T') + 'Z').getTime();
    const now = Date.now();
    return Math.max(0, Math.floor((target - now) / 1000));
  });

  useEffect(() => {
    if (isPermanentlyLocked || !lockedUntil) {
      setRemainingSeconds(0);
      return;
    }

    const calculate = () => {
      // Handle UTC date strings
      const dateStr = lockedUntil.includes('T') ? lockedUntil : lockedUntil.replace(' ', 'T') + 'Z';
      const target = new Date(dateStr).getTime();
      const now = Date.now();
      const diff = Math.max(0, Math.floor((target - now) / 1000));
      setRemainingSeconds(diff);
      if (diff <= 0 && onExpire) {
        onExpire();
      }
    };

    calculate();
    const interval = setInterval(calculate, 1000);
    return () => clearInterval(interval);
  }, [lockedUntil, isPermanentlyLocked]);

  if (isPermanentlyLocked) {
    if (compact) {
      return (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-bold bg-rose-950/90 text-rose-300 border border-rose-500/50">
          <Lock className="w-3 h-3 text-rose-400" />
          <span>Permanently Locked</span>
        </span>
      );
    }
    return (
      <div className="p-3 bg-rose-950/80 border border-rose-500/50 rounded-xl flex items-center gap-2.5 text-rose-300 text-xs font-mono">
        <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
        <div>
          <strong className="font-bold text-white">Permanently Locked:</strong> Security attempts exceeded. Cannot be unlocked.
        </div>
      </div>
    );
  }

  if (remainingSeconds <= 0) {
    return null;
  }

  if (compact) {
    return (
      <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-bold font-mono bg-amber-950/90 text-amber-300 border border-amber-500/50 animate-pulse">
        <Clock className="w-3 h-3 text-amber-400" />
        <span>Locked: {formatTimeRemaining(remainingSeconds)}</span>
      </span>
    );
  }

  return (
    <div className="p-3 bg-amber-950/70 border border-amber-500/50 rounded-xl flex items-center justify-between gap-3 text-amber-300 text-xs font-mono animate-pulse">
      <div className="flex items-center gap-2">
        <Clock className="w-4 h-4 text-amber-400 shrink-0" />
        <div>
          <span className="font-bold text-white">Progressive Lockout Active:</span> Try again in
        </div>
      </div>
      <div className="px-2.5 py-1 bg-amber-900/80 rounded-lg text-amber-200 font-black tracking-wider text-xs border border-amber-500/40">
        {formatTimeRemaining(remainingSeconds)}
      </div>
    </div>
  );
}
