import React, { useState, useEffect } from 'react';
import { Clock, Lock, AlertTriangle } from 'lucide-react';

export function parseTargetTime(lockedUntil) {
  if (!lockedUntil) return 0;
  if (typeof lockedUntil === 'number') {
    return lockedUntil > 1e11 ? lockedUntil : lockedUntil * 1000;
  }
  if (typeof lockedUntil !== 'string') return 0;

  const raw = lockedUntil.trim();

  // 1. Try direct parse if standard ISO
  let parsed = Date.parse(raw);
  if (!isNaN(parsed) && parsed > 0) return parsed;

  // 2. Handle ISO without Z: "2026-09-10T21:45:00"
  if (raw.includes('T')) {
    const withZ = raw.endsWith('Z') ? raw : raw + 'Z';
    parsed = Date.parse(withZ);
    if (!isNaN(parsed) && parsed > 0) return parsed;
  }

  // 3. Handle formats like "10 Sep 2026 21:45:10" or "10 Sep 2026, 09:45:10 PM IST"
  const clean = raw.replace(/\bIST\b/ig, '').replace(/,/g, '').trim();
  parsed = Date.parse(clean);
  if (!isNaN(parsed) && parsed > 0) {
    // If it was IST time string, adjust from UTC assumption by subtracting 5.5 hours
    return parsed - (5.5 * 3600 * 1000);
  }

  // 4. Regex fallback: "DD Mon YYYY HH:MM:SS"
  const m = clean.match(/^(\d{1,2})\s+([A-Za-z]{3})\s+(\d{4})\s+(\d{1,2}):(\d{2}):(\d{2})(?:\s+(AM|PM))?$/i);
  if (m) {
    const months = { jan: 0, feb: 1, mar: 2, apr: 3, may: 4, jun: 5, jul: 6, aug: 7, sep: 8, oct: 9, nov: 10, dec: 11 };
    const month = months[m[2].toLowerCase()] ?? 0;
    let hour = parseInt(m[4], 10);
    const isPm = m[7] && m[7].toUpperCase() === 'PM';
    const isAm = m[7] && m[7].toUpperCase() === 'AM';
    if (isPm && hour < 12) hour += 12;
    if (isAm && hour === 12) hour = 0;
    const utcDate = Date.UTC(parseInt(m[3], 10), month, parseInt(m[1], 10), hour, parseInt(m[5], 10), parseInt(m[6], 10));
    return utcDate - (5.5 * 3600 * 1000);
  }

  return 0;
}

export function formatTimeRemaining(seconds) {
  const s = Math.max(0, Math.floor(Number(seconds) || 0));
  if (s <= 0) return '00:00';
  const hours = Math.floor(s / 3600);
  const minutes = Math.floor((s % 3600) / 60);
  const secs = s % 60;

  if (hours > 0) {
    return `${hours}h ${minutes.toString().padStart(2, '0')}m ${secs.toString().padStart(2, '0')}s`;
  }
  return `${minutes.toString().padStart(2, '0')}m ${secs.toString().padStart(2, '0')}s`;
}

export function LockoutCountdown({ lockedUntil, isPermanentlyLocked, onExpire, compact = false }) {
  const getRemainingSeconds = (targetStr) => {
    if (isPermanentlyLocked || !targetStr) return 0;
    const targetMs = parseTargetTime(targetStr);
    if (!targetMs || isNaN(targetMs)) return 0;
    const now = Date.now();
    return Math.max(0, Math.floor((targetMs - now) / 1000));
  };

  const [remainingSeconds, setRemainingSeconds] = useState(() => getRemainingSeconds(lockedUntil));

  useEffect(() => {
    if (isPermanentlyLocked || !lockedUntil) {
      setRemainingSeconds(0);
      return;
    }

    const calculate = () => {
      const diff = getRemainingSeconds(lockedUntil);
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
