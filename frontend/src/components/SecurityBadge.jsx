import React from 'react';
import { ShieldCheck, ShieldAlert, AlertTriangle, Clock, RefreshCw } from 'lucide-react';

export function SecurityBadge({ status = 'CLEAN', score = 0, isScanning = false }) {
  if (isScanning || status === 'SCANNING' || status === 'QUEUED') {
    return (
      <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-sky-950/80 text-sky-300 border border-sky-500/40">
        <RefreshCw className="w-3 h-3 animate-spin" />
        <span>Scanning...</span>
      </span>
    );
  }

  const upper = (status || 'CLEAN').toUpperCase();
  const numScore = Number(score !== undefined && score !== null ? score : 0);

  if (upper === 'VERIFIED_CLEAN') {
    return (
      <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-emerald-950 text-emerald-300 border border-emerald-500/50 shadow">
        <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
        <span>VERIFIED CLEAN (0%)</span>
      </span>
    );
  }

  // DANGER (>= 80%)
  if (upper === 'DANGER' || (numScore >= 80 && upper !== 'CLEAN' && upper !== 'VERIFIED_CLEAN')) {
    return (
      <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-rose-950 text-rose-300 border border-rose-500/80 shadow-lg shadow-rose-950/50 animate-pulse">
        <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
        <span>DANGER ({numScore}%)</span>
      </span>
    );
  }

  // MALICIOUS (50% - 79.9%)
  if (upper === 'MALICIOUS' || (numScore >= 50 && upper !== 'CLEAN' && upper !== 'VERIFIED_CLEAN')) {
    return (
      <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold badge-malicious">
        <ShieldAlert className="w-3.5 h-3.5 text-red-400" />
        <span>MALICIOUS ({numScore ? `${numScore}%` : 'ALERT'})</span>
      </span>
    );
  }

  // SUSPICIOUS (20% - 49.9%)
  if (upper === 'SUSPICIOUS' || (numScore >= 20 && numScore < 50 && upper !== 'VERIFIED_CLEAN')) {
    return (
      <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold badge-suspicious">
        <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
        <span>SUSPICIOUS ({numScore ? `${numScore}%` : 'RISK'})</span>
      </span>
    );
  }

  if (upper === 'QUARANTINED') {
    return (
      <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-red-900/60 text-red-200 border border-red-500/50">
        <ShieldAlert className="w-3.5 h-3.5 text-red-300" />
        <span>QUARANTINED</span>
      </span>
    );
  }

  if (upper === 'NOT_SCANNED' || upper === 'PENDING') {
    return (
      <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-slate-800 text-slate-400 border border-slate-700">
        <Clock className="w-3.5 h-3.5" />
        <span>NOT SCANNED</span>
      </span>
    );
  }

  // CLEAN (< 20%)
  return (
    <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold badge-clean">
      <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
      <span>CLEAN ({numScore ? `${numScore}%` : '0%'})</span>
    </span>
  );
}
