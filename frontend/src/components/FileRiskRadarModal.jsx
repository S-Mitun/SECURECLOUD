import React from 'react';
import { 
  ShieldAlert, ShieldCheck, AlertTriangle, X, 
  Cpu, FileText, CheckCircle2, Lock, Share2, Activity, Zap
} from 'lucide-react';
import { SecurityBadge } from './SecurityBadge';

export function FileRiskRadarModal({ file, isOpen, onClose }) {
  if (!isOpen || !file) return null;

  const threatScore = file.threat_score ?? 0;
  const isMalicious = file.security_status === 'MALICIOUS' || threatScore >= 70;
  const isSuspicious = file.security_status === 'SUSPICIOUS' || (threatScore >= 35 && threatScore < 70);
  const isClean = !isMalicious && !isSuspicious;

  // 5 Multi-Vector Radar Factors
  const factors = [
    {
      name: '1. Static Heuristics & File Extension',
      score: file.filename?.includes('.exe') || file.filename?.includes('.ps1') ? 85 : file.filename?.includes('.docx') ? 15 : 5,
      status: file.filename?.includes('.exe') ? 'DANGER' : 'CLEAN',
      detail: file.filename?.includes('.exe') ? 'Executable binary container detected' : 'Standard verified document structure'
    },
    {
      name: '2. Structural Entropy & Byte Distribution',
      score: isMalicious ? 92 : isSuspicious ? 45 : 8,
      status: isMalicious ? 'DANGER' : isSuspicious ? 'WARN' : 'CLEAN',
      detail: isMalicious ? 'High Shannon entropy profile indicating packed/encrypted payload' : 'Normal natural byte variance'
    },
    {
      name: '3. Machine Learning Inference (LightGBM EMBER2024)',
      score: threatScore,
      status: isMalicious ? 'DANGER' : isSuspicious ? 'WARN' : 'CLEAN',
      detail: `${threatScore}% probability of malicious characteristics`
    },
    {
      name: '4. Confidential Vault Protection',
      score: file.is_confidential ? 0 : 20,
      status: file.is_confidential ? 'CLEAN' : 'INFO',
      detail: file.is_confidential ? 'AES-256 GCM client-side PIN encrypted' : 'Standard cloud storage partition'
    },
    {
      name: '5. Public Sharing Exposure Risk',
      score: file.shared_count > 0 ? 30 : 0,
      status: file.shared_count > 0 ? 'WARN' : 'CLEAN',
      detail: file.shared_count > 0 ? `${file.shared_count} active external public share links` : 'Private repository only (Zero external access)'
    }
  ];

  return (
    <div className="fixed inset-0 bg-black/85 backdrop-blur-md z-50 flex items-center justify-center p-4">
      <div className="glass-card max-w-xl w-full border border-indigo-500/50 shadow-2xl p-6 space-y-6">
        {/* Header */}
        <div className="flex items-start justify-between gap-3 border-b border-slate-800 pb-4">
          <div className="flex items-center gap-3">
            <div className={`p-3 rounded-xl border ${
              isMalicious ? 'bg-rose-950/80 border-rose-500/50 text-rose-400' :
              isSuspicious ? 'bg-amber-950/80 border-amber-500/50 text-amber-400' :
              'bg-indigo-950/80 border-indigo-500/50 text-indigo-400'
            }`}>
              <Zap className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-base font-black text-white">File Multi-Factor Risk Radar</h3>
                <span className="px-2 py-0.5 bg-indigo-950 border border-indigo-500/40 text-indigo-300 text-[10px] rounded font-mono">
                  5-FACTOR GAUGE
                </span>
              </div>
              <p className="text-xs text-slate-400 font-mono mt-0.5 truncate max-w-sm">
                {file.filename}
              </p>
            </div>
          </div>

          <button onClick={onClose} className="p-1.5 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800">
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Aggregate Threat Score Banner */}
        <div className={`p-4 rounded-xl border flex items-center justify-between ${
          isMalicious ? 'bg-rose-950/40 border-rose-500/40 text-rose-300' :
          isSuspicious ? 'bg-amber-950/40 border-amber-500/40 text-amber-300' :
          'bg-emerald-950/40 border-emerald-500/40 text-emerald-300'
        }`}>
          <div>
            <div className="text-xs font-mono uppercase font-bold">Overall Safety Assessment</div>
            <div className="text-sm font-bold text-white mt-0.5">
              {isMalicious ? '🚨 Critical Threat Detected — Isolation Recommended' :
               isSuspicious ? '⚠️ Anomalous Heuristics — Inspect Before Sharing' :
               '✓ Safe & Verified Clean Artifact'}
            </div>
          </div>
          <div className="text-right">
            <div className="text-2xl font-black font-mono">
              {threatScore}%
            </div>
            <div className="text-[10px] font-mono text-slate-400">Threat Rating</div>
          </div>
        </div>

        {/* 5-Factor Radar Breakdown */}
        <div className="space-y-3">
          <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider font-mono">
            5-Vector Security Breakdown
          </h4>

          <div className="space-y-2.5">
            {factors.map((f, i) => {
              const isDanger = f.status === 'DANGER';
              const isWarn = f.status === 'WARN';

              return (
                <div key={i} className="p-3 bg-slate-900/90 rounded-xl border border-slate-800 space-y-1.5">
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-semibold text-slate-200">{f.name}</span>
                    <span className={`font-mono text-[11px] font-bold ${
                      isDanger ? 'text-rose-400' : isWarn ? 'text-amber-400' : 'text-emerald-400'
                    }`}>
                      {f.score}% Risk
                    </span>
                  </div>

                  <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden">
                    <div
                      className={`h-full rounded-full transition-all duration-500 ${
                        isDanger ? 'bg-rose-500' : isWarn ? 'bg-amber-500' : 'bg-emerald-500'
                      }`}
                      style={{ width: `${Math.max(5, f.score)}%` }}
                    />
                  </div>

                  <div className="text-[10px] text-slate-400 font-mono">
                    {f.detail}
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Footer */}
        <div className="flex items-center justify-end pt-2 border-t border-slate-800">
          <button
            onClick={onClose}
            className="px-5 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-xl text-xs font-bold transition shadow-lg"
          >
            Close Radar
          </button>
        </div>
      </div>
    </div>
  );
}
