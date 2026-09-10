import React, { useEffect, useState } from 'react';
import { useApp } from '../context/AppContext';
import { adminApi } from '../api/adminApi';
import { 
  ShieldCheck, ShieldAlert, AlertTriangle, Cpu, Terminal, X, CheckCircle2, 
  Trash2, RotateCcw, Shield, RefreshCw
} from 'lucide-react';
import { SecurityBadge } from './SecurityBadge';

export function SecurityDetailsModal({ onUpdate }) {
  const { activeModal, modalData, closeModal, showToast } = useApp();
  const [loading, setLoading] = useState(false);
  const [details, setDetails] = useState(null);
  const [actionLoading, setActionLoading] = useState(false);

  useEffect(() => {
    if (activeModal === 'securityDetails' && modalData?.id) {
      loadDetails(modalData.id);
    } else {
      setDetails(null);
    }
  }, [activeModal, modalData]);

  const loadDetails = async (fileId) => {
    setLoading(true);
    try {
      const res = await adminApi.getSecurityDetails(fileId);
      setDetails(res);
    } catch (err) {
      console.error(err);
      showToast(err.message || 'Failed to retrieve deep security telemetry.', 'error');
    } finally {
      setLoading(false);
    }
  };

  if (activeModal !== 'securityDetails' || !modalData) return null;

  const targetFileId = modalData.id || modalData.file_id;
  const filename = modalData.filename || details?.filename || 'File';
  const currentStatus = details?.security_status || modalData.security_status || 'UNKNOWN';
  const currentScore = Number(details?.threat_score ?? modalData.threat_score ?? 0);
  const healthScore = Number(details?.health_score ?? Math.max(0, Math.min(100, Math.round((100 - currentScore) * 10) / 10))).toFixed(1);
  const isCleanStatus = (currentStatus === 'CLEAN' && currentScore < 20) || details?.model_version?.includes('Trust Registry');
  const isThreat = !isCleanStatus && (currentStatus === 'SUSPICIOUS' || currentStatus === 'MALICIOUS' || currentScore >= 20);

  const handleOverrideClean = async () => {
    if (!window.confirm(`Are you sure you want to mark "${filename}" as verified CLEAN? This will override all security warnings.`)) return;

    setActionLoading(true);
    try {
      const res = await adminApi.overrideFileToClean(targetFileId);
      showToast(res.message || `"${filename}" marked as CLEAN.`, 'success');
      loadDetails(targetFileId);
      if (onUpdate) onUpdate();
      window.dispatchEvent(new CustomEvent('files:updated'));
    } catch (err) {
      showToast(err.message || 'Failed to override security status.', 'error');
    } finally {
      setActionLoading(false);
    }
  };

  const handlePurgeThreat = async () => {
    if (!window.confirm(`DANGER: Permanently purge threat file "${filename}" from the device and storage? This cannot be undone.`)) return;

    setActionLoading(true);
    try {
      const res = await adminApi.purgeThreatFile(targetFileId);
      showToast(res.message || `"${filename}" permanently purged.`, 'info');
      closeModal();
      if (onUpdate) onUpdate();
      window.dispatchEvent(new CustomEvent('files:updated'));
    } catch (err) {
      showToast(err.message || 'Failed to purge file.', 'error');
    } finally {
      setActionLoading(false);
    }
  };

  const finalVerdict = details?.final_verdict || (
    isCleanStatus ? '✓ VERIFIED CLEAN FILE' :
    currentStatus === 'MALICIOUS' ? '✕ MALICIOUS FILE DETECTED' :
    currentStatus === 'SUSPICIOUS' ? '⚠ SUSPICIOUS FILE HEURISTICS' :
    '✓ CLEAN FILE'
  );

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/85 backdrop-blur-sm">
      <div className="glass-card max-w-2xl w-full p-6 border border-slate-700 shadow-2xl relative max-h-[90vh] flex flex-col animate-scale-up">
        <button
          onClick={closeModal}
          className="absolute top-4 right-4 text-slate-400 hover:text-white"
        >
          <X className="w-5 h-5" />
        </button>

        <div className="flex items-center gap-3 mb-4 shrink-0">
          <div className="p-2.5 rounded-xl bg-slate-800 border border-slate-700 text-sky-400">
            <Shield className="w-6 h-6" />
          </div>
          <div>
            <h3 className="text-base font-bold text-white flex items-center gap-2">
              Security Telemetry & Threat Vector Inspection
              <span className="px-2 py-0.5 bg-slate-800 text-slate-300 text-[10px] rounded font-mono border border-slate-700">
                AI / EMBER MODEL
              </span>
            </h3>
            <p className="text-xs text-slate-400">Deep structural analysis for <strong>{filename}</strong></p>
          </div>
        </div>

        <div className="flex-1 overflow-y-auto pr-1 space-y-4">
          {loading ? (
            <div className="py-12 text-center text-slate-400 text-xs font-mono">
              <RefreshCw className="w-6 h-6 animate-spin mx-auto mb-2 text-sky-400" />
              RETRIEVING SECURITY TELEMETRY...
            </div>
          ) : (
            <>
              {/* Verdict Summary Card */}
              <div className={`p-4 rounded-xl border flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 ${
                isCleanStatus
                  ? 'bg-emerald-950/40 border-emerald-500/50'
                  : currentStatus === 'MALICIOUS'
                  ? 'bg-red-950/40 border-red-500/50'
                  : currentStatus === 'SUSPICIOUS'
                  ? 'bg-amber-950/40 border-amber-500/50'
                  : 'bg-slate-900/90 border-slate-800'
              }`}>
                <div>
                  <div className="text-xs text-slate-400 uppercase font-mono">Security Verdict</div>
                  <div className={`text-lg font-black mt-0.5 ${
                    isCleanStatus ? 'text-emerald-400' :
                    currentStatus === 'MALICIOUS' ? 'text-red-400' :
                    currentStatus === 'SUSPICIOUS' ? 'text-amber-400' : 'text-emerald-400'
                  }`}>
                    {finalVerdict}
                  </div>
                </div>
                <div className="flex items-center gap-4">
                  <div className="text-right font-mono">
                    <div className="text-[10px] text-slate-400">Intrinsic Health Score</div>
                    <div className="text-base font-bold text-emerald-400">
                      {healthScore}%
                    </div>
                  </div>
                  <div className="text-right font-mono">
                    <div className="text-[10px] text-slate-400">ML Threat Probability</div>
                    <div className={`text-base font-bold ${
                      currentScore > 50 ? 'text-red-400' : currentScore > 20 ? 'text-amber-400' : 'text-emerald-400'
                    }`}>
                      {currentScore.toFixed(1)}%
                    </div>
                  </div>
                  <SecurityBadge status={isCleanStatus ? 'CLEAN' : currentStatus} score={currentScore} />
                </div>
              </div>

              {/* Threat Mitigation & User Action Buttons */}
              {isThreat && (
                <div className="p-4 rounded-xl bg-slate-900 border border-slate-700 space-y-3">
                  <div className="flex items-center gap-2 text-xs font-bold text-slate-200">
                    <ShieldAlert className="w-4 h-4 text-amber-400" />
                    Threat Containment & Authorization Controls
                  </div>
                  <p className="text-xs text-slate-400">
                    If this file is a known safe asset (false positive), you can mark it as clean. Alternatively, purge the file to immediately protect your system.
                  </p>
                  <div className="flex flex-wrap items-center gap-2 pt-1">
                    {/* Mark as Clean */}
                    <button
                      onClick={handleOverrideClean}
                      disabled={actionLoading}
                      className="px-3.5 py-2 bg-emerald-950 hover:bg-emerald-900 text-emerald-300 border border-emerald-500/40 rounded-lg text-xs font-bold flex items-center gap-1.5 transition shadow"
                    >
                      <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                      Mark as Safe / Override to CLEAN
                    </button>

                    {/* Purge Threat */}
                    <button
                      onClick={handlePurgeThreat}
                      disabled={actionLoading}
                      className="px-3.5 py-2 bg-red-950 hover:bg-red-900 text-red-300 border border-red-500/50 rounded-lg text-xs font-bold flex items-center gap-1.5 transition shadow"
                    >
                      <Trash2 className="w-4 h-4 text-red-400" />
                      Purge / Delete Threat from Device
                    </button>
                  </div>
                </div>
              )}

              {/* Static Heuristics & Risk Indicators */}
              <div className="glass-card p-4 border border-slate-800">
                <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider mb-2 flex items-center gap-1.5 font-mono">
                  <Terminal className="w-4 h-4 text-sky-400" /> Heuristic Explanations & Rule Matches
                </h4>
                {details?.model_version?.includes('Trust Registry') ? (
                  <div className="text-xs text-emerald-400 flex items-center gap-2 p-2.5 bg-emerald-950/30 rounded-lg border border-emerald-500/30 font-mono">
                    <CheckCircle2 className="w-4 h-4 shrink-0" />
                    Cryptographically verified safe asset (100% Intrinsic Health). Verified Clean in Trust Registry.
                  </div>
                ) : details?.explanations?.length ? (
                  <ul className="space-y-1.5 text-xs text-slate-300">
                    {details.explanations.map((exp, idx) => (
                      <li key={idx} className="flex items-start gap-2 bg-slate-950/60 p-2.5 rounded-lg border border-slate-800">
                        <span className="text-sky-400 font-mono">[{idx + 1}]</span>
                        <span>{exp}</span>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <div className="text-xs text-emerald-400 flex items-center gap-2 p-2.5 bg-emerald-950/30 rounded-lg border border-emerald-500/30 font-mono">
                    <CheckCircle2 className="w-4 h-4 shrink-0" />
                    Intrinsic static heuristics and LightGBM model evaluated threat risk at {currentScore.toFixed(1)}% (Intrinsic Health: {healthScore}%).
                  </div>
                )}
              </div>

              {/* ML Probability Class Distribution */}
              {(details?.ml_probabilities || details?.latest_scan?.ml_probabilities) && (() => {
                const probs = details?.ml_probabilities || details?.latest_scan?.ml_probabilities || {};
                return (
                  <div className="glass-card p-4 border border-slate-800">
                    <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider mb-3 font-mono">
                      Model Classification Confidence
                    </h4>
                    <div className="grid grid-cols-3 gap-3 text-center">
                      <div className="p-3 bg-slate-950 rounded-xl border border-slate-800">
                        <div className="text-[10px] text-slate-400 font-mono">CLEAN / HEALTHY</div>
                        <div className="text-sm font-bold text-emerald-400 mt-1 font-mono">
                          {probs.CLEAN ?? healthScore}%
                        </div>
                      </div>
                      <div className="p-3 bg-slate-950 rounded-xl border border-slate-800">
                        <div className="text-[10px] text-slate-400 font-mono">SUSPICIOUS ANOMALY</div>
                        <div className="text-sm font-bold text-amber-400 mt-1 font-mono">
                          {probs.SUSPICIOUS ?? 0}%
                        </div>
                      </div>
                      <div className="p-3 bg-slate-950 rounded-xl border border-slate-800">
                        <div className="text-[10px] text-slate-400 font-mono">MALICIOUS VECTOR</div>
                        <div className="text-sm font-bold text-red-400 mt-1 font-mono">
                          {probs.MALICIOUS ?? 0}%
                        </div>
                      </div>
                    </div>
                  </div>
                );
              })()}
            </>
          )}
        </div>

        <div className="pt-4 border-t border-slate-800 flex justify-end">
          <button
            onClick={closeModal}
            className="px-5 py-2 bg-slate-800 hover:bg-slate-700 text-white rounded-lg text-xs font-bold transition"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
}
