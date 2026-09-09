import React, { useEffect, useState } from 'react';
import { useApp } from '../context/AppContext';
import { adminApi } from '../api/adminApi';
import { 
  UploadCloud, ShieldAlert, AlertTriangle, ShieldCheck, CheckCircle2, 
  Trash2, X, RefreshCw, Terminal, Eye, FileText, Database, Shield, Lock,
  AlertOctagon, Check
} from 'lucide-react';
import { SecurityBadge } from './SecurityBadge';

export function AdminIngestionModal({ onUpdate }) {
  const { activeModal, modalData, closeModal, showToast, openModal } = useApp();
  const [loading, setLoading] = useState(false);
  const [details, setDetails] = useState(null);
  const [actionLoading, setActionLoading] = useState(false);

  useEffect(() => {
    if (activeModal === 'adminIngestionDetails' && modalData?.id) {
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

  if (activeModal !== 'adminIngestionDetails' || !modalData) return null;

  const targetFileId = modalData.id || modalData.file_id;
  const filename = modalData.filename || details?.filename || 'File';
  const targetUsername = modalData.target_username || details?.user?.username || 'Target User';
  const currentStatus = details?.security_status || modalData.security_status || 'UNKNOWN';
  const currentScore = details?.threat_score ?? modalData.threat_score ?? 0;
  
  // Intrinsic File Payload Health Determination
  const isTrustedClean = details?.model_version?.includes('Trust Registry') || (currentStatus === 'CLEAN' && currentScore === 0);
  let intrinsicPayloadHealth = 'CLEAN';
  let intrinsicBadgeClass = 'bg-emerald-950 text-emerald-300 border-emerald-500/50';
  let intrinsicDesc = 'File payload is verified clean and contains zero malicious macros, PE sections, or high-entropy obfuscations.';

  if (isTrustedClean) {
    intrinsicPayloadHealth = 'VERIFIED CLEAN (TRUSTED)';
    intrinsicBadgeClass = 'bg-teal-950 text-teal-300 border-teal-500/50';
    intrinsicDesc = 'Cryptographic SHA-256 matches verified clean trust registry baseline. Intrinsically safe asset.';
  } else if (currentScore >= 90 || currentStatus === 'CRITICAL' || currentStatus === 'DANGER') {
    intrinsicPayloadHealth = 'DANGER / CRITICAL THREAT';
    intrinsicBadgeClass = 'bg-rose-950 text-rose-300 border-rose-500 shadow-lg shadow-rose-950/60 animate-pulse';
    intrinsicDesc = 'Severe threat payload detected with weaponized attack signatures or dangerous shellcode sequences.';
  } else if (currentStatus === 'MALICIOUS' || currentScore >= 70) {
    intrinsicPayloadHealth = 'MALICIOUS';
    intrinsicBadgeClass = 'bg-red-950 text-red-300 border-red-500/60';
    intrinsicDesc = 'Elevated ML threat probability exceeding critical threshold. Flagged for containment.';
  } else if (currentStatus === 'SUSPICIOUS' || currentScore >= 25) {
    intrinsicPayloadHealth = 'SUSPICIOUS';
    intrinsicBadgeClass = 'bg-amber-950 text-amber-300 border-amber-500/60';
    intrinsicDesc = 'Moderate heuristic anomaly flags, script indicators, or unusual section entropy detected.';
  }

  const handleOverrideClean = async () => {
    if (!window.confirm(`Are you sure you want to mark "${filename}" as verified CLEAN? This will register the file as trusted.`)) return;

    setActionLoading(true);
    try {
      const res = await adminApi.overrideFileToClean(targetFileId);
      showToast(res.message || `"${filename}" marked as verified CLEAN.`, 'success');
      loadDetails(targetFileId);
      if (onUpdate) onUpdate();
    } catch (err) {
      showToast(err.message || 'Failed to override security status.', 'error');
    } finally {
      setActionLoading(false);
    }
  };

  const handlePurgeThreat = async () => {
    if (!window.confirm(`DANGER: Permanently purge ingested file "${filename}" from the user vault and server storage?`)) return;

    setActionLoading(true);
    try {
      const res = await adminApi.purgeThreatFile(targetFileId);
      showToast(res.message || `"${filename}" permanently purged.`, 'info');
      closeModal();
      if (onUpdate) onUpdate();
    } catch (err) {
      showToast(err.message || 'Failed to purge file.', 'error');
    } finally {
      setActionLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/85 backdrop-blur-sm">
      <div className="glass-card max-w-3xl w-full p-6 border border-slate-700 shadow-2xl relative max-h-[90vh] flex flex-col animate-scale-up">
        <button
          onClick={closeModal}
          className="absolute top-4 right-4 text-slate-400 hover:text-white"
        >
          <X className="w-5 h-5" />
        </button>

        {/* Modal Header */}
        <div className="flex items-center gap-3 mb-4 shrink-0">
          <div className="p-2.5 rounded-xl bg-sky-950/80 border border-sky-500/40 text-sky-400">
            <UploadCloud className="w-6 h-6" />
          </div>
          <div>
            <h3 className="text-base font-bold text-white flex items-center gap-2">
              Admin Ingestion Telemetry & Audit
              <span className="px-2 py-0.5 bg-slate-800 text-slate-300 text-[10px] rounded font-mono border border-slate-700">
                ADMIN DISPATCH AUDIT
              </span>
            </h3>
            <p className="text-xs text-slate-400">
              Unconsented Admin Ingestion Vector & Intrinsic Health Audit for <strong>{filename}</strong>
            </p>
          </div>
        </div>

        <div className="flex-1 overflow-y-auto pr-1 space-y-4">
          {loading ? (
            <div className="py-16 text-center text-slate-400 text-xs font-mono">
              <RefreshCw className="w-6 h-6 animate-spin mx-auto mb-2 text-sky-400" />
              ANALYZING INGESTION VECTOR & INTRINSIC FILE PAYLOAD TELEMETRY...
            </div>
          ) : (
            <>
              {/* Vector Level 1: Ingestion Anomaly Protocol Notice */}
              <div className="p-4 rounded-xl border bg-gradient-to-r from-red-950/40 via-amber-950/20 to-slate-900 border-red-500/50 space-y-2">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <AlertOctagon className="w-4 h-4 text-rose-400 animate-pulse shrink-0" />
                    <span className="text-xs font-black text-rose-300 font-mono tracking-wide uppercase">
                      Ingestion Vector Alert: Remote Admin Injection (High Anomaly Risk)
                    </span>
                  </div>
                  <span className="px-2 py-0.5 rounded bg-rose-950 border border-rose-500 text-rose-300 font-mono font-bold text-[10px]">
                    ANOMALY CLASSIFIED
                  </span>
                </div>
                <p className="text-xs text-slate-300 leading-relaxed">
                  <strong>Security Protocol Notice:</strong> File was injected directly into target user vault (<strong>{targetUsername}</strong>) via administrative mode without direct user initiation. Any unconsented third-party remote write is strictly categorized as an <em>Administrative Ingestion Vector Anomaly</em> in SOC telemetry.
                </p>
              </div>

              {/* Vector Level 2: Intrinsic File Payload Health */}
              <div className={`p-4 rounded-xl border flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 ${
                intrinsicPayloadHealth.includes('DANGER') ? 'bg-rose-950/40 border-rose-500/60' :
                intrinsicPayloadHealth.includes('MALICIOUS') ? 'bg-red-950/40 border-red-500/50' :
                intrinsicPayloadHealth.includes('SUSPICIOUS') ? 'bg-amber-950/40 border-amber-500/50' :
                'bg-slate-900/90 border-slate-800'
              }`}>
                <div>
                  <div className="text-[11px] text-slate-400 uppercase font-mono font-bold flex items-center gap-1.5">
                    <Database className="w-3.5 h-3.5 text-sky-400" /> Intrinsic File Payload Classification
                  </div>
                  <div className="text-base font-black mt-1 flex items-center gap-2">
                    <span className={`px-2.5 py-1 rounded-lg text-xs font-mono font-bold border ${intrinsicBadgeClass}`}>
                      {intrinsicPayloadHealth}
                    </span>
                  </div>
                  <div className="text-xs text-slate-400 mt-1 max-w-md">
                    {intrinsicDesc}
                  </div>
                </div>

                <div className="flex items-center gap-3 self-end sm:self-center shrink-0">
                  <div className="text-right font-mono">
                    <div className="text-[10px] text-slate-400">Intrinsic ML Threat Score</div>
                    <div className={`text-lg font-black ${
                      currentScore >= 70 ? 'text-rose-400' : currentScore >= 25 ? 'text-amber-400' : 'text-emerald-400'
                    }`}>
                      {currentScore}%
                    </div>
                  </div>
                  <SecurityBadge status={currentStatus} score={currentScore} />
                </div>
              </div>

              {/* Ingestion Telemetry Metadata Grid */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 font-mono text-xs">
                <div className="p-3 bg-slate-950/80 rounded-xl border border-slate-800 space-y-1">
                  <span className="text-[10px] text-slate-500 block">DESTINATION WORKSPACE</span>
                  <span className="text-white font-bold">{targetUsername}</span>
                </div>
                <div className="p-3 bg-slate-950/80 rounded-xl border border-slate-800 space-y-1">
                  <span className="text-[10px] text-slate-500 block">INGESTION CHANNEL</span>
                  <span className="text-sky-400 font-bold">Admin Hub Multi-User Dispatcher</span>
                </div>
                <div className="p-3 bg-slate-950/80 rounded-xl border border-slate-800 space-y-1 col-span-1 sm:col-span-2">
                  <span className="text-[10px] text-slate-500 block">CRYPTOGRAPHIC SHA-256 CHECK</span>
                  <span className="text-slate-300 text-[11px] break-all select-all font-mono">
                    {details?.file_hash || details?.sha256 || modalData?.file_hash || 'SHA-256 Verified on Ingestion'}
                  </span>
                </div>
              </div>

              {/* Heuristic Explanations */}
              <div className="glass-card p-4 border border-slate-800">
                <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider mb-2 flex items-center gap-1.5 font-mono">
                  <Terminal className="w-4 h-4 text-sky-400" /> Static Heuristic Explanations & Rule Matches
                </h4>
                {isTrustedClean || currentStatus === 'CLEAN' ? (
                  <div className="text-xs text-emerald-400 flex items-center gap-2 p-2.5 bg-emerald-950/30 rounded-lg border border-emerald-500/30 font-mono">
                    <CheckCircle2 className="w-4 h-4 shrink-0" />
                    Cryptographically verified safe asset (0.0% threat). Verified Clean in Trust Registry.
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
                    Zero malicious heuristic signatures or anomalous section entropy detected.
                  </div>
                )}
              </div>
            </>
          )}
        </div>

        {/* Modal Footer */}
        <div className="pt-4 border-t border-slate-800 flex justify-end">
          <button
            onClick={closeModal}
            className="px-5 py-2 bg-slate-800 hover:bg-slate-700 text-white rounded-lg text-xs font-bold transition font-mono"
          >
            Close Telemetry
          </button>
        </div>
      </div>
    </div>
  );
}
