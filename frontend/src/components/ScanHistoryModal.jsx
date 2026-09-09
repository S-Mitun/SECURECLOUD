import React, { useEffect, useState } from 'react';
import { useApp } from '../context/AppContext';
import { adminApi } from '../api/adminApi';
import { History, X, ShieldAlert, ShieldCheck, AlertTriangle, Clock, RefreshCw, Cpu } from 'lucide-react';
import { SecurityBadge } from './SecurityBadge';

export function ScanHistoryModal() {
  const { activeModal, modalData, closeModal, showToast } = useApp();
  const [loading, setLoading] = useState(false);
  const [historyItems, setHistoryItems] = useState([]);

  const loadHistory = async (fileId) => {
    setLoading(true);
    try {
      const res = await adminApi.getScanHistory(fileId);
      const items = Array.isArray(res) ? res : (res?.history || res?.scans || []);
      setHistoryItems(items);
    } catch (err) {
      console.error("Failed to load scan history:", err);
      showToast(err.message || 'Failed to load scan history.', 'error');
      setHistoryItems([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (activeModal === 'scanHistory' && modalData) {
      const fileId = modalData.id || modalData.file_id;
      if (fileId) {
        loadHistory(fileId);
      }
    } else {
      setHistoryItems([]);
    }
  }, [activeModal, modalData]);

  if (activeModal !== 'scanHistory' || !modalData) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
      <div className="glass-card max-w-2xl w-full p-6 border border-slate-700 shadow-2xl relative max-h-[85vh] flex flex-col animate-scale-up">
        <button
          onClick={closeModal}
          className="absolute top-4 right-4 text-slate-400 hover:text-white"
        >
          <X className="w-5 h-5" />
        </button>

        <div className="flex items-center gap-3 mb-4 shrink-0">
          <div className="p-2.5 rounded-xl bg-sky-950/80 border border-sky-500/40 text-sky-400">
            <History className="w-6 h-6" />
          </div>
          <div>
            <h3 className="text-base font-bold text-white">Scan & Threat History</h3>
            <p className="text-xs text-slate-400">
              Audit log for <strong className="text-sky-300">{modalData.filename || modalData.original_filename}</strong>
            </p>
          </div>
        </div>

        <div className="flex-1 overflow-y-auto pr-1">
          {loading ? (
            <div className="py-12 text-center text-slate-400 text-xs font-mono flex flex-col items-center gap-2">
              <RefreshCw className="w-5 h-5 animate-spin text-sky-400" />
              LOADING AUDIT LOGS...
            </div>
          ) : historyItems.length > 0 ? (
            <div className="space-y-3">
              {historyItems.map((item, idx) => (
                <div
                  key={idx}
                  className="p-3.5 rounded-xl bg-slate-900/90 border border-slate-800 flex items-start justify-between gap-3 text-xs shadow"
                >
                  <div className="space-y-1.5 flex-1">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="font-bold text-white uppercase tracking-wider text-[11px]">
                        {item.final_verdict || (item.threat_score < 20 ? '✓ VERIFIED CLEAN' : 'THREAT DETECTED')}
                      </span>
                      <SecurityBadge status={item.security_status || 'CLEAN'} score={item.threat_score} />
                    </div>
                    <p className="text-slate-400 leading-relaxed text-xs">
                      {item.ml_prediction ? `ML Prediction: ${item.ml_prediction}` : 'Static heuristic and ML analysis completed.'}
                      {item.rules_count ? ` • ${item.rules_count} Heuristic Rules Evaluated` : ''}
                    </p>
                    <div className="text-[11px] text-slate-400 font-mono flex items-center gap-1">
                      <Clock className="w-3.5 h-3.5 text-slate-500" />
                      <span>{item.scanned_at || item.created_at || 'Recent'}</span>
                    </div>
                  </div>
                  <div className="text-right font-mono text-[11px] text-sky-400 shrink-0 bg-slate-950 px-2.5 py-1 rounded border border-slate-800">
                    <div className="text-slate-400 text-[10px]">Model:</div>
                    {item.model_version || 'LightGBM v2'}
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="p-8 text-center text-slate-400 text-xs bg-slate-900/50 rounded-xl border border-slate-800">
              No historical scan events recorded for this file yet.
            </div>
          )}
        </div>

        <div className="flex justify-end pt-4 border-t border-slate-800 mt-4 shrink-0">
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
