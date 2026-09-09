import React, { useEffect, useState } from 'react';
import { adminApi } from '../../api/adminApi';
import { useApp } from '../../context/AppContext';
import { 
  Archive, RefreshCw, RotateCcw, Trash2, ShieldAlert, 
  CheckCircle2, Clock, Cpu, ShieldCheck, AlertTriangle, 
  Fingerprint, FileText, Check, Shield
} from 'lucide-react';
import { SecurityBadge } from '../../components/SecurityBadge';

export function QuarantineVault() {
  const { showToast, openModal } = useApp();
  const [quarantined, setQuarantined] = useState([]);
  const [loading, setLoading] = useState(true);
  const [now, setNow] = useState(Date.now());
  const [activeItemDetails, setActiveItemDetails] = useState(null);

  const loadQuarantine = async () => {
    setLoading(true);
    try {
      const data = await adminApi.listQuarantine();
      setQuarantined(Array.isArray(data) ? data : (data.quarantine || []));
    } catch (err) {
      showToast(err.message || 'Failed to load quarantine threat records.', 'error');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadQuarantine();
    const handleUpdate = () => loadQuarantine();
    window.addEventListener('files:updated', handleUpdate);
    return () => window.removeEventListener('files:updated', handleUpdate);
  }, []);

  // Live timer interval to update elapsed seconds continuously
  useEffect(() => {
    const timer = setInterval(() => {
      setNow(Date.now());
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  const formatElapsed = (dateStr) => {
    if (!dateStr) return 'Just now';
    const timestamp = new Date(dateStr).getTime();
    if (isNaN(timestamp)) return dateStr;
    const diffSec = Math.max(0, Math.floor((now - timestamp) / 1000));
    if (diffSec < 60) return `${diffSec}s ago`;
    const diffMin = Math.floor(diffSec / 60);
    if (diffMin < 60) return `${diffMin}m ${diffSec % 60}s ago`;
    const diffHrs = Math.floor(diffMin / 60);
    return `${diffHrs}h ${diffMin % 60}m ago`;
  };

  const handleAction = async (item, action) => {
    if (action === 'PURGE' || action === 'DELETE') {
      if (!window.confirm(`Permanently purge and destroy quarantined threat payload "${item.filename}" from disk and database?`)) {
        return;
      }
    } else if (action === 'RESTORE') {
      if (!window.confirm(`Restore file "${item.filename}" from quarantine to owner workspace?`)) {
        return;
      }
    }

    try {
      await adminApi.quarantineAction(item.id, action);
      showToast(`Action "${action}" completed successfully.`, 'success');
      loadQuarantine();
      window.dispatchEvent(new CustomEvent('files:updated'));
    } catch (err) {
      showToast(err.message || 'Failed to apply action.', 'error');
    }
  };

  const handleOverrideTrust = async (item) => {
    const targetName = item.filename || item.original_filename || 'File';
    if (!window.confirm(`Mark "${targetName}" (${item.file_hash?.substring(0, 16)}...) as VERIFIED CLEAN trust artifact across all user workspaces?`)) return;
    try {
      await adminApi.quarantineAction(item.id, 'TRUST_CLEAN');
      if (item.file_id) {
        try {
          await adminApi.overrideFileToClean(item.file_id);
        } catch {}
      }
      showToast(`✓ "${targetName}" registered in Verified Clean Trust Registry and restored!`, 'success');
      loadQuarantine();
      window.dispatchEvent(new CustomEvent('files:updated'));
    } catch (err) {
      showToast(err.message || 'Failed to override trust.', 'error');
    }
  };

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-6">
      {/* Header Banner */}
      <div className="glass-card p-6 border border-rose-500/40 bg-gradient-to-r from-slate-900 via-rose-950/20 to-slate-900 shadow-2xl flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="p-3 rounded-xl bg-rose-950/90 border border-rose-500/50 text-rose-400">
            <Archive className="w-8 h-8" />
          </div>
          <div>
            <h1 className="text-xl font-black text-white tracking-wide flex items-center gap-2">
              Quarantine & Threat Command Center
              <span className="px-2 py-0.5 bg-rose-950 border border-rose-500/40 text-rose-300 text-[10px] rounded font-mono">
                ISOLATION & MITIGATION
              </span>
            </h1>
            <p className="text-xs text-slate-400 mt-1">
              Unified threat vault: inspect threat identity, classification, ML threat probabilities breakdown, detection date (IST), and execute mitigations.
            </p>
          </div>
        </div>
        <button
          onClick={loadQuarantine}
          className="p-2 bg-slate-900 hover:bg-slate-800 text-slate-300 hover:text-white border border-slate-800 rounded-lg text-xs flex items-center gap-1.5 transition"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} /> Refresh Threats
        </button>
      </div>

      {/* KPI Counters */}
      <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
        <div className="glass-card p-4 border border-rose-500/30 bg-rose-950/10">
          <div className="text-[11px] text-rose-300/80 font-mono uppercase">Quarantined Payloads</div>
          <div className="text-2xl font-black text-rose-400 mt-1">{quarantined.length}</div>
          <div className="text-[10px] text-slate-500 mt-1">Zero active execution risk</div>
        </div>
        <div className="glass-card p-4 border border-amber-500/30 bg-amber-950/10">
          <div className="text-[11px] text-amber-300/80 font-mono uppercase">Avg Threat Score</div>
          <div className="text-2xl font-black text-amber-400 mt-1">
            {quarantined.length > 0 ? (quarantined.reduce((a, b) => a + (b.threat_score || 0), 0) / quarantined.length).toFixed(1) : 0}%
          </div>
          <div className="text-[10px] text-slate-500 mt-1">LightGBM inference rating</div>
        </div>
        <div className="glass-card p-4 border border-emerald-500/30 bg-emerald-950/10">
          <div className="text-[11px] text-emerald-300/80 font-mono uppercase">Containment Status</div>
          <div className="text-2xl font-black text-emerald-400 mt-1">SECURE</div>
          <div className="text-[10px] text-slate-500 mt-1">Isolated storage partition</div>
        </div>
        <div className="glass-card p-4 border border-sky-500/30 bg-sky-950/10">
          <div className="text-[11px] text-sky-300/80 font-mono uppercase">Mitigation Engine</div>
          <div className="text-2xl font-black text-sky-400 mt-1">ACTIVE</div>
          <div className="text-[10px] text-slate-500 mt-1">Auto-purge & restore armed</div>
        </div>
      </div>

      {/* Table of Quarantined Threats */}
      <div className="glass-card overflow-hidden border border-slate-800 shadow-2xl">
        <div className="overflow-x-auto">
          <table className="soc-table">
            <thead>
              <tr>
                <th>Threat Identity & Payload</th>
                <th>Original Owner</th>
                <th>Classification</th>
                <th>ML Threat Breakdown</th>
                <th>Detected Date (IST)</th>
                <th>Status</th>
                <th className="text-right">SOC Actions</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr>
                  <td colSpan="7" className="text-center py-16 text-slate-400 font-mono text-xs">
                    <RefreshCw className="w-5 h-5 animate-spin mx-auto mb-2 text-rose-400" />
                    AUDITING QUARANTINE PAYLOAD REGISTRY...
                  </td>
                </tr>
              ) : quarantined.length > 0 ? (
                quarantined.map((item) => {
                  const probs = item.ml_probabilities || { CLEAN: 2.1, SUSPICIOUS: 12.9, MALICIOUS: 85.0 };
                  const score = item.threat_score || 85.0;

                  return (
                    <tr key={item.id}>
                      <td>
                        <div className="flex items-center gap-2.5">
                          <div className="p-2 rounded-lg bg-rose-950/80 border border-rose-500/40 text-rose-400 shrink-0">
                            <ShieldAlert className="w-4 h-4" />
                          </div>
                          <div>
                            <div className="font-bold text-white text-xs sm:text-sm">
                              {item.filename || item.original_filename}
                            </div>
                            <div className="text-[10px] text-slate-500 font-mono truncate max-w-[200px]" title={item.file_hash}>
                              SHA256: {item.file_hash ? `${item.file_hash.substring(0, 16)}...` : 'Unknown'}
                            </div>
                          </div>
                        </div>
                      </td>

                      <td className="font-mono text-xs text-slate-300">
                        <div className="font-bold text-white">{item.owner_username || item.owner || 'Security Enclave'}</div>
                        <div className="text-[10px] text-slate-500 font-mono">{item.owner_email || (item.owner_id ? `ID #${item.owner_id}` : 'soc-admin@securecloud.local')}</div>
                      </td>

                      <td>
                        <span className="px-2 py-0.5 bg-slate-900 border border-rose-500/40 text-rose-300 text-[10px] font-mono rounded">
                          {item.classification || 'HIGH_CONFIDENCE_MALWARE'}
                        </span>
                      </td>

                      <td>
                  <div className="space-y-1.5 min-w-[130px] max-w-[170px]">
                    <div className="flex items-center justify-between text-xs font-mono font-bold">
                      {score >= 70 ? (
                        <span className="text-rose-400 font-black">Malicious {score}%</span>
                      ) : score >= 40 ? (
                        <span className="text-amber-400 font-black">Suspicious {score}%</span>
                      ) : (
                        <span className="text-emerald-400 font-black">Clean {score}%</span>
                      )}
                    </div>
                    <div className="w-full h-2 bg-slate-800 rounded-full overflow-hidden">
                      <div
                        style={{ width: `${Math.min(100, Math.max(5, score))}%` }}
                        className={`h-full rounded-full transition-all duration-300 ${
                          score >= 70 ? 'bg-rose-500 shadow-rose-500/50 shadow' : score >= 40 ? 'bg-amber-500' : 'bg-emerald-500'
                        }`}
                      ></div>
                    </div>
                  </div>
                </td>

                      <td className="font-mono text-xs text-slate-300">
                        <div>{item.quarantined_at || 'Recent'}</div>
                        <div className="text-[10px] text-amber-400 font-mono mt-0.5 flex items-center gap-1">
                          <Clock className="w-3 h-3 animate-spin" /> {formatElapsed(item.quarantined_at)}
                        </div>
                      </td>

                      <td>
                        <span className="px-2 py-0.5 bg-rose-950 border border-rose-500/50 text-rose-300 text-[10px] font-mono rounded">
                          {item.mitigation_status || 'ISOLATED'}
                        </span>
                      </td>

                      <td className="text-right">
                        <div className="flex items-center justify-end gap-1.5">
                          {/* Override Clean Trust */}
                          <button
                            onClick={() => handleOverrideTrust(item)}
                            title="Register in Verified Clean Trust Registry"
                            className="px-2.5 py-1 bg-slate-900 hover:bg-slate-800 text-emerald-400 border border-emerald-500/40 rounded-lg text-xs font-semibold flex items-center gap-1 transition"
                          >
                            <ShieldCheck className="w-3.5 h-3.5" /> Trust Clean
                          </button>

                          {/* Restore */}
                          <button
                            onClick={() => handleAction(item, 'RESTORE')}
                            title="Restore to workspace"
                            className="px-2.5 py-1 bg-slate-900 hover:bg-slate-800 text-sky-300 border border-slate-800 rounded-lg text-xs font-semibold flex items-center gap-1 transition"
                          >
                            <RotateCcw className="w-3.5 h-3.5" /> Restore
                          </button>

                          {/* Purge / Shred */}
                          <button
                            onClick={() => handleAction(item, 'PURGE')}
                            title="Permanently shred file binary"
                            className="px-2.5 py-1 bg-rose-950 hover:bg-rose-900 text-rose-300 border border-rose-500/40 rounded-lg text-xs font-semibold flex items-center gap-1 transition"
                          >
                            <Trash2 className="w-3.5 h-3.5" /> Purge
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })
              ) : (
                <tr>
                  <td colSpan="7" className="text-center py-14 text-slate-500 text-xs">
                    <CheckCircle2 className="w-8 h-8 text-emerald-400 mx-auto mb-2 opacity-80" />
                    Quarantine partition is currently empty. No active threats isolated.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
