import React, { useEffect, useState } from 'react';
import { adminApi } from '../../api/adminApi';
import { useApp } from '../../context/AppContext';
import { ShieldAlert, RefreshCw, AlertTriangle, CheckCircle2, Archive, Cpu, Trash2, Check } from 'lucide-react';
import { SecurityBadge } from '../../components/SecurityBadge';
import { SecurityDetailsModal } from '../../components/SecurityDetailsModal';

export function ThreatCenter() {
  const { openModal, showToast } = useApp();
  const [threats, setThreats] = useState([]);
  const [loading, setLoading] = useState(true);

  const loadThreats = async () => {
    setLoading(true);
    try {
      const data = await adminApi.listThreats();
      setThreats(Array.isArray(data) ? data : (data.threats || []));
    } catch (err) {
      showToast(err.message || 'Failed to load threat registry.', 'error');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadThreats();
  }, []);

  const handleOverrideClean = async (t) => {
    if (!window.confirm(`Mark threat "${t.filename}" as verified CLEAN?`)) return;
    try {
      await adminApi.overrideFileToClean(t.file_id || t.id);
      showToast(`"${t.filename}" overridden to CLEAN.`, 'success');
      loadThreats();
    } catch (err) {
      showToast(err.message || 'Failed to override file.', 'error');
    }
  };

  const handlePurgeThreat = async (t) => {
    if (!window.confirm(`Permanently purge threat file "${t.filename}" from the device and storage?`)) return;
    try {
      await adminApi.purgeThreatFile(t.file_id || t.id);
      showToast(`"${t.filename}" permanently purged.`, 'info');
      loadThreats();
    } catch (err) {
      showToast(err.message || 'Failed to purge file.', 'error');
    }
  };

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-6">
      {/* Header Banner */}
      <div className="glass-card p-6 border border-red-500/40 bg-gradient-to-r from-slate-900 via-red-950/20 to-slate-900 shadow-2xl flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="p-3 rounded-xl bg-red-950/90 border border-red-500/50 text-red-400">
            <ShieldAlert className="w-8 h-8" />
          </div>
          <div>
            <h1 className="text-xl font-black text-white tracking-wide flex items-center gap-2">
              Threat Operations Center & Risk Mitigation
              <span className="px-2 py-0.5 bg-red-950 border border-red-500/40 text-red-300 text-[10px] rounded font-mono">
                ACTIVE MONITOR
              </span>
            </h1>
            <p className="text-xs text-slate-400 mt-1">
              Active structural heuristics and LightGBM machine learning threat classifications with real-time override and purge containment.
            </p>
          </div>
        </div>
        <button
          onClick={loadThreats}
          className="p-2 bg-slate-900 hover:bg-slate-800 text-slate-300 hover:text-white border border-slate-800 rounded-lg text-xs flex items-center gap-1.5 transition"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} /> Refresh Threats
        </button>
      </div>

      {/* Threats Table */}
      <div className="glass-card overflow-hidden border border-slate-800 shadow-2xl">
        <div className="overflow-x-auto">
          <table className="soc-table">
            <thead>
              <tr>
                <th>Threat Entity</th>
                <th>Owner Identity</th>
                <th>ML Threat Probability</th>
                <th>Classification</th>
                <th>Detected Date</th>
                <th className="text-right">Mitigation & Action</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr>
                  <td colSpan="6" className="text-center py-16 text-slate-400 font-mono text-xs">
                    <RefreshCw className="w-5 h-5 animate-spin mx-auto mb-2 text-red-400" />
                    CORRELATING ACTIVE THREAT SIGNATURES...
                  </td>
                </tr>
              ) : threats.length > 0 ? (
                threats.map((t) => (
                  <tr key={t.id}>
                    <td>
                      <div className="flex items-center gap-2.5">
                        <div className="p-2 rounded-lg bg-red-950/80 border border-red-500/40 text-red-400 shrink-0">
                          <ShieldAlert className="w-4 h-4" />
                        </div>
                        <div>
                          <div className="font-bold text-white text-xs sm:text-sm">
                            {t.filename}
                          </div>
                          <div className="text-[10px] text-red-400/80 font-mono">
                            Verdict: {t.verdict || 'SUSPICIOUS / MALICIOUS'}
                          </div>
                        </div>
                      </div>
                    </td>
                    <td className="font-mono text-xs text-slate-300">
                      {t.owner_email || `User #${t.owner_id || t.user_id || 'System'}`}
                    </td>
                    <td className="font-mono text-xs font-bold text-red-400">
                      {t.threat_score || 85}% Score
                    </td>
                    <td>
                      <SecurityBadge status={t.security_status || 'SUSPICIOUS'} score={t.threat_score} />
                    </td>
                    <td className="font-mono text-xs text-slate-400">
                      {t.created_at || t.detected_at || 'Recent'}
                    </td>
                    <td className="text-right">
                      <div className="flex items-center justify-end gap-1.5">
                        {/* Inspect ML breakdown */}
                        <button
                          onClick={() => openModal('securityDetails', { ...t, id: t.file_id || t.id })}
                          title="Inspect ML Vectors & Features"
                          className="px-2.5 py-1.5 bg-slate-800 hover:bg-slate-700 text-sky-300 hover:text-white border border-slate-700 rounded-lg text-xs font-semibold flex items-center gap-1 transition"
                        >
                          <Cpu className="w-3.5 h-3.5" /> Inspect
                        </button>

                        {/* Override to Clean */}
                        <button
                          onClick={() => handleOverrideClean(t)}
                          title="Mark as Safe / Override to CLEAN"
                          className="px-2.5 py-1.5 bg-emerald-950 hover:bg-emerald-900 text-emerald-300 border border-emerald-500/40 rounded-lg text-xs font-bold flex items-center gap-1 transition"
                        >
                          <Check className="w-3.5 h-3.5" /> Clean
                        </button>

                        {/* Purge Threat */}
                        <button
                          onClick={() => handlePurgeThreat(t)}
                          title="Permanently Purge Threat File"
                          className="p-1.5 bg-red-950 hover:bg-red-900 text-red-300 border border-red-500/40 rounded-lg transition"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan="6" className="text-center py-14 text-slate-500 text-xs">
                    <CheckCircle2 className="w-8 h-8 text-emerald-400 mx-auto mb-2 opacity-80" />
                    Zero active threats. All files are clean and verified.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      <SecurityDetailsModal onUpdate={loadThreats} />
    </div>
  );
}
