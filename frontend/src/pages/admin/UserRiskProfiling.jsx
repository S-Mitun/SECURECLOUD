import React, { useEffect, useState } from 'react';
import { adminApi } from '../../api/adminApi';
import { useApp } from '../../context/AppContext';
import { 
  UserCheck, ShieldAlert, AlertTriangle, CheckCircle2, 
  RefreshCw, Lock, ShieldX, Key, UserX, Activity, Eye, Shield, Check, UserMinus,
  TrendingUp, Clock, FileText, Share2, Globe, Cpu, AlertCircle, X, ChevronRight
} from 'lucide-react';

export function UserRiskProfiling() {
  const { showToast } = useApp();
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [activeTier, setActiveTier] = useState('ALL');
  const [processingId, setProcessingId] = useState(null);
  const [selectedUserDetail, setSelectedUserDetail] = useState(null);
  const [detailLoading, setDetailLoading] = useState(false);

  const loadProfiles = async () => {
    setLoading(true);
    try {
      const res = await adminApi.getUserRiskProfiling();
      setData(res);
    } catch (err) {
      showToast(err.message || 'Failed to load User Risk Profiles.', 'error');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadProfiles();
  }, []);

  const handleEnforce2FA = async (profile) => {
    setProcessingId(`2fa-${profile.user_id}`);
    try {
      const res = await adminApi.enforceUser2FA(profile.user_id);
      showToast(`2FA enforced & required for user "${profile.username}".`, 'success');
      await loadProfiles();
    } catch (err) {
      showToast(err.message || 'Failed to enforce 2FA.', 'error');
    } finally {
      setProcessingId(null);
    }
  };

  const handleLockdownUser = async (profile) => {
    if (!window.confirm(`Initiate Emergency Account Lockdown for user "${profile.username}"? All active sessions and share links will be severed immediately.`)) return;
    setProcessingId(`lock-${profile.user_id}`);
    try {
      const res = await adminApi.lockdownUserProfile(profile.user_id, 'Admin Risk Matrix Trigger');
      showToast(`Account lockdown activated for "${profile.username}". Active sessions terminated.`, 'success');
      await loadProfiles();
    } catch (err) {
      showToast(err.message || 'Lockdown failed.', 'error');
    } finally {
      setProcessingId(null);
    }
  };

  const handleRecalculateSingle = async (profile) => {
    setProcessingId(`recalc-${profile.user_id}`);
    try {
      const res = await adminApi.recalculateUserRisk(profile.user_id);
      showToast(`Recalculated risk score for "${profile.username}": ${res.risk_score}% (${res.risk_level})`, 'success');
      await loadProfiles();
      if (selectedUserDetail && selectedUserDetail.user_id === profile.user_id) {
        await handleOpenDetail(profile.user_id);
      }
    } catch (err) {
      showToast(err.message || 'Failed to recalculate user risk.', 'error');
    } finally {
      setProcessingId(null);
    }
  };

  const handleOpenDetail = async (userId) => {
    setDetailLoading(true);
    try {
      const res = await adminApi.getUserRiskDetail(userId);
      setSelectedUserDetail(res);
    } catch (err) {
      showToast(err.message || 'Failed to load user risk diagnostics.', 'error');
    } finally {
      setDetailLoading(false);
    }
  };

  const filteredProfiles = data?.profiles?.filter((p) => {
    if (activeTier === 'ALL') return true;
    return p.risk_level === activeTier || p.risk_tier === activeTier;
  }) || [];

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-6">
      {/* Header Banner */}
      <div className="glass-card p-6 border border-purple-500/40 bg-gradient-to-r from-slate-900 via-purple-950/20 to-slate-900 shadow-2xl flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="p-3 rounded-xl bg-purple-950/90 border border-purple-500/50 text-purple-400">
            <UserCheck className="w-8 h-8" />
          </div>
          <div>
            <h1 className="text-xl font-black text-white tracking-wide flex items-center gap-2">
              User Risk Profiling Matrix
              <span className="px-2 py-0.5 bg-purple-950 border border-purple-500/50 text-purple-300 text-[10px] rounded font-mono font-bold">
                BEHAVIORAL ENGINE
              </span>
            </h1>
            <p className="text-xs text-slate-400 mt-1">
              Multi-factor risk scoring evaluating authentication failures, payload threat history, baseline deviation, and IOC threat matches.
            </p>
          </div>
        </div>

        <button
          onClick={loadProfiles}
          className="p-2.5 bg-slate-900 hover:bg-slate-800 text-slate-300 hover:text-white border border-slate-800 rounded-lg text-xs flex items-center gap-2 transition font-mono font-semibold"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} /> Recalculate Risk Matrix
        </button>
      </div>

      {/* Tier Filter Tabs */}
      <div className="flex flex-wrap items-center gap-2">
        {['ALL', 'CRITICAL', 'HIGH', 'ELEVATED', 'GUARDED', 'LOW'].map((tier) => {
          const count = data?.counts?.[tier] ?? 0;
          const isActive = activeTier === tier;
          return (
            <button
              key={tier}
              onClick={() => setActiveTier(tier)}
              className={`px-3.5 py-1.5 rounded-xl text-xs font-mono font-bold flex items-center gap-2 transition ${
                isActive
                  ? 'bg-purple-600 text-white shadow-lg'
                  : 'bg-slate-900/80 hover:bg-slate-800 text-slate-400 hover:text-white border border-slate-800'
              }`}
            >
              <span>{tier}</span>
              <span className={`px-1.5 py-0.5 rounded text-[10px] ${
                isActive ? 'bg-purple-800 text-white' : 'bg-slate-800 text-slate-300'
              }`}>
                {count}
              </span>
            </button>
          );
        })}
      </div>

      {/* User Profiles Grid */}
      {loading ? (
        <div className="glass-card p-16 text-center text-slate-400 text-xs font-mono">
          <RefreshCw className="w-6 h-6 animate-spin mx-auto mb-2 text-purple-400" />
          CALCULATING USER BEHAVIORAL VECTORS & SECURITY TELEMETRY...
        </div>
      ) : filteredProfiles.length > 0 ? (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
          {filteredProfiles.map((p) => {
            const isCrit = p.risk_level === 'CRITICAL' || p.risk_score >= 90;
            const isHigh = p.risk_level === 'HIGH' || (p.risk_score >= 75 && p.risk_score < 90);
            const isElevated = p.risk_level === 'ELEVATED' || (p.risk_score >= 50 && p.risk_score < 75);
            const isGuarded = p.risk_level === 'GUARDED' || (p.risk_score >= 25 && p.risk_score < 50);

            const is2faLoading = processingId === `2fa-${p.user_id}`;
            const isLockLoading = processingId === `lock-${p.user_id}`;
            const isRecalcLoading = processingId === `recalc-${p.user_id}`;

            const subScores = p.sub_scores || {};

            return (
              <div
                key={p.user_id}
                className={`glass-card p-5 border transition flex flex-col justify-between ${
                  isCrit ? 'border-rose-500/60 bg-slate-900/95 shadow-xl' :
                  isHigh ? 'border-amber-500/50 bg-slate-900/90' :
                  isElevated ? 'border-yellow-500/40 bg-slate-900/80' :
                  isGuarded ? 'border-sky-500/40 bg-slate-900/70' :
                  'border-slate-800 bg-slate-900/60'
                }`}
              >
                <div>
                  {/* Header User Row */}
                  <div className="flex items-start justify-between gap-3 mb-4">
                    <div className="flex items-center gap-3">
                      <div className={`w-11 h-11 rounded-xl flex items-center justify-center font-black text-sm ${
                        p.role === 'ADMIN' ? 'bg-amber-950 border border-amber-500/50 text-amber-400' : 'bg-purple-950 border border-purple-500/50 text-purple-400'
                      }`}>
                        {p.username.substring(0, 2).toUpperCase()}
                      </div>
                      <div>
                        <div className="text-sm font-bold text-white flex items-center gap-2">
                          {p.username}
                          <span className="px-1.5 py-0.5 bg-slate-800 border border-slate-700 text-slate-300 text-[10px] rounded uppercase font-mono">
                            {p.role}
                          </span>
                          {!p.is_active && (
                            <span className="px-1.5 py-0.5 bg-rose-950 border border-rose-500/50 text-rose-300 text-[10px] rounded font-mono font-bold">
                              LOCKED DOWN
                            </span>
                          )}
                          {p.risk_level === 'LOW' || p.risk_score < 25 ? (
                            <span className="px-1.5 py-0.5 bg-slate-900 border border-slate-800 text-slate-400 text-[10px] rounded font-mono">
                              2FA STOPPED (LOW RISK)
                            </span>
                          ) : p.two_factor_enforced ? (
                            <span className="px-1.5 py-0.5 bg-emerald-950 border border-emerald-500/50 text-emerald-300 text-[10px] rounded font-mono font-bold flex items-center gap-1">
                              <Shield className="w-2.5 h-2.5" /> 2FA ENFORCED
                            </span>
                          ) : (
                            <span className="px-1.5 py-0.5 bg-amber-950/60 border border-amber-500/40 text-amber-300 text-[10px] rounded font-mono">
                              2FA APPLICABLE
                            </span>
                          )}
                        </div>
                        <div className="text-xs text-slate-400 font-mono">{p.email}</div>
                      </div>
                    </div>

                    {/* Risk Score Pill */}
                    <div className="text-right">
                      <span className={`px-2.5 py-1 rounded-lg text-xs font-black font-mono inline-block ${
                        isCrit ? 'bg-rose-950 text-rose-400 border border-rose-500/60 shadow-lg shadow-rose-950/40' :
                        isHigh ? 'bg-amber-950 text-amber-400 border border-amber-500/60' :
                        isElevated ? 'bg-yellow-950 text-yellow-400 border border-yellow-500/50' :
                        isGuarded ? 'bg-sky-950 text-sky-400 border border-sky-500/50' :
                        'bg-emerald-950 text-emerald-400 border border-emerald-500/50'
                      }`}>
                        {p.risk_score}% • {p.risk_level || p.status}
                      </span>
                      <div className="text-[10px] text-slate-500 font-mono mt-1">
                        Updated: {p.calculated_at || 'Just now'}
                      </div>
                    </div>
                  </div>

                  {/* Sub-Vector Scores Progress Bars */}
                  <div className="bg-slate-950/80 p-3 rounded-xl border border-slate-800/80 space-y-2 mb-4">
                    <div className="text-[10px] text-slate-400 font-mono font-bold flex items-center justify-between">
                      <span>BEHAVIORAL RISK SUB-VECTORS:</span>
                      <span className="text-slate-500">Max 100% Weighted</span>
                    </div>

                    <div className="space-y-1.5">
                      {/* Auth Score */}
                      <div>
                        <div className="flex justify-between text-[10px] font-mono text-slate-300">
                          <span>Auth & Login Anomalies</span>
                          <span className={subScores.authentication > 0 ? 'text-amber-400 font-bold' : 'text-slate-500'}>
                            +{subScores.authentication || 0} pts
                          </span>
                        </div>
                        <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden">
                          <div 
                            className="bg-amber-500 h-full rounded-full transition-all"
                            style={{ width: `${Math.min(100, ((subScores.authentication || 0) / 40) * 100)}%` }}
                          />
                        </div>
                      </div>

                      {/* File Score */}
                      <div>
                        <div className="flex justify-between text-[10px] font-mono text-slate-300">
                          <span>File Payload Threats & Spikes</span>
                          <span className={subScores.file_activity > 0 ? 'text-rose-400 font-bold' : 'text-slate-500'}>
                            +{subScores.file_activity || 0} pts
                          </span>
                        </div>
                        <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden">
                          <div 
                            className="bg-rose-500 h-full rounded-full transition-all"
                            style={{ width: `${Math.min(100, ((subScores.file_activity || 0) / 50) * 100)}%` }}
                          />
                        </div>
                      </div>

                      {/* Sharing Score */}
                      <div>
                        <div className="flex justify-between text-[10px] font-mono text-slate-300">
                          <span>Public Link Sharing Volume</span>
                          <span className={subScores.sharing > 0 ? 'text-sky-400 font-bold' : 'text-slate-500'}>
                            +{subScores.sharing || 0} pts
                          </span>
                        </div>
                        <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden">
                          <div 
                            className="bg-sky-500 h-full rounded-full transition-all"
                            style={{ width: `${Math.min(100, ((subScores.sharing || 0) / 20) * 100)}%` }}
                          />
                        </div>
                      </div>

                      {/* Threat Intel Score */}
                      <div>
                        <div className="flex justify-between text-[10px] font-mono text-slate-300">
                          <span>Threat Intelligence Matches</span>
                          <span className={subScores.threat_intelligence > 0 ? 'text-purple-400 font-bold' : 'text-slate-500'}>
                            +{subScores.threat_intelligence || 0} pts
                          </span>
                        </div>
                        <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden">
                          <div 
                            className="bg-purple-500 h-full rounded-full transition-all"
                            style={{ width: `${Math.min(100, ((subScores.threat_intelligence || 0) / 40) * 100)}%` }}
                          />
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Top Triggered Factors */}
                  {p.top_factors && p.top_factors.length > 0 && (
                    <div className="space-y-1.5 mb-4">
                      <div className="text-[10px] text-slate-500 uppercase font-mono font-bold">Triggered Risk Signals:</div>
                      <div className="space-y-1">
                        {p.top_factors.map((f, i) => (
                          <div key={i} className="p-2 bg-slate-950/90 border border-slate-800/90 rounded-lg text-xs flex items-start justify-between gap-2">
                            <div>
                              <div className="font-mono font-bold text-[11px] text-slate-200 flex items-center gap-1.5">
                                <AlertTriangle className="w-3 h-3 text-amber-400 flex-shrink-0" />
                                {f.signal_type}
                                <span className="text-[10px] text-slate-500 font-normal">({f.category})</span>
                              </div>
                              <div className="text-[10px] text-slate-400 mt-0.5">{f.reason}</div>
                            </div>
                            <span className="px-1.5 py-0.5 bg-rose-950 border border-rose-500/40 text-rose-400 text-[10px] font-mono font-bold rounded flex-shrink-0">
                              +{f.contribution}
                            </span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Automated SOC Recommendations */}
                  {p.recommendations && p.recommendations.length > 0 && (
                    <div className="mb-4 p-2.5 bg-slate-950/60 border border-slate-800/60 rounded-xl space-y-1">
                      <div className="text-[10px] text-indigo-300 font-mono font-bold flex items-center gap-1">
                        <Activity className="w-3 h-3 text-indigo-400" />
                        RECOMMENDED MITIGATION ACTIONS:
                      </div>
                      <ul className="text-[11px] text-slate-400 space-y-0.5 list-disc list-inside">
                        {p.recommendations.map((rec, ri) => (
                          <li key={ri}>{rec}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>

                {/* Quick Administrative Defense Actions */}
                <div className="pt-3 border-t border-slate-800 flex flex-wrap items-center justify-between gap-2 mt-2">
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => handleOpenDetail(p.user_id)}
                      className="px-2.5 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded-lg text-xs font-mono flex items-center gap-1 transition"
                    >
                      <Eye className="w-3.5 h-3.5 text-sky-400" />
                      <span>Diagnostics</span>
                    </button>
                    <button
                      onClick={() => handleRecalculateSingle(p)}
                      disabled={isRecalcLoading}
                      className="p-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white border border-slate-700 rounded-lg text-xs transition"
                      title="Recalculate Single Profile"
                    >
                      <RefreshCw className={`w-3.5 h-3.5 ${isRecalcLoading ? 'animate-spin text-purple-400' : ''}`} />
                    </button>
                  </div>

                  <div className="flex items-center gap-2">
                    {p.risk_level === 'LOW' || p.risk_score < 25 ? (
                      <button
                        type="button"
                        disabled
                        title="2FA enforcement is stopped because user is at clean LOW risk baseline. Only applicable if risk score raises above LOW."
                        className="px-3 py-1.5 rounded-lg text-xs font-mono font-bold transition flex items-center gap-1.5 bg-slate-900 text-slate-500 border border-slate-800 cursor-not-allowed opacity-80"
                      >
                        <Shield className="w-3.5 h-3.5 text-slate-600" />
                        <span>2FA Inactive (Low Risk)</span>
                      </button>
                    ) : (
                      <button
                        onClick={() => handleEnforce2FA(p)}
                        disabled={is2faLoading || isLockLoading || p.two_factor_enforced}
                        className={`px-3 py-1.5 rounded-lg text-xs font-mono font-bold transition flex items-center gap-1.5 shadow ${
                          p.two_factor_enforced 
                            ? 'bg-emerald-950/60 text-emerald-300 border border-emerald-500/30 cursor-not-allowed'
                            : 'bg-indigo-950 hover:bg-indigo-900 text-indigo-200 hover:text-white border border-indigo-500/40'
                        }`}
                      >
                        {is2faLoading ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Shield className="w-3.5 h-3.5 text-indigo-400" />}
                        <span>{p.two_factor_enforced ? '2FA Enforced' : 'Enforce 2FA'}</span>
                      </button>
                    )}
                    <button
                      onClick={() => handleLockdownUser(p)}
                      disabled={isLockLoading || is2faLoading || !p.is_active}
                      className={`px-3 py-1.5 rounded-lg text-xs font-mono font-bold transition flex items-center gap-1.5 shadow ${
                        !p.is_active
                          ? 'bg-slate-800 text-slate-500 border border-slate-700 cursor-not-allowed'
                          : 'bg-rose-950 hover:bg-rose-900 text-rose-200 hover:text-white border border-rose-500/50'
                      }`}
                    >
                      {isLockLoading ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <UserMinus className="w-3.5 h-3.5 text-rose-400" />}
                      <span>{!p.is_active ? 'Locked Down' : 'Lockdown'}</span>
                    </button>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      ) : (
        <div className="glass-card p-16 text-center text-slate-400 text-xs font-mono">
          NO USERS FOUND MATCHING THE SELECTED RISK TIER.
        </div>
      )}

      {/* Diagnostics & Behavioral Timeline Modal */}
      {selectedUserDetail && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm">
          <div className="glass-card w-full max-w-3xl max-h-[85vh] overflow-y-auto border border-purple-500/50 bg-slate-900 shadow-2xl p-6 space-y-6">
            <div className="flex items-center justify-between border-b border-slate-800 pb-4">
              <div className="flex items-center gap-3">
                <div className="p-2.5 rounded-xl bg-purple-950 border border-purple-500/50 text-purple-400">
                  <Activity className="w-6 h-6" />
                </div>
                <div>
                  <h2 className="text-lg font-bold text-white flex items-center gap-2">
                    Behavioral Diagnostics: {selectedUserDetail.username}
                    <span className="px-2 py-0.5 bg-slate-800 text-slate-300 text-xs rounded font-mono">
                      ID #{selectedUserDetail.user_id}
                    </span>
                  </h2>
                  <div className="text-xs text-slate-400 font-mono">{selectedUserDetail.email}</div>
                </div>
              </div>
              <button
                onClick={() => setSelectedUserDetail(null)}
                className="p-1.5 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Baseline Metrics Grid */}
            <div className="space-y-2">
              <h3 className="text-xs font-mono font-bold text-slate-300 flex items-center gap-1.5">
                <Cpu className="w-4 h-4 text-purple-400" />
                30-DAY BEHAVIORAL BASELINE ANALYSIS
              </h3>
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                <div className="p-3 bg-slate-950 border border-slate-800 rounded-xl">
                  <div className="text-[10px] text-slate-400 font-mono">DOWNLOAD MEAN (30d)</div>
                  <div className="text-base font-bold font-mono text-white mt-1">
                    {selectedUserDetail.baseline?.downloads_mean_per_day ?? 0} files/day
                  </div>
                </div>
                <div className="p-3 bg-slate-950 border border-slate-800 rounded-xl">
                  <div className="text-[10px] text-slate-400 font-mono">UPLOAD MEAN (30d)</div>
                  <div className="text-base font-bold font-mono text-white mt-1">
                    {selectedUserDetail.baseline?.uploads_mean_per_day ?? 0} files/day
                  </div>
                </div>
                <div className="p-3 bg-slate-950 border border-slate-800 rounded-xl">
                  <div className="text-[10px] text-slate-400 font-mono">SHARE LINK MEAN (30d)</div>
                  <div className="text-base font-bold font-mono text-white mt-1">
                    {selectedUserDetail.baseline?.shares_mean_per_day ?? 0} links/day
                  </div>
                </div>
              </div>
            </div>

            {/* Recent Telemetry Timeline */}
            <div className="space-y-2">
              <h3 className="text-xs font-mono font-bold text-slate-300 flex items-center gap-1.5">
                <Clock className="w-4 h-4 text-sky-400" />
                RECORDED TELEMETRY EVENT TIMELINE (LAST 20 EVENTS)
              </h3>
              {selectedUserDetail.timeline && selectedUserDetail.timeline.length > 0 ? (
                <div className="space-y-1.5 max-h-60 overflow-y-auto">
                  {selectedUserDetail.timeline.map((ev, i) => (
                    <div key={i} className="p-2.5 bg-slate-950 border border-slate-800/80 rounded-lg flex items-center justify-between text-xs">
                      <div className="flex items-center gap-2.5">
                        <span className={`w-2 h-2 rounded-full ${
                          ev.severity === 'CRITICAL' ? 'bg-rose-500' :
                          ev.severity === 'HIGH' ? 'bg-amber-500' :
                          ev.severity === 'WARNING' ? 'bg-yellow-500' :
                          'bg-emerald-500'
                        }`} />
                        <div>
                          <div className="font-mono font-bold text-white text-xs">{ev.event_type}</div>
                          <div className="text-[10px] text-slate-400">{ev.details}</div>
                        </div>
                      </div>
                      <div className="text-right font-mono text-[10px] text-slate-400">
                        <div>{ev.timestamp}</div>
                        <div className="text-slate-500">{ev.ip_address || 'Internal'}</div>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="p-6 text-center text-xs text-slate-500 font-mono bg-slate-950 rounded-xl border border-slate-800">
                  NO TELEMETRY EVENTS RECORDED FOR THIS USER YET.
                </div>
              )}
            </div>

            <div className="pt-4 border-t border-slate-800 flex justify-end">
              <button
                onClick={() => setSelectedUserDetail(null)}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-white rounded-lg text-xs font-mono font-bold"
              >
                Close Diagnostics
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
