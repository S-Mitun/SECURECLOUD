import React, { useEffect, useState } from 'react';
import { adminApi } from '../../api/adminApi';
import { useApp } from '../../context/AppContext';
import { 
  Network, ShieldAlert, AlertTriangle, CheckCircle2, 
  RefreshCw, Activity, Terminal, Shield, ArrowRight, UserX, 
  FileWarning, Globe, Hash, Zap, Check, X, ExternalLink, ShieldCheck, Lock, Plus, Trash2, Database,
  Sliders, Filter, Cpu, Layers, CheckSquare, Square
} from 'lucide-react';

const THREAT_CORRELATION_OPTIONS = [
  {
    id: 'OPTION_1',
    num: 1,
    title: 'Option 1: Multi-Vector IP & Ingress Authentication Correlation',
    shortTitle: 'Option 1: IP & Ingress Auth',
    badge: 'OPTION 1',
    category: 'Ingress & Auth Security',
    description: 'Correlates anomalous IP subnets, brute-force login attempts, consecutive 2FA failures, and unauthorized geolocation deviation against active IOC feeds.',
    countermeasure: 'Blacklist attacker IP in IP Guard & isolate network ingress',
    color: 'rose',
    accentBorder: 'border-rose-500/40',
    activeBg: 'bg-rose-950/40',
    activeRing: 'ring-rose-500/50'
  },
  {
    id: 'OPTION_2',
    num: 2,
    title: 'Option 2: Cryptographic Payload & SHA-256 Hash Matching',
    shortTitle: 'Option 2: Payload Hash Matching',
    badge: 'OPTION 2',
    category: 'Payload Cryptography',
    description: 'Correlates uploaded file SHA-256/MD5 hashes against local IOC repositories, known ransomware families, and EICAR definitions.',
    countermeasure: 'Isolate & quarantine matched malicious payload files into Quarantine Vault',
    color: 'amber',
    accentBorder: 'border-amber-500/40',
    activeBg: 'bg-amber-950/40',
    activeRing: 'ring-amber-500/50'
  },
  {
    id: 'OPTION_3',
    num: 3,
    title: 'Option 3: Behavioral Heuristics & Anomaly Scoring',
    shortTitle: 'Option 3: Behavioral Heuristics',
    badge: 'OPTION 3',
    category: 'ML & Behavioral Telemetry',
    description: 'Correlates machine-learning threat probability anomalies (>20%), rapid file mutation spikes, entropy drift, and abnormal egress bursts.',
    countermeasure: 'Enforce mandatory Two-Factor Authentication (2FA) & security challenge on account',
    color: 'purple',
    accentBorder: 'border-purple-500/40',
    activeBg: 'bg-purple-950/40',
    activeRing: 'ring-purple-500/50'
  },
  {
    id: 'OPTION_4',
    num: 4,
    title: 'Option 4: Cross-Account Lateral Threat Propagation',
    shortTitle: 'Option 4: Lateral Threat & Sessions',
    badge: 'OPTION 4',
    category: 'Lateral Movement & Sessions',
    description: 'Correlates multi-tenant file sharing tokens, unauthorized lateral user pivots, public link exposure, and concurrent session compromise.',
    countermeasure: 'Sever active user sessions & revoke external distribution share tokens',
    color: 'sky',
    accentBorder: 'border-sky-500/40',
    activeBg: 'bg-sky-950/40',
    activeRing: 'ring-sky-500/50'
  }
];

export function ThreatCorrelation() {
  const { showToast, triggerCriticalAlert } = useApp();
  const [data, setData] = useState(null);
  const [indicators, setIndicators] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedCluster, setSelectedCluster] = useState(null);
  const [executingAction, setExecutingAction] = useState(null);
  const [mitigationReport, setMitigationReport] = useState(null);
  const [showAddIocModal, setShowAddIocModal] = useState(false);
  
  // 4 Selectable Correlation Options & Combinations state
  const [selectedOptions, setSelectedOptions] = useState(['OPTION_1', 'OPTION_2', 'OPTION_3', 'OPTION_4']);
  const [filterByOptions, setFilterByOptions] = useState(false);

  const [newIoc, setNewIoc] = useState({
    indicator: '',
    indicator_type: 'IP_ADDRESS',
    threat_type: 'MALICIOUS_INFRASTRUCTURE',
    malware_family: '',
    severity: 'HIGH',
    confidence: 90.0
  });

  const toggleOption = (optId) => {
    setSelectedOptions(prev => 
      prev.includes(optId) 
        ? prev.filter(id => id !== optId) 
        : [...prev, optId]
    );
  };

  const selectAll = () => {
    setSelectedOptions(['OPTION_1', 'OPTION_2', 'OPTION_3', 'OPTION_4']);
  };

  const clearAll = () => {
    setSelectedOptions([]);
  };

  const selectSingle = (optId) => {
    setSelectedOptions([optId]);
  };

  const selectCombo = (optIds) => {
    setSelectedOptions(optIds);
  };

  const loadCorrelation = async () => {
    setLoading(true);
    try {
      const [res, indRes] = await Promise.all([
        adminApi.getThreatOverview(),
        adminApi.getThreatIndicators()
      ]);
      setData(res);
      setIndicators(Array.isArray(indRes) ? indRes : []);
      setSelectedCluster(prev => {
        if (!res.clusters || res.clusters.length === 0) return null;
        if (prev) {
          const matching = res.clusters.find(c => c.cluster_id === prev.cluster_id);
          if (matching) return matching;
        }
        return res.clusters[0];
      });
    } catch (err) {
      showToast(err.message || 'Failed to load Threat Correlation data.', 'error');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadCorrelation();
  }, []);

  const handleExecuteAction = async (actionText) => {
    if (!selectedCluster) return;
    if (selectedOptions.length === 0) {
      showToast('Please select at least one correlation option before executing mitigation.', 'warning');
      return;
    }

    const currentScore = Number(selectedCluster.threat_score || 0);
    if (currentScore <= 0 || selectedCluster.status === 'RESOLVED') {
      showToast(`Cluster ${selectedCluster.cluster_id} is already at 0% threat score. Mitigation is complete.`, 'info');
      return;
    }

    setExecutingAction(actionText);
    try {
      const res = await adminApi.mitigateThreatCluster(selectedCluster.cluster_id, actionText, selectedOptions);
      
      const newScore = res.threat_score !== undefined ? Number(res.threat_score) : 0;
      const isNowResolved = newScore === 0 || res.cluster_status === 'RESOLVED';
      const updatedMitigated = res.mitigated_options || Array.from(new Set([...(selectedCluster.mitigated_options || []), ...selectedOptions]));
      
      setSelectedCluster(prev => ({
        ...prev,
        status: isNowResolved ? 'RESOLVED' : (res.cluster_status || 'IN_PROGRESS'),
        threat_score: newScore,
        mitigated_options: updatedMitigated
      }));
      
      setMitigationReport({
        cluster: selectedCluster,
        action: actionText,
        previous_score: res.previous_score ?? currentScore,
        threat_score: newScore,
        reduction: res.reduction ?? (currentScore - newScore),
        selected_options: res.selected_options || selectedOptions,
        actions_taken: res.actions_taken || [actionText],
        message: res.message
      });
      
      if (newScore === 0) {
        showToast(`Threat Score reduced to 0.0% — Incident fully resolved! Mitigation execution complete.`, 'success');
      } else {
        showToast(`Applied ${selectedOptions.join(' + ')}: Threat score reduced from ${res.previous_score ?? currentScore}% to ${newScore}%. Continue mitigation until 0%.`, 'info');
      }
      loadCorrelation();
    } catch (err) {
      showToast(err.message || 'Mitigation execution failed.', 'error');
    } finally {
      setExecutingAction(null);
    }
  };

  const handleAddIocSubmit = async (e) => {
    e.preventDefault();
    if (!newIoc.indicator.trim()) return;
    try {
      await adminApi.addThreatIndicator(newIoc);
      showToast(`Threat indicator '${newIoc.indicator}' added to IOC database.`, 'success');
      setShowAddIocModal(false);
      setNewIoc({
        indicator: '',
        indicator_type: 'IP_ADDRESS',
        threat_type: 'MALICIOUS_INFRASTRUCTURE',
        malware_family: '',
        severity: 'HIGH',
        confidence: 90.0
      });
      loadCorrelation();
    } catch (err) {
      showToast(err.message || 'Failed to add indicator.', 'error');
    }
  };

  const handleDeleteIoc = async (id) => {
    try {
      await adminApi.deleteThreatIndicator(id);
      showToast('Indicator removed from active IOC feed.', 'info');
      loadCorrelation();
    } catch (err) {
      showToast(err.message || 'Failed to delete indicator.', 'error');
    }
  };

  // Filter clusters based on whether they match any of the selected options
  const clustersToDisplay = (data?.clusters || []).filter(c => {
    if (!filterByOptions) return true;
    if (selectedOptions.length === 0) return true;
    const appOpts = c.applicable_options || ['OPTION_1', 'OPTION_2', 'OPTION_3', 'OPTION_4'];
    return appOpts.some(opt => selectedOptions.includes(opt));
  });

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-6">
      {/* Header Banner */}
      <div className="glass-card p-6 border border-rose-500/40 bg-gradient-to-r from-slate-900 via-rose-950/20 to-slate-900 shadow-2xl flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="p-3 rounded-xl bg-rose-950/90 border border-rose-500/50 text-rose-400">
            <Network className="w-8 h-8" />
          </div>
          <div>
            <h1 className="text-xl font-black text-white tracking-wide flex items-center gap-2">
              Threat Intelligence Correlation Engine
              <span className="px-2 py-0.5 bg-rose-950 border border-rose-500/50 text-rose-300 text-[10px] rounded font-mono">
                EVENT-DRIVEN IOC ENGINE
              </span>
            </h1>
            <p className="text-xs text-slate-400 mt-1">
              Multi-signal correlation engine linking real security events, IOC feeds, authentication failures, and file integrity telemetry.
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowAddIocModal(true)}
            className="p-2 px-3 bg-rose-950/80 hover:bg-rose-900 text-rose-300 border border-rose-500/50 rounded-lg text-xs flex items-center gap-1.5 transition font-bold"
          >
            <Plus className="w-3.5 h-3.5" /> Add IOC Indicator
          </button>
          <button
            onClick={loadCorrelation}
            className="p-2 px-3 bg-slate-900 hover:bg-slate-800 text-slate-300 hover:text-white border border-slate-800 rounded-lg text-xs flex items-center gap-1.5 transition"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} /> Recorrelate
          </button>
        </div>
      </div>

      {/* Metric Counter Summary */}
      <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
        <div className="glass-card p-4 border border-rose-500/30 bg-rose-950/10">
          <div className="text-[11px] text-rose-300/80 font-mono uppercase">Active Threat Clusters</div>
          <div className="text-2xl font-black text-rose-400 mt-1">{data?.active_correlations_count ?? 0}</div>
          <div className="text-[10px] text-slate-500 mt-1">Multi-signal correlated incidents</div>
        </div>
        <div className="glass-card p-4 border border-cyan-500/30 bg-cyan-950/10">
          <div className="text-[11px] text-cyan-300/80 font-mono uppercase">Active IOC Indicators</div>
          <div className="text-2xl font-black text-cyan-400 mt-1">{data?.total_indicators_count ?? indicators.length}</div>
          <div className="text-[10px] text-slate-500 mt-1">Local & admin IOC database</div>
        </div>
        <div className="glass-card p-4 border border-emerald-500/30 bg-emerald-950/10">
          <div className="text-[11px] text-emerald-300/80 font-mono uppercase">Mitigated Correlations</div>
          <div className="text-2xl font-black text-emerald-400 mt-1">{data?.mitigated_count ?? 0}</div>
          <div className="text-[10px] text-slate-500 mt-1">Resolved security clusters</div>
        </div>
        <div className="glass-card p-4 border border-sky-500/30 bg-sky-950/10">
          <div className="text-[11px] text-sky-300/80 font-mono uppercase">Telemetry Events Processed</div>
          <div className="text-2xl font-black text-sky-400 mt-1">{data?.total_events_processed ?? 0}</div>
          <div className="text-[10px] text-slate-500 mt-1">Live normalized event stream</div>
        </div>
      </div>

      {/* 4 Selectable Threat Correlation Options Matrix */}
      <div className="glass-card p-6 border border-slate-700/80 bg-gradient-to-b from-slate-900 via-slate-900/90 to-slate-950 shadow-2xl space-y-5">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-800">
          <div>
            <div className="flex items-center gap-2">
              <Sliders className="w-5 h-5 text-rose-400" />
              <h2 className="text-base font-bold text-white tracking-wide flex items-center gap-2">
                Threat Correlation Strategy & Rule Matrix
                <span className="px-2 py-0.5 bg-slate-800 border border-slate-700 text-slate-300 text-[10px] rounded font-mono">
                  4 SELECTABLE VECTORS
                </span>
              </h2>
            </div>
            <p className="text-xs text-slate-400 mt-1">
              Choose single options (Option 1, Option 2, Option 3, Option 4) or any combination using the checkboxes below to filter telemetry and customize automated countermeasures.
            </p>
          </div>

          {/* Quick Preset Combination Buttons */}
          <div className="flex flex-wrap items-center gap-1.5">
            <button
              type="button"
              onClick={() => selectSingle('OPTION_1')}
              className={`px-2 py-1 rounded-md text-[11px] font-mono font-bold transition border ${
                selectedOptions.length === 1 && selectedOptions.includes('OPTION_1')
                  ? 'bg-rose-600 border-rose-500 text-white shadow'
                  : 'bg-slate-900 border-slate-800 text-slate-400 hover:text-white'
              }`}
            >
              Opt 1 (-25%)
            </button>
            <button
              type="button"
              onClick={() => selectSingle('OPTION_2')}
              className={`px-2 py-1 rounded-md text-[11px] font-mono font-bold transition border ${
                selectedOptions.length === 1 && selectedOptions.includes('OPTION_2')
                  ? 'bg-amber-600 border-amber-500 text-white shadow'
                  : 'bg-slate-900 border-slate-800 text-slate-400 hover:text-white'
              }`}
            >
              Opt 2 (-30%)
            </button>
            <button
              type="button"
              onClick={() => selectCombo(['OPTION_1', 'OPTION_2'])}
              className={`px-2.5 py-1 rounded-md text-[11px] font-mono font-bold transition border ${
                selectedOptions.length === 2 && selectedOptions.includes('OPTION_1') && selectedOptions.includes('OPTION_2')
                  ? 'bg-rose-600 border-rose-500 text-white shadow'
                  : 'bg-slate-900 border-slate-800 text-slate-400 hover:text-white'
              }`}
            >
              Combo 1+2 (-55%)
            </button>
            <button
              type="button"
              onClick={() => selectCombo(['OPTION_1', 'OPTION_3'])}
              className={`px-2.5 py-1 rounded-md text-[11px] font-mono font-bold transition border ${
                selectedOptions.length === 2 && selectedOptions.includes('OPTION_1') && selectedOptions.includes('OPTION_3')
                  ? 'bg-rose-600 border-rose-500 text-white shadow'
                  : 'bg-slate-900 border-slate-800 text-slate-400 hover:text-white'
              }`}
            >
              Combo 1+3 (-50%)
            </button>
            <button
              type="button"
              onClick={selectAll}
              className={`px-2.5 py-1 rounded-md text-[11px] font-mono font-bold transition border ${
                selectedOptions.length === 4 
                  ? 'bg-rose-600 border-rose-500 text-white shadow' 
                  : 'bg-slate-900 border-slate-800 text-slate-400 hover:text-white'
              }`}
            >
              All 4 Options (-100%)
            </button>
            <button
              type="button"
              onClick={clearAll}
              className="px-2 py-1 rounded-md text-[11px] font-mono font-medium transition bg-slate-900 border border-slate-800 text-slate-500 hover:text-rose-400"
            >
              Clear
            </button>
          </div>
        </div>

        {/* Active Combination Status Bar */}
        <div className="flex flex-wrap items-center justify-between gap-3 p-3 rounded-xl bg-slate-950/80 border border-slate-800">
          <div className="flex items-center gap-2 text-xs font-mono">
            <span className="text-slate-400">Active Rule Combination:</span>
            {selectedOptions.length > 0 ? (
              <div className="flex flex-wrap items-center gap-1.5">
                {THREAT_CORRELATION_OPTIONS.filter(o => selectedOptions.includes(o.id)).map(o => (
                  <span
                    key={o.id}
                    className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase font-mono ${
                      o.id === 'OPTION_1' ? 'bg-rose-950 text-rose-300 border border-rose-500/50' :
                      o.id === 'OPTION_2' ? 'bg-amber-950 text-amber-300 border border-amber-500/50' :
                      o.id === 'OPTION_3' ? 'bg-purple-950 text-purple-300 border border-purple-500/50' :
                      'bg-sky-950 text-sky-300 border border-sky-500/50'
                    }`}
                  >
                    {o.badge}
                  </span>
                ))}
                <span className="text-[11px] text-slate-400">
                  ({selectedOptions.length} of 4 Vectors Active)
                </span>
              </div>
            ) : (
              <span className="text-amber-400 text-xs font-bold">
                ⚠️ No options selected (Check at least one checkbox below to apply correlation or mitigation)
              </span>
            )}
          </div>
          <div className="flex items-center gap-2">
            <label className="flex items-center gap-2 cursor-pointer text-xs font-mono text-slate-400 hover:text-slate-300">
              <input
                type="checkbox"
                checked={filterByOptions}
                onChange={(e) => setFilterByOptions(e.target.checked)}
                className="rounded border-slate-700 bg-slate-900 text-rose-600 focus:ring-rose-500 w-3.5 h-3.5"
              />
              <span>Filter Clusters by Selected Options</span>
            </label>
          </div>
        </div>

        {/* 4 Checkbox Option Cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {THREAT_CORRELATION_OPTIONS.map((opt) => {
            const isChecked = selectedOptions.includes(opt.id);
            return (
              <div
                key={opt.id}
                onClick={() => toggleOption(opt.id)}
                className={`glass-card p-4 rounded-xl cursor-pointer transition border flex flex-col justify-between ${
                  isChecked
                    ? `${opt.accentBorder} ${opt.activeBg} shadow-lg ring-1 ${opt.activeRing}`
                    : 'border-slate-800 bg-slate-900/40 hover:border-slate-700 opacity-70 hover:opacity-100'
                }`}
              >
                <div className="space-y-2.5">
                  {/* Top Row: Checkbox + Badge + Preset Single Button */}
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <input
                        type="checkbox"
                        id={`checkbox-${opt.id}`}
                        checked={isChecked}
                        onChange={() => {}} // Handled by card click
                        className="rounded border-slate-700 bg-slate-900 text-rose-600 focus:ring-rose-500 w-4 h-4 cursor-pointer"
                      />
                      <span className={`px-2 py-0.5 rounded text-[10px] font-black uppercase font-mono ${
                        opt.id === 'OPTION_1' ? 'bg-rose-950 text-rose-300 border border-rose-500/50' :
                        opt.id === 'OPTION_2' ? 'bg-amber-950 text-amber-300 border border-amber-500/50' :
                        opt.id === 'OPTION_3' ? 'bg-purple-950 text-purple-300 border border-purple-500/50' :
                        'bg-sky-950 text-sky-300 border border-sky-500/50'
                      }`}>
                        {opt.badge}
                      </span>
                    </div>
                    <button
                      type="button"
                      onClick={(e) => {
                        e.stopPropagation();
                        selectSingle(opt.id);
                      }}
                      className="text-[10px] text-slate-500 hover:text-white font-mono underline"
                      title={`Select only ${opt.badge}`}
                    >
                      Only
                    </button>
                  </div>

                  {/* Option Title */}
                  <div>
                    <h3 className={`text-xs font-bold leading-snug ${isChecked ? 'text-white' : 'text-slate-300'}`}>
                      {opt.title}
                    </h3>
                    <p className="text-[11px] text-slate-400 mt-1.5 leading-relaxed">
                      {opt.description}
                    </p>
                  </div>
                </div>

                {/* Bottom Row: Countermeasure Pill */}
                <div className="mt-3 pt-3 border-t border-slate-800/80">
                  <div className="text-[10px] font-mono text-slate-500 uppercase">Automated Countermeasure:</div>
                  <div className="text-[11px] text-emerald-400/90 font-mono mt-0.5 flex items-start gap-1">
                    <span className="text-emerald-500 font-bold">⚡</span>
                    <span>{opt.countermeasure}</span>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Main Correlation Workspace */}
      {loading ? (
        <div className="glass-card p-16 text-center text-slate-400 text-xs font-mono">
          <RefreshCw className="w-6 h-6 animate-spin mx-auto mb-2 text-rose-400" />
          EVALUATING MULTI-SIGNAL THREAT CORRELATION ACROSS REPOSITORIES...
        </div>
      ) : clustersToDisplay && clustersToDisplay.length > 0 ? (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Left: Clusters List */}
          <div className="lg:col-span-5 space-y-4">
            <h2 className="text-xs font-bold text-slate-300 uppercase tracking-wider font-mono flex items-center justify-between">
              <span className="flex items-center gap-2">
                <Zap className="w-4 h-4 text-rose-400" /> Active Threat Clusters ({clustersToDisplay.length})
              </span>
              {filterByOptions && (
                <span className="text-[10px] text-amber-400 font-normal">Filtered by selected options</span>
              )}
            </h2>

            <div className="space-y-3">
              {clustersToDisplay.map((c) => {
                const isSelected = selectedCluster?.cluster_id === c.cluster_id;
                const isClusterResolved = c.status === 'RESOLVED' || c.status === 'FALSE_POSITIVE' || Number(c.threat_score || 0) === 0;
                const isCritical = c.severity === 'CRITICAL' && !isClusterResolved;
                const clusterOpts = c.applicable_options || ['OPTION_1', 'OPTION_2', 'OPTION_3', 'OPTION_4'];
                const clusterMitigatedOpts = c.mitigated_options || [];
                return (
                  <div
                    key={c.cluster_id}
                    onClick={() => setSelectedCluster(c)}
                    className={`glass-card p-4 cursor-pointer transition border ${
                      isSelected 
                        ? 'border-rose-500 bg-rose-950/30 shadow-lg shadow-rose-950/50 ring-1 ring-rose-500/50' 
                        : 'border-slate-800 hover:border-slate-700 bg-slate-900/60'
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-mono font-black text-white">{c.cluster_id}</span>
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase font-mono flex items-center gap-1 ${
                          isClusterResolved 
                            ? 'bg-emerald-950 text-emerald-400 border border-emerald-500/40' 
                            : isCritical 
                              ? 'bg-rose-950 text-rose-400 border border-rose-500/50 animate-pulse' 
                              : 'bg-amber-950 text-amber-400 border border-amber-500/40'
                        }`}>
                          {isClusterResolved && <Check className="w-3 h-3 text-emerald-400" />}
                          {isClusterResolved ? 'RESOLVED (0%)' : c.status}
                        </span>
                      </div>
                      <div className="text-right">
                        <span className={`text-xs font-mono font-bold ${isClusterResolved ? 'text-emerald-400' : 'text-rose-400'}`}>
                          {isClusterResolved ? '0% Threat' : `${c.threat_score}% Threat`}
                        </span>
                      </div>
                    </div>

                    <div className="mt-2 text-xs text-slate-300 font-medium leading-snug line-clamp-2">
                      {c.explanation}
                    </div>

                    {/* Matched Option Tags & Mitigated Status */}
                    <div className="mt-2 flex flex-wrap items-center gap-1">
                      {clusterOpts.map(optId => {
                        const isMitigated = clusterMitigatedOpts.includes(optId);
                        const isSelectedOpt = selectedOptions.includes(optId);
                        return (
                          <span
                            key={optId}
                            className={`px-1.5 py-0.2 rounded text-[9px] font-mono font-bold flex items-center gap-0.5 ${
                              isMitigated
                                ? 'bg-emerald-950 text-emerald-300 border border-emerald-500/40'
                                : isSelectedOpt
                                  ? 'bg-rose-950/80 text-rose-300 border border-rose-500/40'
                                  : 'bg-slate-900 text-slate-500 border border-slate-800'
                            }`}
                          >
                            {isMitigated && '✓ '}
                            {optId.replace('OPTION_', 'Opt ')}
                          </span>
                        );
                      })}
                    </div>

                    <div className="mt-3 flex items-center justify-between text-[11px] text-slate-500 font-mono">
                      <span>Target: <strong className="text-sky-400">{c.target_user}</strong></span>
                      <span>Confidence: <strong className="text-rose-300">{c.confidence}%</strong></span>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Right: Selected Cluster Detail Card */}
          {selectedCluster && (() => {
            const clusterScore = Number(selectedCluster.threat_score || 0);
            const isClusterResolved = clusterScore === 0 || selectedCluster.status === 'RESOLVED';
            const mitigatedOpts = selectedCluster.mitigated_options || [];

            const OPTION_REDUCTIONS = {
              OPTION_1: 25,
              OPTION_2: 30,
              OPTION_3: 25,
              OPTION_4: 20
            };

            const totalReductionFromSelected = selectedOptions.reduce((acc, opt) => acc + (OPTION_REDUCTIONS[opt] || 25), 0);
            const projectedScore = Math.max(0, Math.round((clusterScore - totalReductionFromSelected) * 10) / 10);

            return (
              <div className="lg:col-span-7 space-y-4">
                <div className="glass-card p-6 border border-slate-700 shadow-2xl space-y-6">
                  <div className="flex items-start justify-between gap-4 pb-4 border-b border-slate-800">
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="text-lg font-black text-white font-mono">{selectedCluster.cluster_id}</span>
                        <span className={`px-2 py-0.5 rounded text-xs font-bold uppercase font-mono ${
                          isClusterResolved
                            ? 'bg-emerald-950 border border-emerald-500/50 text-emerald-300'
                            : 'bg-rose-950 border border-rose-500/50 text-rose-300'
                        }`}>
                          {isClusterResolved ? 'RESOLVED (0% THREAT)' : `${selectedCluster.severity} SEVERITY`}
                        </span>
                      </div>
                      <p className="text-xs text-slate-400 mt-1">
                        Target Account: <strong className="text-sky-300">{selectedCluster.target_user}</strong> • Timestamp: {selectedCluster.created_at}
                      </p>
                    </div>
                    <div className="text-right bg-slate-950 px-3.5 py-2 rounded-xl border border-slate-800">
                      <div className="text-[10px] text-slate-400 font-mono uppercase">Correlation Score</div>
                      <div className={`text-xl font-black font-mono ${isClusterResolved ? 'text-emerald-400' : 'text-rose-400'}`}>
                        {isClusterResolved ? '0.0%' : `${selectedCluster.threat_score}%`}
                      </div>
                      <div className="text-[10px] text-slate-500 font-mono">Confidence: {selectedCluster.confidence}%</div>
                    </div>
                  </div>

                  {/* Evidence Section */}
                  <div className="space-y-3">
                    <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider font-mono flex items-center gap-1.5">
                      <CheckCircle2 className="w-4 h-4 text-emerald-400" /> Correlated Event Evidence
                    </h3>
                    <div className="space-y-2 bg-slate-950/80 p-4 rounded-xl border border-slate-800">
                      {selectedCluster.evidence?.map((item, idx) => (
                        <div key={idx} className="flex items-start gap-2.5 text-xs text-slate-300 leading-relaxed">
                          <span className="text-emerald-400 font-bold mt-0.5">✓</span>
                          <span>{item}</span>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Matched Indicators & Sources */}
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                    <div className="bg-slate-950/70 p-3.5 rounded-xl border border-slate-800 space-y-1.5">
                      <div className="text-[10px] text-slate-400 font-mono uppercase">Matched Indicators</div>
                      {selectedCluster.matched_indicators?.length > 0 ? (
                        selectedCluster.matched_indicators.map((ind, i) => (
                          <div key={i} className="text-xs font-mono text-rose-300 truncate">
                            • {ind}
                          </div>
                        ))
                      ) : (
                        <div className="text-xs text-slate-500">No direct IOC indicator matches</div>
                      )}
                    </div>
                    <div className="bg-slate-950/70 p-3.5 rounded-xl border border-slate-800 space-y-1.5">
                      <div className="text-[10px] text-slate-400 font-mono uppercase">Intelligence Sources</div>
                      {selectedCluster.threat_sources?.map((src, i) => (
                        <div key={i} className="text-xs font-mono text-cyan-300 truncate">
                          • {src}
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Recommended Mitigation & Action */}
                  <div className="p-4 rounded-xl bg-gradient-to-r from-rose-950/40 to-slate-950 border border-rose-500/40 space-y-4">
                    <div className="flex items-center justify-between">
                      <div className="text-xs font-bold text-rose-300 uppercase font-mono flex items-center gap-1.5">
                        <ShieldAlert className="w-4 h-4 text-rose-400" /> Recommended SOC Mitigation
                      </div>
                      {!isClusterResolved && (
                        <div className="text-xs font-mono text-amber-300 font-bold">
                          Remaining Threat: {clusterScore}%
                        </div>
                      )}
                    </div>
                    <div className="text-xs text-slate-300 whitespace-pre-line leading-relaxed font-mono">
                      {selectedCluster.recommended_action}
                    </div>

                    {/* Targeted Mitigation Options Selection */}
                    <div className="space-y-2 pt-2 border-t border-rose-500/20">
                      <div className="text-[11px] font-mono font-bold text-rose-300 uppercase flex items-center justify-between">
                        <span>Countermeasure Vectors to Execute:</span>
                        <span className="text-[10px] text-slate-400 font-normal">
                          {selectedOptions.length} of 4 Selected {!isClusterResolved && `(-${totalReductionFromSelected}% Threat Reduction)`}
                        </span>
                      </div>
                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                        {THREAT_CORRELATION_OPTIONS.map(opt => {
                          const isChecked = selectedOptions.includes(opt.id);
                          const isOptMitigated = mitigatedOpts.includes(opt.id);
                          const reductionVal = OPTION_REDUCTIONS[opt.id] || 25;
                          return (
                            <label
                              key={opt.id}
                              className={`flex items-center justify-between p-2 rounded-lg border text-xs font-mono cursor-pointer transition ${
                                isChecked 
                                  ? isOptMitigated && isClusterResolved
                                    ? 'border-emerald-500/50 bg-emerald-950/40 text-emerald-300'
                                    : 'border-rose-500/50 bg-rose-950/40 text-white' 
                                  : 'border-slate-800 bg-slate-900/40 text-slate-400 hover:text-slate-200'
                              }`}
                            >
                              <div className="flex items-center gap-2 truncate">
                                <input
                                  type="checkbox"
                                  checked={isChecked}
                                  onChange={() => toggleOption(opt.id)}
                                  className="rounded border-slate-700 bg-slate-900 text-rose-600 focus:ring-rose-500 w-3.5 h-3.5"
                                />
                                <span className="truncate flex items-center gap-1">
                                  {isOptMitigated && isClusterResolved && <Check className="w-3 h-3 text-emerald-400" />}
                                  {opt.badge}: {opt.shortTitle.split(':')[1]}
                                </span>
                              </div>
                              <span className="text-[10px] text-rose-400 font-bold shrink-0 ml-1">
                                -{reductionVal}%
                              </span>
                            </label>
                          );
                        })}
                      </div>
                    </div>

                    {/* Projected Threat Calculation Bar */}
                    {!isClusterResolved && (
                      <div className="p-2.5 rounded-lg bg-slate-950/80 border border-slate-800 flex items-center justify-between text-xs font-mono">
                        <span className="text-slate-400">Projected Threat Score:</span>
                        <div className="flex items-center gap-2 font-bold">
                          <span className="text-rose-400">{clusterScore}%</span>
                          <span className="text-slate-500">→</span>
                          <span className={projectedScore === 0 ? "text-emerald-400" : "text-amber-400"}>
                            {projectedScore}% Threat
                          </span>
                          {projectedScore === 0 && (
                            <span className="px-1.5 py-0.2 rounded bg-emerald-950 text-emerald-300 border border-emerald-500/40 text-[10px]">
                              100% CONTAINED
                            </span>
                          )}
                        </div>
                      </div>
                    )}

                    {/* Mitigation State: Resolved (0%) vs In-Progress (>0%) */}
                    {isClusterResolved ? (
                      /* 0% Threat Score: Stop Asking for Mitigation Execution */
                      <div className="p-3.5 rounded-xl bg-emerald-950/50 border border-emerald-500/50 space-y-2">
                        <div className="flex items-center gap-2 text-xs font-bold text-emerald-300 font-mono">
                          <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                          <span>0.0% THREAT SCORE ACHIEVED — INCIDENT FULLY RESOLVED</span>
                          <span className="px-2 py-0.5 rounded bg-emerald-900 text-emerald-200 text-[10px] font-mono border border-emerald-400/40">
                            EXECUTION COMPLETED
                          </span>
                        </div>
                        <p className="text-[11px] text-emerald-200/80 leading-relaxed">
                          All threat vectors have been neutralized to <strong>0.0%</strong>. The correlation engine has stopped asking for mitigation execution as this cluster is fully resolved.
                        </p>
                        <div className="pt-1 flex justify-end">
                          <div className="px-5 py-2.5 rounded-lg text-xs font-bold font-mono flex items-center gap-2 bg-emerald-950 text-emerald-300 border border-emerald-500/50 shadow">
                            <ShieldCheck className="w-4 h-4 text-emerald-400" />
                            Incident Contained (0.0% Threat — Complete)
                          </div>
                        </div>
                      </div>
                    ) : (
                      /* Active Mitigation Execution Button (while >0%) */
                      <div className="pt-2 flex justify-end">
                        <button
                          onClick={() => handleExecuteAction(selectedCluster.recommended_action || "Execute Countermeasures")}
                          disabled={executingAction !== null || selectedOptions.length === 0}
                          className="btn-cyber px-5 py-2.5 rounded-lg text-xs font-bold flex items-center gap-2 bg-rose-600 hover:bg-rose-500 text-white disabled:opacity-50 disabled:cursor-not-allowed shadow-lg"
                        >
                          {executingAction ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Zap className="w-4 h-4" />}
                          Execute Mitigation ({selectedOptions.map(o => o.replace('OPTION_', 'Opt ')).join('+')}: -{totalReductionFromSelected}% Threat)
                        </button>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            );
          })()}
        </div>
      ) : (
        /* Empty Telemetry State */
        <div className="glass-card p-12 text-center border border-slate-800 space-y-4">
          <div className="w-12 h-12 rounded-full bg-slate-900 border border-slate-800 flex items-center justify-center mx-auto text-slate-500">
            <ShieldCheck className="w-6 h-6 text-emerald-400" />
          </div>
          <div>
            <h3 className="text-base font-bold text-white">No Threat Intelligence Matches Found</h3>
            <p className="text-xs text-slate-400 mt-1 max-w-md mx-auto">
              {filterByOptions 
                ? 'No active threat clusters match the currently selected combination of correlation options.' 
                : 'All system operations, user logins, and uploaded artifacts currently conform to clean integrity baselines.'}
            </p>
          </div>
        </div>
      )}

      {/* IOC Management Table */}
      <div className="glass-card p-6 border border-slate-800 shadow-xl space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Database className="w-5 h-5 text-cyan-400" />
            <h2 className="text-sm font-bold text-white">Threat Intelligence IOC Repository</h2>
          </div>
          <span className="text-xs text-slate-400 font-mono">{indicators.length} Active Indicators</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-900/90 text-slate-400 uppercase font-mono text-[11px] border-b border-slate-800">
              <tr>
                <th className="p-3">Indicator</th>
                <th className="p-3">Type</th>
                <th className="p-3">Threat Category</th>
                <th className="p-3">Family</th>
                <th className="p-3">Severity</th>
                <th className="p-3">Source</th>
                <th className="p-3 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800 font-mono">
              {indicators.map((ind) => (
                <tr key={ind.id} className="hover:bg-slate-900/50">
                  <td className="p-3 font-bold text-white truncate max-w-xs">{ind.indicator}</td>
                  <td className="p-3 text-cyan-300">{ind.indicator_type || ind.type}</td>
                  <td className="p-3 text-slate-300">{ind.threat_type}</td>
                  <td className="p-3 text-rose-300">{ind.malware_family}</td>
                  <td className="p-3">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                      ind.severity === 'CRITICAL' ? 'bg-rose-950 text-rose-400 border border-rose-500/50' : 'bg-amber-950 text-amber-400 border border-amber-500/40'
                    }`}>
                      {ind.severity}
                    </span>
                  </td>
                  <td className="p-3 text-slate-400">{ind.source}</td>
                  <td className="p-3 text-right">
                    <button
                      onClick={() => handleDeleteIoc(ind.id)}
                      className="p-1 text-slate-500 hover:text-rose-400 transition"
                      title="Deactivate Indicator"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Add IOC Modal */}
      {showAddIocModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fade-in">
          <div className="glass-card max-w-md w-full p-6 border border-slate-700 shadow-2xl relative">
            <button
              onClick={() => setShowAddIocModal(false)}
              className="absolute top-4 right-4 text-slate-400 hover:text-white"
            >
              <X className="w-5 h-5" />
            </button>
            <h3 className="text-base font-bold text-white mb-4 flex items-center gap-2">
              <Plus className="w-4 h-4 text-rose-400" /> Add Threat Intelligence IOC
            </h3>

            <form onSubmit={handleAddIocSubmit} className="space-y-4">
              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1.5">Indicator Value</label>
                <input
                  type="text"
                  value={newIoc.indicator}
                  onChange={(e) => setNewIoc(prev => ({ ...prev, indicator: e.target.value }))}
                  placeholder="e.g. 198.51.100.42 or SHA-256 hash"
                  className="w-full bg-slate-900 border border-slate-700 rounded-lg p-2.5 text-xs text-white font-mono focus:outline-none focus:border-rose-500"
                  required
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-1.5">Type</label>
                  <select
                    value={newIoc.indicator_type}
                    onChange={(e) => setNewIoc(prev => ({ ...prev, indicator_type: e.target.value }))}
                    className="w-full bg-slate-900 border border-slate-700 rounded-lg p-2 text-xs text-white"
                  >
                    <option value="IP_ADDRESS">IP_ADDRESS</option>
                    <option value="SHA256">SHA256</option>
                    <option value="MD5">MD5</option>
                    <option value="DOMAIN">DOMAIN</option>
                    <option value="URL">URL</option>
                  </select>
                </div>

                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-1.5">Severity</label>
                  <select
                    value={newIoc.severity}
                    onChange={(e) => setNewIoc(prev => ({ ...prev, severity: e.target.value }))}
                    className="w-full bg-slate-900 border border-slate-700 rounded-lg p-2 text-xs text-white"
                  >
                    <option value="CRITICAL">CRITICAL</option>
                    <option value="HIGH">HIGH</option>
                    <option value="MEDIUM">MEDIUM</option>
                    <option value="LOW">LOW</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1.5">Malware Family / Label</label>
                <input
                  type="text"
                  value={newIoc.malware_family}
                  onChange={(e) => setNewIoc(prev => ({ ...prev, malware_family: e.target.value }))}
                  placeholder="e.g. Cobalt Strike, LockBit, Brute Force Ingress"
                  className="w-full bg-slate-900 border border-slate-700 rounded-lg p-2.5 text-xs text-white focus:outline-none focus:border-rose-500"
                />
              </div>

              <div className="pt-2 flex justify-end gap-2">
                <button
                  type="button"
                  onClick={() => setShowAddIocModal(false)}
                  className="px-4 py-2 bg-slate-900 hover:bg-slate-800 text-slate-300 rounded-lg text-xs"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="btn-cyber px-5 py-2 bg-rose-600 hover:bg-rose-500 text-white rounded-lg text-xs font-bold"
                >
                  Register Indicator
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Mitigation Report Modal */}
      {mitigationReport && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fade-in">
          <div className="glass-card max-w-lg w-full p-6 border border-emerald-500/50 shadow-2xl relative space-y-4">
            <button
              onClick={() => setMitigationReport(null)}
              className="absolute top-4 right-4 text-slate-400 hover:text-white"
            >
              <X className="w-5 h-5" />
            </button>
            <div className="flex items-center gap-3">
              <div className="p-2.5 bg-emerald-950 rounded-xl border border-emerald-500/40 text-emerald-400">
                <ShieldCheck className="w-6 h-6" />
              </div>
              <div>
                <h3 className="text-base font-bold text-white">Countermeasures Enforced</h3>
                <p className="text-xs text-slate-400 font-mono">{mitigationReport.cluster.cluster_id} Status Updated</p>
              </div>
            </div>

            {/* Selected Options Badges */}
            <div className="p-3 bg-slate-950/80 rounded-xl border border-slate-800 space-y-1.5">
              <div className="text-[10px] text-slate-400 font-mono uppercase">Applied Correlation Options:</div>
              <div className="flex flex-wrap items-center gap-1.5">
                {(mitigationReport.selected_options || []).map(optId => (
                  <span
                    key={optId}
                    className="px-2 py-0.5 rounded text-[10px] font-bold font-mono bg-emerald-950 text-emerald-300 border border-emerald-500/40"
                  >
                    {optId}
                  </span>
                ))}
              </div>
            </div>

            <div className="space-y-2 bg-slate-950 p-4 rounded-xl border border-slate-800">
              <div className="text-xs font-bold text-slate-300 font-mono mb-2">Actions Applied to Database:</div>
              {mitigationReport.actions_taken?.map((act, i) => (
                <div key={i} className="text-xs text-emerald-300 flex items-start gap-2">
                  <Check className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                  <span>{act}</span>
                </div>
              ))}
            </div>

            <div className="pt-2 flex justify-end">
              <button
                onClick={() => setMitigationReport(null)}
                className="px-5 py-2 bg-slate-800 hover:bg-slate-700 text-white rounded-lg text-xs font-bold"
              >
                Close Report
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

