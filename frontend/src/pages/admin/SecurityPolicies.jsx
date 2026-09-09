import React, { useEffect, useState } from 'react';
import { adminApi } from '../../api/adminApi';
import { useApp } from '../../context/AppContext';
import { 
  Zap, Plus, RefreshCw, Trash2, CheckCircle2, 
  AlertTriangle, Shield, Sliders, Play, X, ToggleLeft, ToggleRight, History
} from 'lucide-react';

export function SecurityPolicies() {
  const { showToast } = useApp();
  const [policies, setPolicies] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [viewingHistory, setViewingHistory] = useState(null); // { policy, history: [] }
  const [runningPolicyId, setRunningPolicyId] = useState(null);
  const [newPolicy, setNewPolicy] = useState({
    name: '',
    description: '',
    severity: 'HIGH',
    trigger_type: 'MALICIOUS_BURST',
    actions: ['QUARANTINE_FILES', 'REVOKE_ACTIVE_SHARES']
  });

  const loadPolicies = async () => {
    setLoading(true);
    try {
      const data = await adminApi.listSecurityPolicies();
      setPolicies(data || []);
    } catch (err) {
      showToast(err.message || 'Failed to load Security Policies.', 'error');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadPolicies();
  }, []);

  const handleToggle = async (policyId) => {
    try {
      const res = await adminApi.toggleSecurityPolicy(policyId);
      showToast(res.message || 'Policy status updated.', 'success');
      loadPolicies();
    } catch (err) {
      showToast(err.message || 'Failed to toggle policy.', 'error');
    }
  };

  const handleDelete = async (policyId) => {
    if (!window.confirm('Delete this automated security response policy?')) return;
    try {
      const res = await adminApi.deleteSecurityPolicy(policyId);
      showToast(res.message || 'Policy removed.', 'success');
      loadPolicies();
    } catch (err) {
      showToast(err.message || 'Failed to delete policy.', 'error');
    }
  };

  
  const handleViewHistory = async (policy) => {
    try {
      const res = await adminApi.getPolicyHistory(policy.id);
      setViewingHistory(res);
    } catch (err) {
      showToast(err.message || 'Failed to fetch policy execution history.', 'error');
    }
  };

  const handleManualTrigger = async (policyId) => {
    setRunningPolicyId(policyId);
    try {
      const res = await adminApi.triggerPolicyExecution(policyId);
      showToast(`⚡ ${res.message}`, 'success');
      loadPolicies();
    } catch (err) {
      showToast(err.message || 'Failed to trigger policy.', 'error');
    } finally {
      setRunningPolicyId(null);
    }
  };

  const handleCreatePolicy = async (e) => {
    e.preventDefault();
    try {
      await adminApi.createSecurityPolicy(newPolicy);
      showToast(`⚡ Automated Policy '${newPolicy.name}' deployed.`, 'success');
      setShowCreateModal(false);
      setNewPolicy({
        name: '',
        description: '',
        severity: 'HIGH',
        trigger_type: 'MALICIOUS_BURST',
        actions: ['QUARANTINE_FILES', 'REVOKE_ACTIVE_SHARES']
      });
      loadPolicies();
    } catch (err) {
      showToast(err.message || 'Failed to create policy.', 'error');
    }
  };

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-6">
      {/* Header Banner */}
      <div className="glass-card p-6 border border-amber-500/40 bg-gradient-to-r from-slate-900 via-amber-950/20 to-slate-900 shadow-2xl flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="p-3 rounded-xl bg-amber-950/90 border border-amber-500/50 text-amber-400">
            <Zap className="w-8 h-8" />
          </div>
          <div>
            <h1 className="text-xl font-black text-white tracking-wide flex items-center gap-2">
              Automated Security Response Policies Engine
              <span className="px-2 py-0.5 bg-amber-950 border border-amber-500/50 text-amber-300 text-[10px] rounded font-mono">
                SOAR AUTOMATION
              </span>
            </h1>
            <p className="text-xs text-slate-400 mt-1">
              Autonomous mitigation triggers: automatic malware quarantine, public share revocation, brute force IP bans, and MFA escalation.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowCreateModal(true)}
            className="px-3.5 py-2 bg-amber-600 hover:bg-amber-500 text-white rounded-xl text-xs font-bold flex items-center gap-1.5 transition shadow-lg"
          >
            <Plus className="w-4 h-4" /> New Policy Rule
          </button>
          <button
            onClick={loadPolicies}
            className="p-2 bg-slate-900 hover:bg-slate-800 text-slate-300 hover:text-white border border-slate-800 rounded-lg text-xs transition"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* Metric Counters */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="glass-card p-4 border border-amber-500/30 bg-amber-950/10">
          <div className="text-[11px] text-amber-300/80 font-mono uppercase">Active Automated Policies</div>
          <div className="text-2xl font-black text-amber-400 mt-1">{policies.filter(p => p.is_active).length}</div>
          <div className="text-[10px] text-slate-500 mt-1">Autonomous triggers armed</div>
        </div>
        <div className="glass-card p-4 border border-emerald-500/30 bg-emerald-950/10">
          <div className="text-[11px] text-emerald-300/80 font-mono uppercase">Total Policy Executions</div>
          <div className="text-2xl font-black text-emerald-400 mt-1">
            {policies.reduce((acc, p) => acc + (p.execution_count || 0), 0)}
          </div>
          <div className="text-[10px] text-slate-500 mt-1">Mitigations automatically handled</div>
        </div>
        <div className="glass-card p-4 border border-sky-500/30 bg-sky-950/10">
          <div className="text-[11px] text-sky-300/80 font-mono uppercase">Engine Status</div>
          <div className="text-2xl font-black text-sky-400 mt-1">ACTIVE</div>
          <div className="text-[10px] text-slate-500 mt-1">Sub-second execution loop</div>
        </div>
      </div>

      {/* Policies Grid */}
      {loading ? (
        <div className="glass-card p-16 text-center text-slate-400 text-xs font-mono">
          <RefreshCw className="w-6 h-6 animate-spin mx-auto mb-2 text-amber-400" />
          SYNCHRONIZING SOAR POLICIES ENGINE...
        </div>
      ) : policies.length > 0 ? (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {policies.map((p) => {
            const isCrit = p.severity === 'CRITICAL';
            const isHigh = p.severity === 'HIGH';

            return (
              <div
                key={p.id}
                className={`glass-card p-5 border transition ${
                  p.is_active ? 'border-amber-500/40 bg-slate-900/80' : 'border-slate-800 bg-slate-900/40 opacity-75'
                }`}
              >
                <div className="flex items-start justify-between gap-3 mb-3">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold font-mono ${
                        isCrit ? 'bg-rose-950 text-rose-400 border border-rose-500/40' :
                        isHigh ? 'bg-amber-950 text-amber-400 border border-amber-500/40' :
                        'bg-sky-950 text-sky-400 border border-sky-500/40'
                      }`}>
                        {p.severity}
                      </span>
                      <span className="font-mono text-[11px] text-slate-400">Trigger: {p.trigger_type}</span>
                    </div>
                    <h3 className="text-base font-bold text-white mt-1.5">{p.name}</h3>
                  </div>

                  {/* Toggle Switch */}
                  <button
                    onClick={() => handleToggle(p.id)}
                    className="p-1 text-slate-400 hover:text-white transition"
                    title={p.is_active ? 'Deactivate Policy' : 'Activate Policy'}
                  >
                    {p.is_active ? (
                      <ToggleRight className="w-8 h-8 text-emerald-400" />
                    ) : (
                      <ToggleLeft className="w-8 h-8 text-slate-600" />
                    )}
                  </button>
                </div>

                <p className="text-xs text-slate-300 leading-relaxed mb-4">{p.description}</p>

                {/* Automated Actions */}
                <div className="space-y-1.5 mb-4">
                  <div className="text-[10px] text-slate-500 uppercase font-mono">Automated Response Stack:</div>
                  <div className="flex flex-wrap gap-1.5">
                    {p.actions?.map((act, i) => (
                      <span key={i} className="px-2 py-0.5 bg-slate-950 border border-slate-800 text-[10px] text-amber-300 font-mono rounded">
                        ⚡ {act}
                      </span>
                    ))}
                  </div>
                </div>

                {/* Footer Actions & Telemetry */}
                <div className="pt-3 border-t border-slate-800 flex flex-wrap items-center justify-between gap-2 text-[11px] font-mono">
                  <div className="flex items-center gap-2">
                    <span className="text-slate-400">
                      Executed: <strong className="text-amber-300 font-bold">{p.execution_count || 0} times</strong>
                    </span>
                    <span className="text-slate-600">•</span>
                    <span className="text-slate-500 text-[10px] truncate max-w-[120px]">{p.last_triggered_at}</span>
                  </div>

                  <div className="flex items-center gap-1.5">
                    {/* Manual Test / Execute Button */}
                    <button
                      onClick={() => handleManualTrigger(p.id)}
                      disabled={runningPolicyId === p.id}
                      className="px-2.5 py-1 bg-amber-950/80 hover:bg-amber-900 border border-amber-500/40 text-amber-300 hover:text-white rounded-lg text-xs font-bold flex items-center gap-1 transition shadow"
                      title="Test & Execute Defense Routine"
                    >
                      {runningPolicyId === p.id ? (
                        <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                      ) : (
                        <Play className="w-3.5 h-3.5 fill-current" />
                      )}
                      <span>{runningPolicyId === p.id ? 'Running...' : 'Test / Execute'}</span>
                    </button>

                    {/* Execution History Button */}
                    <button
                      onClick={() => handleViewHistory(p)}
                      className="px-2 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white border border-slate-700 rounded-lg text-xs font-medium flex items-center gap-1 transition"
                      title="View Policy Trigger History"
                    >
                      <History className="w-3.5 h-3.5" />
                      <span>History</span>
                    </button>

                    <button
                      onClick={() => handleDelete(p.id)}
                      className="p-1 text-slate-500 hover:text-rose-400 transition"
                      title="Delete Policy"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      ) : (
        <div className="glass-card p-16 text-center text-slate-400 text-xs font-mono">
          NO AUTOMATED SECURITY POLICIES REGISTERED. CREATE A POLICY TO ARM SOAR MITIGATION.
        </div>
      )}

      {/* Create Policy Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="glass-card p-6 max-w-lg w-full border border-amber-500/50 shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="font-bold text-white text-base flex items-center gap-2">
                <Zap className="w-5 h-5 text-amber-400" /> Deploy Autonomous Response Policy
              </h3>
              <button onClick={() => setShowCreateModal(false)} className="text-slate-500 hover:text-white">
                <X className="w-5 h-5" />
              </button>
            </div>

            <form onSubmit={handleCreatePolicy} className="space-y-4 text-xs">
              <div>
                <label className="block text-slate-300 font-semibold mb-1">Policy Name</label>
                <input
                  type="text"
                  placeholder="e.g., Immediate Ransomware Containment"
                  value={newPolicy.name}
                  onChange={(e) => setNewPolicy({ ...newPolicy, name: e.target.value })}
                  required
                  className="w-full bg-slate-900 border border-slate-700 rounded-xl px-3 py-2 text-white focus:outline-none focus:border-amber-500"
                />
              </div>

              <div>
                <label className="block text-slate-300 font-semibold mb-1">Description</label>
                <textarea
                  rows={2}
                  placeholder="Describes conditions and automatic response workflow..."
                  value={newPolicy.description}
                  onChange={(e) => setNewPolicy({ ...newPolicy, description: e.target.value })}
                  required
                  className="w-full bg-slate-900 border border-slate-700 rounded-xl px-3 py-2 text-white focus:outline-none focus:border-amber-500"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-300 font-semibold mb-1">Trigger Condition</label>
                  <select
                    value={newPolicy.trigger_type}
                    onChange={(e) => setNewPolicy({ ...newPolicy, trigger_type: e.target.value })}
                    className="w-full bg-slate-900 border border-slate-700 rounded-xl px-3 py-2 text-white font-mono focus:outline-none focus:border-amber-500"
                  >
                    <option value="MALICIOUS_BURST">Malicious File Burst</option>
                    <option value="BRUTE_FORCE_IP">Brute Force Auth Attack</option>
                    <option value="REPEATED_SUSPICIOUS">Repeated Suspicious Ingress</option>
                    <option value="SHARE_EXFILTRATION">Mass Shared Link Generation</option>
                  </select>
                </div>

                <div>
                  <label className="block text-slate-300 font-semibold mb-1">Severity Level</label>
                  <select
                    value={newPolicy.severity}
                    onChange={(e) => setNewPolicy({ ...newPolicy, severity: e.target.value })}
                    className="w-full bg-slate-900 border border-slate-700 rounded-xl px-3 py-2 text-white font-mono focus:outline-none focus:border-amber-500"
                  >
                    <option value="CRITICAL">CRITICAL</option>
                    <option value="HIGH">HIGH</option>
                    <option value="MEDIUM">MEDIUM</option>
                  </select>
                </div>
              </div>

              <div className="flex items-center justify-end gap-2 pt-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowCreateModal(false)}
                  className="px-4 py-2 bg-slate-900 hover:bg-slate-800 text-slate-400 hover:text-white rounded-xl font-semibold"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 bg-amber-600 hover:bg-amber-500 text-white rounded-xl font-bold shadow-lg"
                >
                  Arm & Deploy Policy
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Policy Execution History Modal */}
      {viewingHistory && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fade-in">
          <div className="glass-card max-w-2xl w-full border border-amber-500/40 shadow-2xl p-6 relative space-y-4 animate-scale-up max-h-[85vh] flex flex-col">
            <button
              onClick={() => setViewingHistory(null)}
              className="absolute right-4 top-4 text-slate-400 hover:text-white p-1 rounded-lg"
            >
              <X className="w-5 h-5" />
            </button>

            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-xl bg-amber-950 border border-amber-500/40 flex items-center justify-center text-amber-400">
                <Zap className="w-5 h-5" />
              </div>
              <div>
                <h3 className="text-base font-black text-white">{viewingHistory.policy_name}</h3>
                <p className="text-xs text-slate-400 font-mono">
                  Autonomous SOAR Execution History • Total Triggers: {viewingHistory.execution_count}
                </p>
              </div>
            </div>

            <div className="flex-1 overflow-y-auto space-y-2.5 pr-1">
              {viewingHistory.history?.map((log, idx) => (
                <div key={idx} className="p-3 bg-slate-950 rounded-xl border border-slate-800 space-y-1 font-mono text-xs">
                  <div className="flex items-center justify-between">
                    <span className="text-amber-400 font-bold">{log.trigger_event}</span>
                    <span className="text-[10px] text-slate-500">{log.timestamp}</span>
                  </div>
                  <div className="text-slate-300">Target: <span className="text-white font-semibold">{log.target}</span></div>
                  <div className="text-slate-400 text-[11px] leading-relaxed">{log.details}</div>
                  <div className="flex items-center gap-1.5 pt-1">
                    <span className="px-1.5 py-0.2 bg-emerald-950 border border-emerald-500/40 text-emerald-300 text-[10px] rounded">
                      SUCCESS
                    </span>
                    {log.actions_applied?.map((act, i) => (
                      <span key={i} className="px-1.5 py-0.2 bg-slate-900 border border-slate-700 text-slate-300 text-[10px] rounded">
                        {act}
                      </span>
                    ))}
                  </div>
                </div>
              ))}
            </div>

            <div className="flex justify-end pt-2 border-t border-slate-800">
              <button
                onClick={() => setViewingHistory(null)}
                className="px-4 py-2 bg-slate-900 hover:bg-slate-800 text-slate-300 rounded-xl text-xs font-semibold"
              >
                Close Logs
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
