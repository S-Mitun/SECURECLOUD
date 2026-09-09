import React, { useEffect, useState } from 'react';
import { adminApi } from '../../api/adminApi';
import { useApp } from '../../context/AppContext';
import { Shield, Plus, Trash2, RefreshCw, CheckCircle2, AlertOctagon } from 'lucide-react';

export function IpGuard() {
  const { showToast } = useApp();
  const [rules, setRules] = useState([]);
  const [loading, setLoading] = useState(true);
  const [newIp, setNewIp] = useState('');
  const [ruleType, setRuleType] = useState('BLACKLIST');
  const [description, setDescription] = useState('');
  const [submitting, setSubmitting] = useState(false);

  const loadRules = async () => {
    setLoading(true);
    try {
      const data = await adminApi.listIpRules();
      setRules(Array.isArray(data) ? data : (data.rules || []));
    } catch (err) {
      showToast(err.message || 'Failed to load IP rules.', 'error');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadRules();
  }, []);

  const handleAddRule = async (e) => {
    e.preventDefault();
    if (!newIp) return;

    setSubmitting(true);
    try {
      await adminApi.addIpRule({
        ip_address: newIp.trim(),
        rule_type: ruleType,
        description
      });
      showToast(`IP Rule for "${newIp}" added!`, 'success');
      setNewIp('');
      setDescription('');
      loadRules();
    } catch (err) {
      showToast(err.message || 'Failed to add rule.', 'error');
    } finally {
      setSubmitting(false);
    }
  };

  const handleDeleteRule = async (ruleId) => {
    try {
      await adminApi.deleteIpRule(ruleId);
      showToast('IP Rule removed.', 'info');
      loadRules();
    } catch (err) {
      showToast(err.message || 'Failed to delete rule.', 'error');
    }
  };

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-6">
      {/* Header Banner */}
      <div className="glass-card p-6 border border-amber-500/40 bg-gradient-to-r from-slate-900 via-amber-950/20 to-slate-900 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="p-3 rounded-xl bg-amber-950/90 border border-amber-500/50 text-amber-400">
            <Shield className="w-8 h-8" />
          </div>
          <div>
            <h1 className="text-xl font-black text-white tracking-wide">
              IP Access Guard & Threat Firewall
            </h1>
            <p className="text-xs text-slate-400 mt-1">
              Configure perimeter IP whitelisting and blacklisting policies to block suspicious network originations.
            </p>
          </div>
        </div>
        <button
          onClick={loadRules}
          className="p-2 bg-slate-900 hover:bg-slate-800 text-slate-400 hover:text-white border border-slate-800 rounded-lg text-xs flex items-center gap-1.5"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} /> Refresh Policies
        </button>
      </div>

      {/* Add Rule Form */}
      <div className="glass-card p-5 border border-slate-800">
        <h3 className="text-xs font-bold text-slate-300 uppercase tracking-wider mb-3 flex items-center gap-1.5">
          <Plus className="w-4 h-4 text-sky-400" /> Define New IP Access Rule
        </h3>
        <form onSubmit={handleAddRule} className="grid grid-cols-1 sm:grid-cols-4 gap-3">
          <input
            type="text"
            value={newIp}
            onChange={(e) => setNewIp(e.target.value)}
            placeholder="IP Address (e.g. 192.168.1.50)"
            className="bg-slate-900 border border-slate-700 rounded-lg px-3.5 py-2 text-xs text-white focus:outline-none focus:border-amber-500 font-mono"
            required
          />
          <select
            value={ruleType}
            onChange={(e) => setRuleType(e.target.value)}
            className="bg-slate-900 border border-slate-700 rounded-lg px-3.5 py-2 text-xs text-white focus:outline-none focus:border-amber-500 font-bold"
          >
            <option value="BLACKLIST">BLACKLIST (Deny Access)</option>
            <option value="WHITELIST">WHITELIST (Always Allow)</option>
          </select>
          <input
            type="text"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="Rule Description / Origin..."
            className="bg-slate-900 border border-slate-700 rounded-lg px-3.5 py-2 text-xs text-white focus:outline-none focus:border-amber-500"
          />
          <button
            type="submit"
            disabled={submitting}
            className="btn-cyber py-2 rounded-lg text-xs font-bold flex items-center justify-center gap-1.5"
          >
            <Plus className="w-4 h-4" /> Add Rule
          </button>
        </form>
      </div>

      {/* Rules Table */}
      <div className="glass-card overflow-hidden border border-slate-800">
        <div className="overflow-x-auto">
          <table className="soc-table">
            <thead>
              <tr>
                <th>IP Address / CIDR</th>
                <th>Policy Rule</th>
                <th>Description</th>
                <th>Added Date</th>
                <th className="text-right">Action</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr>
                  <td colSpan="5" className="text-center py-16 text-slate-400 font-mono text-xs">
                    <RefreshCw className="w-5 h-5 animate-spin mx-auto mb-2 text-amber-400" />
                    SYNCING PERIMETER FIREWALL RULES...
                  </td>
                </tr>
              ) : rules.length > 0 ? (
                rules.map((r) => (
                  <tr key={r.id}>
                    <td className="font-mono text-xs font-bold text-white">
                      {r.ip_address}
                    </td>
                    <td>
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold font-mono ${
                          r.rule_type === 'BLACKLIST'
                            ? 'bg-red-950/80 text-red-400 border border-red-500/40'
                            : 'bg-emerald-950/80 text-emerald-400 border border-emerald-500/40'
                        }`}
                      >
                        {r.rule_type}
                      </span>
                    </td>
                    <td className="text-xs text-slate-300">
                      {r.description || 'Perimeter access rule'}
                    </td>
                    <td className="font-mono text-xs text-slate-400">
                      {new Date(r.created_at || Date.now()).toLocaleDateString()}
                    </td>
                    <td className="text-right">
                      <button
                        onClick={() => handleDeleteRule(r.id)}
                        className="p-1.5 bg-slate-800 hover:bg-red-950 text-slate-400 hover:text-red-400 rounded-lg transition border border-slate-700"
                        title="Delete Rule"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan="5" className="text-center py-12 text-slate-500 text-xs">
                    No active firewall rules defined.
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
