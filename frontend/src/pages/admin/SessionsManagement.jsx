import React, { useEffect, useState } from 'react';
import { adminApi } from '../../api/adminApi';
import { useApp } from '../../context/AppContext';
import { Key, RefreshCw, XCircle, ShieldCheck } from 'lucide-react';

export function SessionsManagement() {
  const { showToast } = useApp();
  const [sessions, setSessions] = useState([]);
  const [loading, setLoading] = useState(true);

  const loadSessions = async () => {
    setLoading(true);
    try {
      const data = await adminApi.listSessions();
      setSessions(Array.isArray(data) ? data : (data.sessions || []));
    } catch (err) {
      showToast(err.message || 'Failed to load active sessions.', 'error');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadSessions();
  }, []);

  const handleRevoke = async (sessionId) => {
    try {
      await adminApi.revokeSession(sessionId);
      showToast('Session revoked immediately.', 'info');
      loadSessions();
    } catch (err) {
      showToast(err.message || 'Failed to revoke session.', 'error');
    }
  };

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-6">
      {/* Header Banner */}
      <div className="glass-card p-6 border border-purple-500/40 bg-gradient-to-r from-slate-900 via-purple-950/20 to-slate-900 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="p-3 rounded-xl bg-purple-950/90 border border-purple-500/50 text-purple-400">
            <Key className="w-8 h-8" />
          </div>
          <div>
            <h1 className="text-xl font-black text-white tracking-wide">
              Active User Sessions & Tokens
            </h1>
            <p className="text-xs text-slate-400 mt-1">
              Real-time inspection of active JWT tokens, IP originations, and instant session revocation.
            </p>
          </div>
        </div>
        <button
          onClick={loadSessions}
          className="p-2 bg-slate-900 hover:bg-slate-800 text-slate-400 hover:text-white border border-slate-800 rounded-lg text-xs flex items-center gap-1.5"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} /> Refresh Sessions
        </button>
      </div>

      {/* Table */}
      <div className="glass-card overflow-hidden border border-slate-800">
        <div className="overflow-x-auto">
          <table className="soc-table">
            <thead>
              <tr>
                <th>User Account</th>
                <th>IP Address</th>
                <th>Device / Browser</th>
                <th>Login Time</th>
                <th>Status</th>
                <th className="text-right">Action</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr>
                  <td colSpan="6" className="text-center py-16 text-slate-400 font-mono text-xs">
                    <RefreshCw className="w-5 h-5 animate-spin mx-auto mb-2 text-purple-400" />
                    AUDITING ACTIVE JWT TOKENS...
                  </td>
                </tr>
              ) : sessions.length > 0 ? (
                sessions.map((s) => (
                  <tr key={s.id}>
                    <td>
                      <div className="font-bold text-white text-xs sm:text-sm">
                        {s.username || s.email}
                      </div>
                      <div className="text-[10px] text-slate-400 font-mono">
                        {s.email}
                      </div>
                    </td>
                    <td className="font-mono text-xs text-slate-300">
                      {s.ip_address || '127.0.0.1'}
                    </td>
                    <td className="text-xs text-slate-400">
                      {s.user_agent || 'Chrome / Desktop Web'}
                    </td>
                    <td className="font-mono text-xs text-slate-400">
                      {new Date(s.created_at || Date.now()).toLocaleString()}
                    </td>
                    <td>
                      <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-950/80 text-emerald-400 border border-emerald-500/40">
                        ACTIVE
                      </span>
                    </td>
                    <td className="text-right">
                      <button
                        onClick={() => handleRevoke(s.id)}
                        className="px-3 py-1 bg-red-950 hover:bg-red-900 text-red-300 border border-red-500/40 rounded text-xs font-semibold flex items-center gap-1 ml-auto"
                      >
                        <XCircle className="w-3.5 h-3.5" /> Revoke
                      </button>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan="6" className="text-center py-12 text-slate-500 text-xs">
                    No active sessions recorded.
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
