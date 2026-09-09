import React, { useEffect, useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { useApp } from '../context/AppContext';
import { adminApi } from '../api/adminApi';
import { Clock, Shield, RefreshCw, FileText, Lock, Share2, Key } from 'lucide-react';

export function UserActivity() {
  const { user } = useAuth();
  const { showToast } = useApp();
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);

  const loadActivity = async () => {
    setLoading(true);
    try {
      if (user?.id) {
        const data = await adminApi.getUserTimeline(user.id);
        setLogs(Array.isArray(data) ? data : (data.timeline || []));
      }
    } catch (err) {
      showToast(err.message || 'Failed to load activity logs.', 'error');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadActivity();
  }, [user]);

  const formatTimestamp = (log) => {
    if (log.date && log.time) {
      return `${log.date} • ${log.time} IST`;
    }
    if (log.timestamp) {
      return log.timestamp.includes('IST') ? log.timestamp : `${log.timestamp} IST`;
    }
    if (log.created_at) {
      return log.created_at.includes('IST') ? log.created_at : `${log.created_at} IST`;
    }
    return 'Recent Activity (IST)';
  };

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-6">
      <div className="glass-card p-6 border border-slate-800 flex items-center justify-between shadow-2xl">
        <div className="flex items-center gap-3">
          <div className="p-3 rounded-xl bg-slate-900 border border-slate-800 text-sky-400">
            <Clock className="w-8 h-8" />
          </div>
          <div>
            <h1 className="text-xl font-black text-white tracking-wide">Account Activity History</h1>
            <p className="text-xs text-slate-400 mt-1">Audit log of your authentication events, file uploads, and shares.</p>
          </div>
        </div>
        <button
          onClick={loadActivity}
          className="p-2 bg-slate-900 hover:bg-slate-800 text-slate-300 hover:text-white border border-slate-800 rounded-lg text-xs flex items-center gap-1.5 transition"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} /> Refresh
        </button>
      </div>

      <div className="glass-card p-6 border border-slate-800 shadow-2xl">
        {loading ? (
          <div className="py-12 text-center text-slate-400 text-xs font-mono">
            <RefreshCw className="w-6 h-6 animate-spin mx-auto mb-2 text-sky-400" />
            LOADING AUDIT EVENTS...
          </div>
        ) : logs.length > 0 ? (
          <div className="space-y-4 relative before:absolute before:left-4 before:top-2 before:bottom-2 before:w-0.5 before:bg-slate-800">
            {logs.map((log, idx) => (
              <div key={idx} className="flex items-start gap-4 relative pl-1">
                <div className="w-7 h-7 rounded-full bg-slate-900 border border-sky-500/50 flex items-center justify-center text-sky-400 shrink-0 z-10">
                  <Shield className="w-3.5 h-3.5" />
                </div>
                <div className="flex-1 bg-slate-900/80 p-3.5 rounded-xl border border-slate-800">
                  <div className="flex items-center justify-between mb-1">
                    <span className="font-bold text-white text-xs uppercase tracking-wider">{log.action}</span>
                    <span className="font-mono text-[10px] text-sky-400">
                      {formatTimestamp(log)}
                    </span>
                  </div>
                  <p className="text-xs text-slate-300">{log.details || log.description || 'System operation executed.'}</p>
                  <div className="mt-1.5 text-[10px] text-slate-500 font-mono">
                    {log.resource && <span>Resource: {log.resource} • </span>}
                    <span>Result: <strong className="text-emerald-400">{log.result || log.status || 'SUCCESS'}</strong></span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="text-center py-12 text-slate-500 text-xs">
            No activity recorded for this account yet.
          </div>
        )}
      </div>
    </div>
  );
}
