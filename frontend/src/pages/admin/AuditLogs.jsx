import React, { useEffect, useState } from 'react';
import { adminApi } from '../../api/adminApi';
import { useApp } from '../../context/AppContext';
import { List, RefreshCw, Filter, Search } from 'lucide-react';

export function AuditLogs() {
  const { showToast } = useApp();
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filterAction, setFilterAction] = useState('');
  const [search, setSearch] = useState('');

  const loadAuditLogs = async () => {
    setLoading(true);
    try {
      const data = await adminApi.listAuditLogs(100, filterAction);
      setLogs(Array.isArray(data) ? data : (data.logs || []));
    } catch (err) {
      showToast(err.message || 'Failed to load audit logs.', 'error');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAuditLogs();
  }, [filterAction]);

  const filtered = logs.filter((l) =>
    (l.action || '').toLowerCase().includes(search.toLowerCase()) ||
    (l.details || '').toLowerCase().includes(search.toLowerCase()) ||
    (l.user_email || '').toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-6">
      {/* Header Banner */}
      <div className="glass-card p-6 border border-slate-700 bg-gradient-to-r from-slate-900 via-slate-800 to-slate-900 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="p-3 rounded-xl bg-slate-900 border border-slate-700 text-sky-400">
            <List className="w-8 h-8" />
          </div>
          <div>
            <h1 className="text-xl font-black text-white tracking-wide">
              Immutable SOC Audit Trail & Forensic Log
            </h1>
            <p className="text-xs text-slate-400 mt-1">
              Append-only compliance log recording authentication attempts, file operations, and ML threat detections.
            </p>
          </div>
        </div>
        <button
          onClick={loadAuditLogs}
          className="p-2 bg-slate-900 hover:bg-slate-800 text-slate-400 hover:text-white border border-slate-800 rounded-lg text-xs flex items-center gap-1.5"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} /> Refresh Trail
        </button>
      </div>

      {/* Filters */}
      <div className="glass-card p-4 flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <select
            value={filterAction}
            onChange={(e) => setFilterAction(e.target.value)}
            className="bg-slate-900 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-white focus:outline-none focus:border-sky-500"
          >
            <option value="">All Actions</option>
            <option value="LOGIN">LOGIN</option>
            <option value="UPLOAD">UPLOAD</option>
            <option value="THREAT_DETECTED">THREAT_DETECTED</option>
            <option value="CONFIDENTIAL_ENCRYPT">CONFIDENTIAL_ENCRYPT</option>
            <option value="SHARE_CREATED">SHARE_CREATED</option>
            <option value="DELETE">DELETE</option>
          </select>
        </div>

        <div className="relative min-w-[240px]">
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search details or user..."
            className="w-full bg-slate-900 border border-slate-700 rounded-lg pl-9 pr-3.5 py-1.5 text-xs text-white focus:outline-none focus:border-sky-500"
          />
          <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-2.5" />
        </div>
      </div>

      {/* Table */}
      <div className="glass-card overflow-hidden border border-slate-800">
        <div className="overflow-x-auto">
          <table className="soc-table">
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Action</th>
                <th>Actor Identity</th>
                <th>IP Address</th>
                <th>Operation Details</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr>
                  <td colSpan="6" className="text-center py-16 text-slate-400 font-mono text-xs">
                    <RefreshCw className="w-5 h-5 animate-spin mx-auto mb-2 text-sky-400" />
                    STREAMING IMMUTABLE AUDIT RECORDS...
                  </td>
                </tr>
              ) : filtered.length > 0 ? (
                filtered.map((log) => (
                  <tr key={log.id}>
                    <td className="font-mono text-xs text-slate-400">
                      {new Date(log.created_at || log.timestamp).toLocaleString()}
                    </td>
                    <td>
                      <span className="font-mono text-xs font-bold px-2 py-0.5 rounded bg-slate-900 border border-slate-700 text-sky-300">
                        {log.action}
                      </span>
                    </td>
                    <td className="font-mono text-xs text-slate-300">
                      {log.user_email || `User #${log.user_id || 'System'}`}
                    </td>
                    <td className="font-mono text-xs text-slate-400">
                      {log.ip_address || '127.0.0.1'}
                    </td>
                    <td className="text-xs text-slate-300">
                      {log.details || log.description || 'System event processed'}
                    </td>
                    <td>
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold font-mono ${
                          (log.status || 'SUCCESS') === 'SUCCESS'
                            ? 'bg-emerald-950/80 text-emerald-400 border border-emerald-500/40'
                            : 'bg-red-950/80 text-red-400 border border-red-500/40'
                        }`}
                      >
                        {log.status || 'SUCCESS'}
                      </span>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan="6" className="text-center py-12 text-slate-500 text-xs">
                    No matching audit records found.
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
