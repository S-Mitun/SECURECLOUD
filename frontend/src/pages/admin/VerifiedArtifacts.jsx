import React, { useEffect, useState } from 'react';
import { adminApi } from '../../api/adminApi';
import { useApp } from '../../context/AppContext';
import { ShieldCheck, RefreshCw, XCircle, Search, FileText, CheckCircle2, ShieldAlert, Key } from 'lucide-react';

export function VerifiedArtifacts() {
  const { showToast } = useApp();
  const [artifacts, setArtifacts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');

  const loadArtifacts = async () => {
    setLoading(true);
    try {
      const data = await adminApi.listVerifiedArtifacts();
      setArtifacts(Array.isArray(data) ? data : []);
    } catch (err) {
      showToast(err.message || 'Failed to load verified artifact trust registry.', 'error');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadArtifacts();
    const handleUpdate = () => loadArtifacts();
    window.addEventListener('files:updated', handleUpdate);
    return () => window.removeEventListener('files:updated', handleUpdate);
  }, []);

  const handleRevoke = async (a) => {
    if (!window.confirm(`Revoke verified clean trust status for "${a.filename}" (SHA-256: ${a.sha256.substring(0, 16)}...)? Future uploads of this file will require fresh scanning.`)) {
      return;
    }

    try {
      await adminApi.revokeVerifiedArtifact(a.artifact_id || a.sha256);
      showToast(`Trust status for "${a.filename}" revoked.`, 'info');
      loadArtifacts();
      window.dispatchEvent(new CustomEvent('files:updated'));
    } catch (err) {
      showToast(err.message || 'Failed to revoke trust.', 'error');
    }
  };

  const filtered = artifacts.filter((a) =>
    (a.filename || '').toLowerCase().includes(search.toLowerCase()) ||
    (a.sha256 || '').toLowerCase().includes(search.toLowerCase()) ||
    (a.verified_by || '').toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-6">
      {/* Header Banner */}
      <div className="glass-card p-6 border border-emerald-500/40 bg-gradient-to-r from-slate-900 via-emerald-950/20 to-slate-900 shadow-2xl flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="p-3 rounded-xl bg-emerald-950/90 border border-emerald-500/50 text-emerald-400">
            <ShieldCheck className="w-8 h-8" />
          </div>
          <div>
            <h1 className="text-xl font-black text-white tracking-wide flex items-center gap-2">
              Server Verified-Clean Trust Registry
              <span className="px-2 py-0.5 bg-emerald-950 border border-emerald-500/40 text-emerald-300 text-[10px] rounded font-mono">
                SHA-256 IDENTITY
              </span>
            </h1>
            <p className="text-xs text-slate-400 mt-1">
              Permanent server-side trusted artifact registry. Files matching these exact cryptographic hashes are instantly recognized across all sessions and restarts.
            </p>
          </div>
        </div>
        <button
          onClick={loadArtifacts}
          className="p-2 bg-slate-900 hover:bg-slate-800 text-slate-300 hover:text-white border border-slate-800 rounded-lg text-xs flex items-center gap-1.5 transition"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} /> Refresh Registry
        </button>
      </div>

      {/* Search Bar */}
      <div className="glass-card p-4">
        <div className="relative">
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search by filename, exact SHA-256 hash, or verifying admin..."
            className="w-full bg-slate-900 border border-slate-700 rounded-lg pl-9 pr-3.5 py-2 text-xs text-white focus:outline-none focus:border-emerald-500"
          />
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
        </div>
      </div>

      {/* Table */}
      <div className="glass-card overflow-hidden border border-slate-800 shadow-2xl">
        <div className="overflow-x-auto">
          <table className="soc-table">
            <thead>
              <tr>
                <th>Artifact Filename</th>
                <th>Cryptographic SHA-256 Hash</th>
                <th>Size</th>
                <th>Trust Status</th>
                <th>Verified By</th>
                <th>Verification Date</th>
                <th className="text-right">Action</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr>
                  <td colSpan="7" className="text-center py-16 text-slate-400 font-mono text-xs">
                    <RefreshCw className="w-5 h-5 animate-spin mx-auto mb-2 text-emerald-400" />
                    AUDITING TRUSTED ARTIFACT REGISTRY...
                  </td>
                </tr>
              ) : filtered.length > 0 ? (
                filtered.map((a) => {
                  const isRevoked = a.status === 'REVOKED';

                  return (
                    <tr key={a.id}>
                      <td>
                        <div className="flex items-center gap-2.5">
                          <div className={`p-2 rounded-lg border shrink-0 ${
                            isRevoked
                              ? 'bg-slate-900 border-slate-800 text-slate-500'
                              : 'bg-emerald-950/80 border-emerald-500/40 text-emerald-400'
                          }`}>
                            <FileText className="w-4 h-4" />
                          </div>
                          <div>
                            <div className="font-bold text-white text-xs sm:text-sm">
                              {a.original_filename || a.filename || a.artifact_id || 'Verified File'}
                            </div>
                            <div className="text-[10px] text-slate-500 font-mono">
                              ID: {a.artifact_id || 'ART-TRUST'} • Scope: {a.scope || 'GLOBAL'}
                            </div>
                          </div>
                        </div>
                      </td>
                      <td className="font-mono text-xs text-emerald-400 font-semibold">
                        <span title={a.sha256}>{(a.sha256 || '').substring(0, 20)}...</span>
                      </td>
                      <td className="font-mono text-xs text-slate-300">
                        {a.file_size_formatted || 'File'}
                      </td>
                      <td>
                        <span className={`inline-flex items-center gap-1 px-2.5 py-0.5 rounded text-[10px] font-bold font-mono tracking-wider uppercase border ${
                          isRevoked
                            ? 'bg-red-950/80 text-red-400 border-red-500/40'
                            : 'bg-emerald-950/90 text-emerald-300 border-emerald-500/50 shadow-sm'
                        }`}>
                          <ShieldCheck className="w-3 h-3 text-emerald-400" />
                          {isRevoked ? 'REVOKED' : 'VERIFIED CLEAN'}
                        </span>
                      </td>
                      <td className="font-mono text-xs text-slate-300">
                        {a.verified_by_username || a.verified_by || 'Admin'}
                      </td>
                      <td className="font-mono text-xs text-slate-400">
                        {a.verified_at || 'Recent (IST)'}
                      </td>
                      <td className="text-right">
                        {!isRevoked && (
                          <button
                            onClick={() => handleRevoke(a)}
                            className="px-2.5 py-1.5 bg-red-950 hover:bg-red-900 text-red-300 border border-red-500/40 rounded-lg text-xs font-semibold flex items-center gap-1 ml-auto transition"
                          >
                            <XCircle className="w-3.5 h-3.5" /> Revoke Trust
                          </button>
                        )}
                      </td>
                    </tr>
                  );
                })
              ) : (
                <tr>
                  <td colSpan="7" className="text-center py-14 text-slate-500 text-xs">
                    <CheckCircle2 className="w-8 h-8 text-emerald-400 mx-auto mb-2 opacity-80" />
                    No verified-clean artifacts registered yet. When an Admin verifies a file or false positive, it will be permanently cataloged here.
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
