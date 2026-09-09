import React, { useEffect, useState } from 'react';
import { adminApi } from '../../api/adminApi';
import { useApp } from '../../context/AppContext';
import { Files, RefreshCw, Eye, History, Cpu, FileText, Search, Lock } from 'lucide-react';
import { SecurityBadge } from '../../components/SecurityBadge';
import { FileViewerModal } from '../../components/FileViewerModal';
import { ScanHistoryModal } from '../../components/ScanHistoryModal';
import { SecurityDetailsModal } from '../../components/SecurityDetailsModal';

export function AllFiles() {
  const { openModal, showToast } = useApp();
  const [files, setFiles] = useState([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');

  const loadAllFiles = async () => {
    setLoading(true);
    try {
      const data = await adminApi.listAllFiles();
      setFiles(Array.isArray(data) ? data : (data.files || []));
    } catch (err) {
      showToast(err.message || 'Failed to load platform files.', 'error');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAllFiles();
  }, []);

  const filtered = files.filter((f) =>
    (f.filename || '').toLowerCase().includes(search.toLowerCase()) ||
    (f.owner_email && f.owner_email.toLowerCase().includes(search.toLowerCase())) ||
    (f.mime_type && f.mime_type.toLowerCase().includes(search.toLowerCase()))
  );

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-6">
      {/* Header Banner */}
      <div className="glass-card p-6 border border-sky-500/40 bg-gradient-to-r from-slate-900 via-sky-950/20 to-slate-900 shadow-2xl flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="p-3 rounded-xl bg-sky-950/90 border border-sky-500/50 text-sky-400">
            <Files className="w-8 h-8" />
          </div>
          <div>
            <h1 className="text-xl font-black text-white tracking-wide flex items-center gap-2">
              Global Platform File Inventory
              <span className="px-2 py-0.5 bg-sky-950 border border-sky-500/40 text-sky-300 text-[10px] rounded font-mono">
                CENTRAL REGISTRY
              </span>
            </h1>
            <p className="text-xs text-slate-400 mt-1">
              Centralized security audit and compliance indexing of all platform files across user workspaces.
            </p>
          </div>
        </div>
        <button
          onClick={loadAllFiles}
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
            placeholder="Search by filename, owner identity, or file extension..."
            className="w-full bg-slate-900 border border-slate-700 rounded-lg pl-9 pr-3.5 py-2 text-xs text-white focus:outline-none focus:border-sky-500"
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
                <th>Filename & Storage Tier</th>
                <th>Owner Identity</th>
                <th>Size</th>
                <th>Security Scan Status</th>
                <th>Uploaded</th>
                <th className="text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr>
                  <td colSpan="6" className="text-center py-16 text-slate-400 font-mono text-xs">
                    <RefreshCw className="w-5 h-5 animate-spin mx-auto mb-2 text-sky-400" />
                    INDEXING PLATFORM STORAGE CATALOG...
                  </td>
                </tr>
              ) : filtered.length > 0 ? (
                filtered.map((file) => {
                  const sizeDisplay = file.file_size_formatted || file.size_formatted || `${Math.round((file.file_size || file.size_bytes || 0) / 1024)} KB`;
                  const ext = (file.filename?.substring(file.filename.lastIndexOf('.')) || '').toLowerCase();
                  const isConfidential = Boolean(file.is_confidential);

                  return (
                    <tr key={file.id}>
                      <td>
                        <div className="flex items-center gap-2.5">
                          <div className={`p-2 rounded-lg border shrink-0 ${
                            isConfidential
                              ? 'bg-amber-950/80 border-amber-500/40 text-amber-400'
                              : 'bg-slate-900 border-slate-800 text-sky-400'
                          }`}>
                            {isConfidential ? <Lock className="w-4 h-4" /> : <FileText className="w-4 h-4" />}
                          </div>
                          <div>
                            <div className="font-bold text-white text-xs sm:text-sm">
                              {file.filename}
                            </div>
                            <div className="flex items-center gap-1.5 text-[10px] font-mono mt-0.5">
                              <span className="text-slate-400 uppercase">{ext.replace('.', '') || file.mime_type || 'FILE'}</span>
                              <span>•</span>
                              {isConfidential ? (
                                <span className="text-amber-400 font-semibold flex items-center gap-0.5">
                                  <Lock className="w-2.5 h-2.5" /> Confidential Vault
                                </span>
                              ) : (
                                <span className="text-slate-500">Standard Storage</span>
                              )}
                            </div>
                          </div>
                        </div>
                      </td>
                      <td className="font-mono text-xs text-slate-300">
                        {file.owner_email || file.owner?.email || `User #${file.owner_id || file.user_id || 'Me'}`}
                      </td>
                      <td className="font-mono text-xs text-slate-300">
                        {sizeDisplay}
                      </td>
                      <td>
                        <SecurityBadge status={file.security_status} score={file.threat_score} />
                      </td>
                      <td className="font-mono text-xs text-slate-400">
                        {file.created_at || file.uploaded_at || 'Recent'}
                      </td>
                      <td className="text-right">
                        <div className="flex items-center justify-end gap-1.5">
                          {/* Preview Button */}
                          <button
                            onClick={() => openModal('fileViewer', file)}
                            className="p-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white border border-slate-700 rounded-lg text-xs transition"
                            title="Preview Original Format"
                          >
                            <Eye className="w-3.5 h-3.5" />
                          </button>

                          {/* Scan History Button */}
                          <button
                            onClick={() => openModal('scanHistory', file)}
                            className="p-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white border border-slate-700 rounded-lg text-xs transition"
                            title="Scan History"
                          >
                            <History className="w-3.5 h-3.5" />
                          </button>

                          {/* Security Breakdown Button */}
                          <button
                            onClick={() => openModal('securityDetails', file)}
                            className="p-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-sky-400 border border-slate-700 rounded-lg text-xs transition"
                            title="ML Security Details"
                          >
                            <Cpu className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })
              ) : (
                <tr>
                  <td colSpan="6" className="text-center py-12 text-slate-500 text-xs">
                    No files found matching your search.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      <FileViewerModal />
      <ScanHistoryModal />
      <SecurityDetailsModal onUpdate={loadAllFiles} />
    </div>
  );
}
