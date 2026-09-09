import React, { useEffect, useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { useApp } from '../context/AppContext';
import { fileApi } from '../api/fileApi';
import { 
  Trash2, RotateCcw, XCircle, RefreshCw, FileText, AlertTriangle, ShieldCheck
} from 'lucide-react';

export function RecycleBin() {
  const { refreshUser } = useAuth();
  const { showToast } = useApp();
  const [deletedFiles, setDeletedFiles] = useState([]);
  const [loading, setLoading] = useState(true);

  const loadRecycleBin = async () => {
    setLoading(true);
    try {
      const data = await fileApi.listRecycleBin();
      setDeletedFiles(Array.isArray(data) ? data : (data.files || []));
    } catch (err) {
      showToast(err.message || 'Failed to load recycle bin.', 'error');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadRecycleBin();
  }, []);

  const handleRestore = async (fileId, filename) => {
    try {
      await fileApi.restoreFile(fileId);
      showToast(`"${filename}" restored to your active workspace!`, 'success');
      loadRecycleBin();
      refreshUser();
    } catch (err) {
      showToast(err.message || 'Failed to restore file.', 'error');
    }
  };

  const handlePermanentDelete = async (fileId, filename) => {
    if (!window.confirm(`Permanently purge "${filename}"? This action cannot be undone.`)) return;
    try {
      await fileApi.permanentDelete(fileId);
      showToast(`"${filename}" permanently purged from storage.`, 'info');
      loadRecycleBin();
      refreshUser();
    } catch (err) {
      showToast(err.message || 'Failed to permanently purge file.', 'error');
    }
  };

  const handleAttemptView = () => {
    showToast('Files in the Recycle Bin cannot be opened directly. Restore the file first.', 'warning');
  };

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-6">
      {/* Header Banner */}
      <div className="glass-card p-6 border border-red-500/40 bg-gradient-to-r from-slate-900 via-red-950/20 to-slate-900 shadow-2xl">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="p-3 rounded-xl bg-red-950/90 border border-red-500/50 text-red-400">
              <Trash2 className="w-8 h-8" />
            </div>
            <div>
              <h1 className="text-xl font-black text-white tracking-wide flex items-center gap-2">
                Secure Recycle Bin
                <span className="px-2 py-0.5 bg-red-950 border border-red-500/50 text-red-300 text-[10px] rounded font-mono">
                  ISOLATED STAGING
                </span>
              </h1>
              <p className="text-xs text-slate-400 mt-1">
                Soft-deleted files reside here in an isolated state. Files cannot be executed or opened until restored.
              </p>
            </div>
          </div>
          <button
            onClick={loadRecycleBin}
            className="p-2 bg-slate-900 hover:bg-slate-800 text-slate-300 hover:text-white border border-slate-800 rounded-lg text-xs flex items-center gap-1.5 transition"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} /> Refresh Bin
          </button>
        </div>
      </div>

      {/* Deleted Files Table */}
      <div className="glass-card overflow-hidden border border-slate-800 shadow-2xl">
        <div className="overflow-x-auto">
          <table className="soc-table">
            <thead>
              <tr>
                <th>Deleted File</th>
                <th>File Size</th>
                <th>Deleted Date</th>
                <th>Storage Status</th>
                <th className="text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr>
                  <td colSpan="5" className="text-center py-16 text-slate-400 font-mono text-xs">
                    <RefreshCw className="w-5 h-5 animate-spin mx-auto mb-2 text-red-400" />
                    QUERYING ISOLATED RECYCLE STAGE...
                  </td>
                </tr>
              ) : deletedFiles.length > 0 ? (
                deletedFiles.map((file) => {
                  const targetId = file.file_id || file.id;
                  const displayName = file.original_name || file.filename || 'Deleted File';
                  const sizeDisplay = file.file_size_formatted || file.size_formatted || `${Math.round((file.file_size || file.size_bytes || 0) / 1024)} KB`;
                  const dateDisplay = file.deleted_at_ist || file.deleted_at || file.updated_at || 'Recently (IST)';

                  return (
                    <tr key={String(file.id || targetId)}>
                      <td>
                        <div className="flex items-center gap-2.5">
                          <div className="p-2 rounded-lg bg-slate-900 border border-slate-800 text-red-400 shrink-0">
                            <FileText className="w-4 h-4" />
                          </div>
                          <div>
                            <div 
                              className="font-bold text-white text-xs sm:text-sm hover:text-red-400 cursor-pointer"
                              onClick={handleAttemptView}
                              title="Click to view"
                            >
                              {displayName}
                            </div>
                            <div className="text-[10px] text-slate-500 font-mono">
                              ID: {String(targetId || '').substring(0, 16)}...
                            </div>
                          </div>
                        </div>
                      </td>
                      <td className="font-mono text-xs text-slate-300">
                        {sizeDisplay}
                      </td>
                      <td className="font-mono text-xs text-slate-400">
                        {dateDisplay}
                      </td>
                      <td>
                        <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-semibold bg-red-950/80 text-red-300 border border-red-500/40">
                          <Trash2 className="w-3 h-3" />
                          <span>STAGED IN BIN</span>
                        </span>
                      </td>
                      <td className="text-right">
                        <div className="flex items-center justify-end gap-2">
                          <button
                            onClick={() => handleRestore(targetId, displayName)}
                            className="px-3 py-1.5 bg-emerald-950 hover:bg-emerald-900 text-emerald-300 border border-emerald-500/40 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition shadow"
                          >
                            <RotateCcw className="w-3.5 h-3.5" /> Restore
                          </button>
                          <button
                            onClick={() => handlePermanentDelete(targetId, displayName)}
                            className="px-3 py-1.5 bg-red-950 hover:bg-red-900 text-red-300 border border-red-500/40 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition shadow"
                          >
                            <XCircle className="w-3.5 h-3.5" /> Purge
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })
              ) : (
                <tr>
                  <td colSpan="5" className="text-center py-14 text-slate-500 text-xs">
                    <Trash2 className="w-8 h-8 mx-auto mb-2 opacity-40 text-slate-400" />
                    Recycle bin is completely empty. No files currently staged for deletion.
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
