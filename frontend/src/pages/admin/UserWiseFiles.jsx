import React, { useEffect, useState, useRef } from 'react';
import { adminApi } from '../../api/adminApi';
import { fileApi } from '../../api/fileApi';
import { useApp } from '../../context/AppContext';
import { 
  GitBranch, User, RefreshCw, Eye, ShieldAlert, 
  History, Cpu, FileText, UploadCloud
} from 'lucide-react';
import { SecurityBadge } from '../../components/SecurityBadge';
import { FileViewerModal } from '../../components/FileViewerModal';
import { ScanHistoryModal } from '../../components/ScanHistoryModal';
import { SecurityDetailsModal } from '../../components/SecurityDetailsModal';

function formatBytes(bytes) {
  if (!bytes || bytes === 0) return '0 B';
  if (bytes >= 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
  if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(2)} KB`;
  return `${bytes} B`;
}

export function UserWiseFiles() {
  const { openModal, showToast, triggerCriticalAlert } = useApp();
  const [userGroups, setUserGroups] = useState([]);
  const [loading, setLoading] = useState(true);
  const [activeScans, setActiveScans] = useState({});
  const [uploading, setUploading] = useState(false);
  const [uploadStage, setUploadStage] = useState('');
  const fileInputRef = useRef(null);

  const loadGroupedFiles = async () => {
    setLoading(true);
    try {
      const data = await adminApi.getUserGroupedFiles();
      setUserGroups(Array.isArray(data) ? data : (data.users || []));
    } catch (err) {
      showToast(err.message || 'Failed to load user-wise files.', 'error');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadGroupedFiles();
    const handleUpdate = () => loadGroupedFiles();
    window.addEventListener('files:updated', handleUpdate);
    return () => window.removeEventListener('files:updated', handleUpdate);
  }, []);

  const handleAdminFileUpload = async (e) => {
    const files = Array.from(e.target.files || []);
    if (files.length === 0) return;

    setUploading(true);
    try {
      for (let i = 0; i < files.length; i++) {
        const file = files[i];
        setUploadStage(`Processing ${file.name} (${i + 1}/${files.length})...`);
        const res = await fileApi.uploadFile(file);

        if (res.scan && res.scan.security_status === 'MALICIOUS') {
          triggerCriticalAlert({
            filename: file.name,
            threat_score: res.scan.threat_score || 85.0
          });
        }
      }
      showToast(`Successfully uploaded & scanned ${files.length} file(s) into Admin Vault!`, 'success');
      loadGroupedFiles();
      window.dispatchEvent(new CustomEvent('files:updated'));
    } catch (err) {
      showToast(err.message || 'Upload failed.', 'error');
    } finally {
      setUploading(false);
      setUploadStage('');
      if (fileInputRef.current) fileInputRef.current.value = '';
    }
  };

  const handleExecuteScan = async (file) => {
    setActiveScans(prev => ({ ...prev, [file.id]: true }));
    try {
      const scanFn = adminApi.retriggerScan || adminApi.rescanFile || adminApi.scanFile;
      const res = await scanFn(file.id);
      showToast(`Scan complete for "${file.filename}": Status is ${res.security_status || 'ANALYZED'} (${res.threat_score || 0}%)`, 'success');
      loadGroupedFiles();
      window.dispatchEvent(new CustomEvent('files:updated'));
    } catch (err) {
      showToast(err.message || 'Threat scan failed.', 'error');
    } finally {
      setActiveScans(prev => ({ ...prev, [file.id]: false }));
    }
  };

  const totalFiles = userGroups.reduce((acc, g) => acc + (g.files ? g.files.length : 0), 0);
  const totalMalicious = userGroups.reduce((acc, g) => {
    const groupMalicious = (g.files || []).filter(f => f.security_status === 'MALICIOUS' || f.threat_score >= 70).length;
    return acc + groupMalicious;
  }, 0);

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-12">
      {/* Header Banner */}
      <div className="glass-card p-6 border border-slate-800 shadow-2xl relative overflow-hidden">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="p-3 rounded-2xl bg-indigo-950/80 border border-indigo-500/40 text-indigo-400">
              <GitBranch className="w-8 h-8" />
            </div>
            <div>
              <h1 className="text-xl font-black text-white tracking-wide flex items-center gap-2">
                User-Wise File Telemetry & Inspection
                <span className="px-2 py-0.5 bg-indigo-950 border border-indigo-500/40 text-indigo-300 text-[10px] rounded font-mono">
                  RBAC Verified
                </span>
              </h1>
              <p className="text-xs text-slate-400 mt-1">
                Audited segregation of user repositories, cross-account file inspection, and centralized threat mitigation.
              </p>
            </div>
          </div>
          
          <div className="flex items-center gap-2">
            <input
              type="file"
              ref={fileInputRef}
              onChange={handleAdminFileUpload}
              multiple
              className="hidden"
            />
            <button
              onClick={() => fileInputRef.current && fileInputRef.current.click()}
              disabled={uploading}
              className="px-4 py-2 bg-gradient-to-r from-sky-600 to-cyan-500 hover:from-sky-500 hover:to-cyan-400 text-white rounded-xl text-xs font-bold flex items-center gap-2 shadow-lg transition"
            >
              {uploading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <UploadCloud className="w-4 h-4" />}
              <span>{uploading ? uploadStage || 'Uploading...' : 'Upload Files for Admin'}</span>
            </button>

            <button
              onClick={loadGroupedFiles}
              className="p-2 bg-slate-900 hover:bg-slate-800 text-slate-300 hover:text-white border border-slate-800 rounded-xl text-xs flex items-center gap-1.5 transition"
              title="Refresh Telemetry"
            >
              <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            </button>
          </div>
        </div>

        {/* Global Stats */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mt-6 pt-6 border-t border-slate-800/80">
          <div>
            <div className="text-[10px] text-slate-400 uppercase font-mono">Total Users Tracked</div>
            <div className="text-xl font-black text-white mt-0.5">{userGroups.length} Accounts</div>
          </div>
          <div>
            <div className="text-[10px] text-slate-400 uppercase font-mono">Total Files Monitored</div>
            <div className="text-xl font-black text-white mt-0.5">{totalFiles} Files</div>
          </div>
          <div>
            <div className="text-[10px] text-slate-400 uppercase font-mono">Malicious Quarantine</div>
            <div className="text-xl font-black text-rose-400 mt-0.5">{totalMalicious} Files</div>
          </div>
          <div>
            <div className="text-[10px] text-slate-400 uppercase font-mono">Admin Enclaves</div>
            <div className="text-xl font-black text-indigo-400 mt-0.5">
              {userGroups.filter(g => g.role === 'ADMIN').length} Active
            </div>
          </div>
        </div>
      </div>

      {/* User Groups List */}
      <div className="space-y-4">
        {loading ? (
          <div className="glass-card p-12 text-center text-slate-400 font-mono text-xs">
            <RefreshCw className="w-6 h-6 animate-spin mx-auto mb-2 text-indigo-400" />
            AGGREGATING REPOSITORIES ACROSS ENCLAVES...
          </div>
        ) : userGroups.length > 0 ? (
          userGroups.map((group) => {
            const isAdminGroup = group.role === 'ADMIN';
            const files = group.files || [];

            return (
              <div key={String(group.user_id)} className="glass-card overflow-hidden border border-slate-800 shadow-xl">
                {/* User Header */}
                <div className="p-4 bg-slate-900/90 border-b border-slate-800 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
                  <div className="flex items-center gap-3">
                    <div className={`p-2 rounded-xl border ${
                      isAdminGroup ? 'bg-indigo-950/80 border-indigo-500/40 text-indigo-400' : 'bg-sky-950/80 border-sky-500/40 text-sky-400'
                    }`}>
                      <User className="w-5 h-5" />
                    </div>
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-black text-white text-sm tracking-wide">{group.username}</span>
                        <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase ${
                          isAdminGroup ? 'bg-indigo-950 text-indigo-300 border border-indigo-500/40' : 'bg-slate-800 text-slate-300'
                        }`}>
                          {group.role}
                        </span>
                      </div>
                      <div className="text-[10px] text-slate-400 font-mono mt-0.5">
                        {group.email} • ID: {group.user_id}
                      </div>
                    </div>
                  </div>

                  <div className="flex items-center gap-2">
                    {(() => {
                      const grpBytes = files.reduce((acc, f) => acc + (f.file_size || 0), 0);
                      const displayStorage = (grpBytes > 0 ? formatBytes(grpBytes) : (group.storage_used_formatted || group.used_quota_formatted || '0 B'));
                      return (
                        <span className="text-xs font-mono text-slate-400 bg-slate-950 px-3 py-1.5 rounded-lg border border-slate-800">
                          {files.length} File(s) • {displayStorage}
                        </span>
                      );
                    })()}
                  </div>
                </div>

                {/* User Files Table */}
                <div className="overflow-x-auto">
                  <table className="soc-table">
                    <thead>
                      <tr>
                        <th>File Name</th>
                        <th>Size</th>
                        <th>Format</th>
                        <th>Threat Score</th>
                        <th>Status</th>
                        <th>State</th>
                        <th className="text-right">Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {files.length > 0 ? (
                        files.map((file) => {
                          const isScanning = activeScans[file.id];
                          return (
                            <tr key={String(file.id)}>
                              <td>
                                <div className="flex items-center gap-2">
                                  <FileText className="w-4 h-4 text-sky-400 shrink-0" />
                                  <span className="font-bold text-white text-xs truncate max-w-[200px]" title={file.filename}>
                                    {file.filename}
                                  </span>
                                </div>
                              </td>
                              <td className="font-mono text-xs text-slate-300">
                                {file.file_size_formatted || `${Math.round((file.file_size || 0) / 1024)} KB`}
                              </td>
                              <td className="font-mono text-xs text-slate-400 uppercase">
                                {file.extension || 'FILE'}
                              </td>
                              <td className="font-mono font-bold text-xs">
                                <span className={file.threat_score >= 70 ? 'text-rose-400' : file.threat_score >= 40 ? 'text-amber-400' : 'text-emerald-400'}>
                                  {file.threat_score}%
                                </span>
                              </td>
                              <td>
                                <SecurityBadge status={file.security_status} score={file.threat_score} />
                              </td>
                              <td>
                                <span className={`px-2 py-0.5 rounded-full text-[10px] font-semibold border ${
                                  file.is_in_recycle_bin ? 'bg-rose-950 text-rose-300 border-rose-500/40' :
                                  file.is_confidential ? 'bg-amber-950 text-amber-300 border-amber-500/40' :
                                  'bg-emerald-950 text-emerald-300 border-emerald-500/40'
                                }`}>
                                  {file.is_in_recycle_bin ? 'RECYCLED' : file.is_confidential ? 'CONFIDENTIAL' : 'ACTIVE'}
                                </span>
                              </td>
                              <td className="text-right">
                                <div className="flex items-center justify-end gap-1">
                                  {/* Trigger ML Threat Scan */}
                                  <button
                                    onClick={() => handleExecuteScan(file)}
                                    disabled={isScanning}
                                    title="Retrigger Real-Time LightGBM Inference"
                                    className="px-2 py-1 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white rounded text-xs font-bold flex items-center gap-1 transition"
                                  >
                                    <Cpu className={`w-3.5 h-3.5 ${isScanning ? 'animate-spin' : ''}`} />
                                    <span>{isScanning ? 'Scanning...' : 'Scan'}</span>
                                  </button>

                                  {/* View Content */}
                                  <button
                                    onClick={() => openModal('fileViewer', file)}
                                    title="View File Content"
                                    className="p-1 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded transition"
                                  >
                                    <Eye className="w-3.5 h-3.5" />
                                  </button>

                                  {/* Scan History */}
                                  <button
                                    onClick={() => openModal('scanHistory', file)}
                                    title="View Scan & Threat Audit History"
                                    className="p-1 bg-slate-800 hover:bg-slate-700 text-sky-400 rounded transition"
                                  >
                                    <History className="w-3.5 h-3.5" />
                                  </button>

                                  {/* Inspect ML Evidence */}
                                  <button
                                    onClick={() => openModal('securityDetails', file)}
                                    title="Inspect Threat Vector & Heuristics"
                                    className="p-1 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded transition"
                                  >
                                    <ShieldAlert className="w-3.5 h-3.5" />
                                  </button>
                                </div>
                              </td>
                            </tr>
                          );
                        })
                      ) : (
                        <tr>
                          <td colSpan="7" className="text-center py-6 text-xs text-slate-500 font-mono">
                            NO FILES STORED IN THIS ENCLAVE
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            );
          })
        ) : (
          <div className="glass-card p-12 text-center text-slate-400 font-mono text-xs">
            NO USER ENCLAVES REGISTERED
          </div>
        )}
      </div>

      <FileViewerModal onUpdate={loadGroupedFiles} />
      <ScanHistoryModal onUpdate={loadGroupedFiles} />
      <SecurityDetailsModal onUpdate={loadGroupedFiles} />
    </div>
  );
}
