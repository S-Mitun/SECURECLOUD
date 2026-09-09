import React, { useEffect, useState, useRef } from 'react';
import { adminApi } from '../../api/adminApi';
import { fileApi } from '../../api/fileApi';
import { useApp } from '../../context/AppContext';
import { 
  GitBranch, User, Files, RefreshCw, Eye, EyeOff, ShieldCheck, ShieldAlert, 
  AlertTriangle, History, Cpu, FileText, CheckCircle2, Lock, Unlock, UploadCloud, KeyRound, Sparkles, X, Plus
} from 'lucide-react';
import { SecurityBadge } from '../../components/SecurityBadge';
import { FileViewerModal } from '../../components/FileViewerModal';
import { ScanHistoryModal } from '../../components/ScanHistoryModal';
import { SecurityDetailsModal } from '../../components/SecurityDetailsModal';
import { AdminSecurityConfigModal } from '../../components/AdminSecurityConfigModal';

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
  const [dualAdminModal, setDualAdminModal] = useState(null);
  const [unlockVaultModal, setUnlockVaultModal] = useState(null);
  const [unlockedAdminIds, setUnlockedAdminIds] = useState({});
  const [showConfigModal, setShowConfigModal] = useState(false);
  const [showUnlockPin, setShowUnlockPin] = useState(false);
  const [showDualPin, setShowDualPin] = useState(false);
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

  const handleInitiateScan = (file, userObj) => {
    const savedPin = unlockedAdminIds[userObj ? userObj.user_id : null];
    if (userObj && userObj.is_admin_protected && !savedPin) {
      setDualAdminModal({ file, user: userObj, authCode: '' });
      return;
    }
    handleExecuteScan(file, savedPin || '');
  };

  const handleExecuteScan = async (file, authCode = '') => {
    setActiveScans(prev => ({ ...prev, [file.id]: true }));
    try {
      const scanFn = adminApi.retriggerScan || adminApi.rescanFile || adminApi.scanFile;
      const res = await scanFn(file.id, authCode);
      showToast(`ML Threat Scan for "${file.filename}" completed: ${res.security_status} (${res.threat_score}%)`, 'info');
      if (res.security_status === 'MALICIOUS') {
        triggerCriticalAlert({
          filename: file.filename,
          threat_score: res.threat_score
        });
      }
      loadGroupedFiles();
      setDualAdminModal(null);
    } catch (err) {
      showToast(err.message || 'Threat scan failed.', 'error');
    } finally {
      setActiveScans(prev => ({ ...prev, [file.id]: false }));
    }
  };

  const handleUnlockAdminVault = async (e) => {
    e.preventDefault();
    if (!unlockVaultModal || !unlockVaultModal.authCode) return;
    try {
      const verifyFn = adminApi.verifyAdminAccess || adminApi.unlockAdminVault;
      const res = await verifyFn(unlockVaultModal.user.user_id, unlockVaultModal.authCode);
      showToast(res.message || 'Access granted! Admin vault unlocked.', 'success');
      setUnlockedAdminIds(prev => ({
        ...prev,
        [unlockVaultModal.user.user_id]: unlockVaultModal.authCode
      }));
      setUnlockVaultModal(null);
    } catch (err) {
      showToast(err.message || 'Invalid Admin Configuration Password.', 'error');
    }
  };

  const totalFiles = userGroups.reduce((acc, g) => acc + (g.file_count || g.files?.length || 0), 0);
  const totalMalicious = userGroups.reduce((acc, g) => {
    const mal = (g.files || []).filter(f => f.security_status === 'MALICIOUS').length;
    return acc + mal;
  }, 0);

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-6">
      {/* Header Banner */}
      <div className="glass-card p-6 border border-slate-800 bg-gradient-to-r from-slate-900 via-indigo-950/30 to-slate-900 shadow-2xl">
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="p-3 rounded-xl bg-indigo-950/80 border border-indigo-500/40 text-indigo-400">
              <GitBranch className="w-8 h-8" />
            </div>
            <div>
              <h1 className="text-xl font-black text-white tracking-wide flex items-center gap-2">
                User-Wise File Telemetry & Dual-Admin Control
                <span className="px-2 py-0.5 bg-indigo-950 border border-indigo-500/40 text-indigo-300 text-[10px] rounded font-mono">
                  RBAC Tier-3
                </span>
              </h1>
              <p className="text-xs text-slate-400 mt-1">
                Audited segregation of user repositories, cross-account file inspection, and Dual-Admin authorization gates.
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
              onClick={() => setShowConfigModal(true)}
              className="px-3 py-2 bg-slate-900 hover:bg-slate-800 border border-indigo-500/40 text-indigo-300 rounded-xl text-xs font-bold flex items-center gap-1.5 transition"
              title="Set or update your own Admin Configuration Password"
            >
              <KeyRound className="w-4 h-4 text-indigo-400" />
              <span>Config Password</span>
            </button>

            <button
              onClick={loadGroupedFiles}
              className="p-2 bg-slate-900 hover:bg-slate-800 text-slate-300 hover:text-white border border-slate-800 rounded-xl text-xs flex items-center gap-1.5 transition"
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
            <div className="text-[10px] text-slate-400 uppercase font-mono">Dual-Admin Vaults</div>
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
            const isProtected = group.is_admin_protected;
            const isUnlocked = unlockedAdminIds[group.user_id];
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
                        {isProtected && (
                          <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold flex items-center gap-1 ${
                            isUnlocked 
                              ? 'bg-emerald-950 text-emerald-300 border border-emerald-500/40'
                              : 'bg-amber-950 text-amber-300 border border-amber-500/40'
                          }`}>
                            {isUnlocked ? <Unlock className="w-3 h-3" /> : <Lock className="w-3 h-3" />}
                            <span>{isUnlocked ? 'Dual-Admin Unlocked' : 'Dual-Admin Protected'}</span>
                          </span>
                        )}
                      </div>
                      <div className="text-[10px] text-slate-400 font-mono mt-0.5">
                        {group.email} • ID: {group.user_id}
                      </div>
                    </div>
                  </div>

                  <div className="flex items-center gap-2">
                    {isProtected && !isUnlocked && (
                      <button
                        onClick={() => setUnlockVaultModal({ user: group, authCode: '' })}
                        className="px-3 py-1.5 bg-amber-950/90 hover:bg-amber-900 border border-amber-500/50 text-amber-300 rounded-lg text-xs font-bold flex items-center gap-1.5 transition"
                      >
                        <KeyRound className="w-3.5 h-3.5" /> Unlock Vault
                      </button>
                    )}
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
                        <th>Type</th>
                        <th>Threat Score</th>
                        <th>Verdict</th>
                        <th>Status</th>
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
                                    onClick={() => handleInitiateScan(file, group)}
                                    disabled={isScanning}
                                    title="Retrigger Real-Time LightGBM Inference"
                                    className="px-2 py-1 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white rounded text-xs font-bold flex items-center gap-1 transition"
                                  >
                                    <Cpu className={`w-3.5 h-3.5 ${isScanning ? 'animate-spin' : ''}`} />
                                    <span>{isScanning ? 'Scanning...' : 'Scan'}</span>
                                  </button>

                                  {/* View Content */}
                                  <button
                                    onClick={() => {
                                      if (isProtected && !isUnlocked) {
                                        setUnlockVaultModal({ user: group, authCode: '' });
                                        showToast(`Dual-Admin Authorization Required: Enter "${group.username}"'s Config Password.`, 'warning');
                                        return;
                                      }
                                      openModal('fileViewer', file);
                                    }}
                                    title="View Decrypted Payload"
                                    className="p-1 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded transition"
                                  >
                                    <Eye className="w-3.5 h-3.5" />
                                  </button>

                                  {/* Scan History */}
                                  <button
                                    onClick={() => {
                                      if (isProtected && !isUnlocked) {
                                        setUnlockVaultModal({ user: group, authCode: '' });
                                        showToast(`Dual-Admin Authorization Required: Enter "${group.username}"'s Config Password.`, 'warning');
                                        return;
                                      }
                                      openModal('scanHistory', file);
                                    }}
                                    title="View Scan & Threat Audit History"
                                    className="p-1 bg-slate-800 hover:bg-slate-700 text-sky-400 rounded transition"
                                  >
                                    <History className="w-3.5 h-3.5" />
                                  </button>

                                  {/* Inspect ML Evidence */}
                                  <button
                                    onClick={() => {
                                      if (isProtected && !isUnlocked) {
                                        setUnlockVaultModal({ user: group, authCode: '' });
                                        showToast(`Dual-Admin Authorization Required: Enter "${group.username}"'s Config Password.`, 'warning');
                                        return;
                                      }
                                      openModal('securityDetails', file);
                                    }}
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
                          <td colSpan="7" className="text-center py-6 text-slate-500 text-xs">
                            No files uploaded in this user repository.
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
          <div className="glass-card p-12 text-center text-slate-500 text-xs">
            No active user accounts found in the database.
          </div>
        )}
      </div>

      {/* Unlock Vault Modal */}
      {unlockVaultModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/85 backdrop-blur-sm">
          <div className="glass-card max-w-md w-full p-6 border border-amber-500/40 shadow-2xl relative space-y-4">
            <button
              onClick={() => setUnlockVaultModal(null)}
              className="absolute top-4 right-4 text-slate-400 hover:text-white"
            >
              <X className="w-5 h-5" />
            </button>

            <div className="flex items-center gap-3">
              <div className="p-2.5 rounded-xl bg-amber-950/80 border border-amber-500/40 text-amber-400">
                <Lock className="w-6 h-6" />
              </div>
              <div>
                <h3 className="text-base font-bold text-white">Dual-Admin Authorization Required</h3>
                <p className="text-xs text-slate-400">Vault: {unlockVaultModal.user.username}</p>
              </div>
            </div>

            <p className="text-xs text-slate-300 bg-slate-900/90 p-3 rounded-lg border border-slate-800 leading-relaxed">
              This administrator has configured a secret <strong>Admin Configuration Password</strong>. Enter their config password to decrypt and inspect their files for this session.
            </p>

            <form onSubmit={handleUnlockAdminVault} className="space-y-4">
              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">
                  Admin Configuration Password:
                </label>
                <div className="relative">
                  <input
                    type={showUnlockPin ? "text" : "password"}
                    value={unlockVaultModal.authCode}
                    onChange={(e) => setUnlockVaultModal(prev => ({ ...prev, authCode: e.target.value }))}
                    placeholder="Enter config password..."
                    required
                    autoFocus
                    className="w-full bg-slate-900 border border-slate-700 rounded-lg pl-3 pr-10 py-2 text-xs text-white font-mono focus:outline-none focus:border-amber-500"
                  />
                  <button
                    type="button"
                    onClick={() => setShowUnlockPin(!showUnlockPin)}
                    className="absolute right-2.5 top-2 text-slate-400 hover:text-white"
                    title={showUnlockPin ? "Hide password" : "Show password"}
                  >
                    {showUnlockPin ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
              </div>

              <div className="flex items-center justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setUnlockVaultModal(null)}
                  className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-xs font-bold"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-5 py-2 bg-amber-600 hover:bg-amber-500 text-white rounded-lg text-xs font-bold flex items-center gap-1.5 shadow"
                >
                  <KeyRound className="w-4 h-4" /> Unlock Admin Files
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Dual Admin Modal */}
      {dualAdminModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/85 backdrop-blur-sm">
          <div className="glass-card max-w-md w-full p-6 border border-indigo-500/40 shadow-2xl relative space-y-4">
            <button
              onClick={() => setDualAdminModal(null)}
              className="absolute top-4 right-4 text-slate-400 hover:text-white"
            >
              <X className="w-5 h-5" />
            </button>

            <div className="flex items-center gap-3">
              <div className="p-2.5 rounded-xl bg-indigo-950/80 border border-indigo-500/40 text-indigo-400">
                <KeyRound className="w-6 h-6" />
              </div>
              <div>
                <h3 className="text-base font-bold text-white">Dual-Admin Scan Authorization</h3>
                <p className="text-xs text-slate-400">{dualAdminModal.file.filename}</p>
              </div>
            </div>

            <p className="text-xs text-slate-300 bg-slate-900/90 p-3 rounded-lg border border-slate-800">
              Admin <strong>"{dualAdminModal.user.username}"</strong> has protected their repository with an Admin Config PIN. Enter the PIN to authorize scanning.
            </p>

            <div className="space-y-3">
              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">
                  Enter Admin Security PIN:
                </label>
                <div className="relative">
                  <input
                    type={showDualPin ? "text" : "password"}
                    value={dualAdminModal.authCode}
                    onChange={(e) => setDualAdminModal(prev => ({ ...prev, authCode: e.target.value }))}
                    placeholder="Enter PIN / Password..."
                    className="w-full bg-slate-900 border border-slate-700 rounded-lg pl-3 pr-10 py-2 text-xs text-white font-mono focus:outline-none focus:border-indigo-500"
                  />
                  <button
                    type="button"
                    onClick={() => setShowDualPin(!showDualPin)}
                    className="absolute right-2.5 top-2 text-slate-400 hover:text-white"
                    title={showDualPin ? "Hide password" : "Show password"}
                  >
                    {showDualPin ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
              </div>

              <div className="flex items-center justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setDualAdminModal(null)}
                  className="px-4 py-2 bg-slate-800 text-slate-300 rounded-lg text-xs font-bold"
                >
                  Cancel
                </button>
                <button
                  onClick={() => handleExecuteScan(dualAdminModal.file, dualAdminModal.authCode)}
                  className="px-5 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg text-xs font-bold flex items-center gap-1.5"
                >
                  <Cpu className="w-4 h-4" /> Authorize & Scan
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Admin Config Password Modal */}
      {showConfigModal && (
        <AdminSecurityConfigModal onClose={() => { setShowConfigModal(false); loadGroupedFiles(); }} />
      )}

      <FileViewerModal onUpdate={loadGroupedFiles} />
      <ScanHistoryModal onUpdate={loadGroupedFiles} />
      <SecurityDetailsModal onUpdate={loadGroupedFiles} />
    </div>
  );
}
