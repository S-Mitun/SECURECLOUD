import React, { useEffect, useState } from 'react';
import { useApp } from '../context/AppContext';
import { useAuth } from '../context/AuthContext';
import { fileApi } from '../api/fileApi';
import { 
  Lock, KeyRound, Eye, ShieldCheck, RefreshCw, Shield, AlertTriangle, Key,
  Download, Share2, Edit2, Trash2, Clock, ShieldAlert
} from 'lucide-react';
import { PinUnlockModal } from '../components/PinUnlockModal';
import { FileViewerModal } from '../components/FileViewerModal';
import { RenameModal } from '../components/RenameModal';
import { ShareCreateModal } from '../components/ShareCreateModal';
import { LockoutCountdown, parseTargetTime } from '../components/LockoutCountdown';

export function ConfidentialVault() {
  const { openModal, showToast } = useApp();
  const { refreshUser } = useAuth();
  const [vaultFiles, setVaultFiles] = useState([]);
  const [loading, setLoading] = useState(true);

  const loadVault = async () => {
    setLoading(true);
    try {
      const data = await fileApi.listConfidential();
      setVaultFiles(Array.isArray(data) ? data : (data.files || []));
    } catch (err) {
      showToast(err.message || 'Failed to load confidential vault.', 'error');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadVault();
  }, []);

  const handleDelete = async (fileId, filename) => {
    if (!window.confirm(`Move "${filename}" to Recycle Bin?`)) return;
    try {
      await fileApi.deleteFile(fileId);
      showToast(`"${filename}" moved to Recycle Bin.`, 'info');
      loadVault();
      refreshUser();
    } catch (err) {
      showToast(err.message || 'Failed to delete file.', 'error');
    }
  };

  // Check if file is currently locked
  const isFileLocked = (file) => {
    if (file.is_permanently_locked) return true;
    if (!file.locked_until) return false;
    const targetMs = parseTargetTime(file.locked_until);
    if (!targetMs) return false;
    return targetMs > Date.now();
  };

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-6">
      {/* Header Banner */}
      <div className="glass-card p-6 border border-amber-500/40 bg-gradient-to-r from-slate-900 via-amber-950/20 to-slate-900 shadow-2xl">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="p-3 rounded-xl bg-amber-950/90 border border-amber-500/50 text-amber-400">
              <Lock className="w-8 h-8" />
            </div>
            <div>
              <h1 className="text-xl font-black text-white tracking-wide flex items-center gap-2">
                Confidential Zero-Knowledge Vault
                <span className="px-2 py-0.5 bg-amber-950 border border-amber-500/50 text-amber-300 text-[10px] rounded font-mono">
                  AES-256-GCM
                </span>
              </h1>
              <p className="text-xs text-slate-400 mt-1">
                Files stored here are client/PIN encrypted. System administrators cannot access or decrypt raw content without your secret PIN.
              </p>
            </div>
          </div>
          <button
            onClick={loadVault}
            className="p-2 bg-slate-900 hover:bg-slate-800 text-slate-300 hover:text-white border border-slate-800 rounded-lg text-xs flex items-center gap-1.5 transition"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} /> Refresh Vault
          </button>
        </div>
      </div>

      {/* Vault Files Table */}
      <div className="glass-card overflow-hidden border border-slate-800 shadow-2xl">
        <div className="overflow-x-auto">
          <table className="soc-table">
            <thead>
              <tr>
                <th>Confidential File</th>
                <th>File Size</th>
                <th>Encryption Standard</th>
                <th>Vault Status & Countdown</th>
                <th>Encrypted Date (IST)</th>
                <th className="text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr>
                  <td colSpan="6" className="text-center py-16 text-slate-400 font-mono text-xs">
                    <RefreshCw className="w-5 h-5 animate-spin mx-auto mb-2 text-amber-400" />
                    DECRYPTING VAULT CATALOG HEADERS...
                  </td>
                </tr>
              ) : vaultFiles.length > 0 ? (
                vaultFiles.map((file) => {
                  const displayName = file.filename || file.original_filename || 'Confidential File';
                  const sizeDisplay = file.file_size_formatted || file.size_formatted || `${Math.round((file.file_size || 0) / 1024)} KB`;
                  const rawDate = file.encrypted_at || file.locked_at || file.created_at;
                  const dateDisplay = rawDate ? (rawDate.includes('IST') ? rawDate : `${rawDate} IST`) : 'Recently';
                  const locked = isFileLocked(file);

                  return (
                    <tr key={String(file.id)} className={locked ? 'bg-amber-950/10' : ''}>
                      <td>
                        <div className="flex items-center gap-2.5">
                          <div className={`p-2 rounded-lg border shrink-0 ${
                            file.is_permanently_locked 
                              ? 'bg-rose-950/70 border-rose-500/40 text-rose-400' 
                              : locked 
                              ? 'bg-amber-950/70 border-amber-500/40 text-amber-400'
                              : 'bg-amber-950/40 border-amber-500/30 text-amber-400'
                          }`}>
                            {file.is_permanently_locked ? <ShieldAlert className="w-4 h-4" /> : <KeyRound className="w-4 h-4" />}
                          </div>
                          <div>
                            <div 
                              className={`font-bold text-xs sm:text-sm cursor-pointer transition ${
                                file.is_permanently_locked ? 'text-rose-300 hover:text-rose-200' : 'text-white hover:text-amber-300'
                              }`}
                              onClick={() => openModal('pinUnlock', { ...file, action: 'view' })}
                              title="Click to unlock & view"
                            >
                              {displayName}
                            </div>
                            <div className="text-[10px] text-slate-500 font-mono flex items-center gap-2 mt-0.5">
                              <span>ID: {String(file.id || '').substring(0, 14)}...</span>
                              {file.failed_attempts > 0 && !file.is_permanently_locked && (
                                <span className="text-amber-400 font-bold">
                                  ({file.failed_attempts} failed {file.failed_attempts === 1 ? 'attempt' : 'attempts'})
                                </span>
                              )}
                            </div>
                          </div>
                        </div>
                      </td>
                      <td className="font-mono text-xs text-slate-300">
                        {sizeDisplay}
                      </td>
                      <td className="font-mono text-xs text-amber-300">
                        AES-256-GCM (PBKDF2)
                      </td>
                      <td>
                        {/* Progressive Lockout Countdown or Status Badge */}
                        {file.is_permanently_locked ? (
                          <LockoutCountdown isPermanentlyLocked={true} compact={true} />
                        ) : file.locked_until && isFileLocked(file) ? (
                          <div className="flex items-center gap-2">
                            <LockoutCountdown 
                              lockedUntil={file.locked_until} 
                              compact={true} 
                              onExpire={loadVault} 
                            />
                            <span className="text-[10px] text-slate-400 font-mono">
                              ({file.lockout_stage === 2 ? '2-Hr Lock' : '30-Min Lock'})
                            </span>
                          </div>
                        ) : (
                          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-emerald-950/60 text-emerald-300 border border-emerald-500/40">
                            <Lock className="w-3.5 h-3.5" />
                            <span>READY TO UNLOCK</span>
                          </span>
                        )}
                      </td>
                      <td className="font-mono text-xs text-slate-400">
                        {dateDisplay}
                      </td>
                      <td className="text-right">
                        <div className="flex items-center justify-end gap-1.5">
                          {/* Unlock & View */}
                          <button
                            onClick={() => openModal('pinUnlock', { ...file, action: 'view' })}
                            title={locked ? "File currently locked" : "Unlock and View Content"}
                            className={`px-2.5 py-1.5 rounded-lg text-xs font-bold flex items-center gap-1 transition shadow ${
                              file.is_permanently_locked
                                ? 'bg-rose-900/50 text-rose-300 border border-rose-700/50 hover:bg-rose-800/50'
                                : locked
                                ? 'bg-amber-800/70 text-amber-200 border border-amber-600/50 hover:bg-amber-700'
                                : 'bg-amber-600 hover:bg-amber-500 text-white'
                            }`}
                          >
                            {locked ? <Clock className="w-3.5 h-3.5 animate-spin" /> : <Eye className="w-3.5 h-3.5" />}
                            <span>{file.is_permanently_locked ? 'Locked' : locked ? 'Countdown' : 'View'}</span>
                          </button>

                          {/* Decrypt & Download */}
                          <button
                            onClick={() => openModal('pinUnlock', { ...file, action: 'download' })}
                            title="Decrypt and Download"
                            className="p-1.5 bg-slate-900 hover:bg-slate-800 text-slate-300 hover:text-white border border-slate-800 rounded-lg transition"
                          >
                            <Download className="w-3.5 h-3.5" />
                          </button>

                          {/* Share Link */}
                          <button
                            onClick={() => openModal('shareCreate', file)}
                            title="Generate Shareable Link"
                            className="p-1.5 bg-slate-900 hover:bg-slate-800 text-slate-300 hover:text-sky-300 border border-slate-800 rounded-lg transition"
                          >
                            <Share2 className="w-3.5 h-3.5" />
                          </button>

                          {/* Rename */}
                          <button
                            onClick={() => openModal('rename', file)}
                            title="Rename File"
                            className="p-1.5 bg-slate-900 hover:bg-slate-800 text-slate-300 hover:text-white border border-slate-800 rounded-lg transition"
                          >
                            <Edit2 className="w-3.5 h-3.5" />
                          </button>

                          {/* Move to Recycle Bin */}
                          <button
                            onClick={() => handleDelete(file.id, displayName)}
                            title="Move to Recycle Bin"
                            className="p-1.5 bg-slate-900 hover:bg-red-950 text-slate-300 hover:text-red-400 border border-slate-800 rounded-lg transition"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })
              ) : (
                <tr>
                  <td colSpan="6" className="text-center py-14 text-slate-500 text-xs">
                    <Lock className="w-8 h-8 mx-auto mb-2 opacity-40 text-amber-400" />
                    Your confidential vault is currently empty. Go to "My Files" and click the Lock icon to encrypt sensitive files.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      <PinUnlockModal onSuccess={loadVault} />
      <FileViewerModal />
      <RenameModal onSuccess={loadVault} />
      <ShareCreateModal />
    </div>
  );
}
