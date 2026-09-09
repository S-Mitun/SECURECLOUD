import React, { useState, useEffect } from 'react';
import { useApp } from '../context/AppContext';
import { fileApi } from '../api/fileApi';
import { KeyRound, Eye, EyeOff, X, Unlock, Download, AlertTriangle, Clock, ShieldAlert } from 'lucide-react';
import { LockoutCountdown, formatTimeRemaining } from './LockoutCountdown';

export function PinUnlockModal({ onSuccess }) {
  const { activeModal, modalData, closeModal, showToast, openModal } = useApp();
  const [pin, setPin] = useState('');
  const [showPin, setShowPin] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [localLockedUntil, setLocalLockedUntil] = useState(null);
  const [localPermanentlyLocked, setLocalPermanentlyLocked] = useState(false);
  const [attemptWarning, setAttemptWarning] = useState('');

  useEffect(() => {
    if (modalData) {
      setLocalLockedUntil(modalData.locked_until || null);
      setLocalPermanentlyLocked(Boolean(modalData.is_permanently_locked));
      setAttemptWarning('');
      setPin('');
    }
  }, [modalData]);

  if (activeModal !== 'pinUnlock' || !modalData) return null;

  const isDownloadAction = modalData.action === 'download';
  const targetFileId = modalData.id || modalData.file_id;
  const filename = modalData.original_filename || modalData.filename || 'Confidential Document';

  // Check if currently locked
  const isLockedNow = () => {
    if (localPermanentlyLocked) return true;
    if (!localLockedUntil) return false;
    const dateStr = localLockedUntil.includes('T') ? localLockedUntil : localLockedUntil.replace(' ', 'T') + 'Z';
    return new Date(dateStr).getTime() > Date.now();
  };

  const handleCountdownExpire = () => {
    setLocalLockedUntil(null);
    setAttemptWarning('Lockout period expired. You may now attempt to unlock.');
    showToast('Lockout expired! You may now try your PIN again.', 'info');
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!pin || isLockedNow()) return;

    setSubmitting(true);
    setAttemptWarning('');
    try {
      if (isDownloadAction) {
        // Authenticated download of decrypted bytes
        const token = (sessionStorage.getItem('sc_token') || localStorage.getItem('sc_token'));
        const res = await fetch(`http://127.0.0.1:8000/api/confidential/unlock-download`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`
          },
          body: JSON.stringify({ file_id: targetFileId, pin })
        });

        if (!res.ok) {
          const errData = await res.json().catch(() => ({}));
          const errMsg = errData.detail || 'Incorrect PIN or decryption failure.';
          if (res.status === 423 || errMsg.includes('30 minutes') || errMsg.includes('2 hours')) {
            // Set 30m or 2h
            const now = new Date();
            const minutesToAdd = errMsg.includes('2 hours') ? 120 : 30;
            now.setMinutes(now.getMinutes() + minutesToAdd);
            setLocalLockedUntil(now.toISOString());
          }
          if (errMsg.includes('permanently') || errMsg.includes('cannot open ever')) {
            setLocalPermanentlyLocked(true);
          }
          setAttemptWarning(errMsg);
          throw new Error(errMsg);
        }

        const blob = await res.blob();
        const blobUrl = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = blobUrl;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        setTimeout(() => URL.revokeObjectURL(blobUrl), 10000);

        showToast(`Decrypted "${filename}" downloaded securely!`, 'success');
        closeModal();
      } else {
        // In-memory view decryption
        const res = await fileApi.unlockConfidential({
          file_id: targetFileId,
          pin
        });

        showToast('PIN verified! Decrypted file unlocked for viewing.', 'success');
        closeModal();
        
        // Pass decrypted payload directly into FileViewerModal
        openModal('fileViewer', {
          ...modalData,
          ...res,
          id: targetFileId,
          filename: filename,
          is_unlocked: true,
          viewPayload: res
        });
      }

      if (onSuccess) onSuccess();
    } catch (err) {
      const errMsg = err.message || 'Incorrect PIN / Decryption failed.';
      if (errMsg.includes('30 minutes')) {
        const now = new Date();
        now.setMinutes(now.getMinutes() + 30);
        setLocalLockedUntil(now.toISOString());
      } else if (errMsg.includes('2 hours')) {
        const now = new Date();
        now.setMinutes(now.getMinutes() + 120);
        setLocalLockedUntil(now.toISOString());
      } else if (errMsg.includes('permanently') || errMsg.includes('cannot open ever')) {
        setLocalPermanentlyLocked(true);
      }
      setAttemptWarning(errMsg);
      showToast(errMsg, 'error');
    } finally {
      setSubmitting(false);
    }
  };

  const locked = isLockedNow();

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/85 backdrop-blur-sm">
      <div className="glass-card max-w-md w-full p-6 border border-amber-500/40 shadow-2xl relative animate-scale-up space-y-4">
        <button
          onClick={closeModal}
          className="absolute top-4 right-4 text-slate-400 hover:text-white"
        >
          <X className="w-5 h-5" />
        </button>

        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-xl bg-amber-950/80 border border-amber-500/40 text-amber-400 shrink-0">
            <KeyRound className="w-6 h-6" />
          </div>
          <div>
            <h3 className="text-base font-bold text-white">
              {isDownloadAction ? 'Decrypt & Download File' : 'Unlock Confidential File'}
            </h3>
            <p className="text-xs text-slate-400">Zero-Knowledge Progressive Security Shield</p>
          </div>
        </div>

        <div className="text-xs text-slate-300 bg-slate-900/90 p-3 rounded-lg border border-slate-800 flex items-center justify-between">
          <span>File: <strong className="text-amber-300">{filename}</strong></span>
          <span className="font-mono text-[10px] text-amber-400/80 uppercase">AES-256-GCM</span>
        </div>

        {/* Lockout Countdown Timer */}
        {(localPermanentlyLocked || localLockedUntil) && (
          <LockoutCountdown 
            lockedUntil={localLockedUntil}
            isPermanentlyLocked={localPermanentlyLocked}
            onExpire={handleCountdownExpire}
            compact={false}
          />
        )}

        {/* Dynamic Warning Alert */}
        {attemptWarning && !locked && (
          <div className="p-3 bg-amber-950/40 border border-amber-500/30 rounded-xl flex items-center gap-2 text-amber-300 text-xs font-mono">
            <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" />
            <span>{attemptWarning}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-xs font-semibold text-slate-300 mb-1.5 flex items-center justify-between">
              <span>Enter 6-Digit PIN or Passphrase:</span>
              <span className="text-[10px] text-slate-400 font-mono">Max 3 attempts per stage</span>
            </label>
            <div className="relative">
              <input
                type={showPin ? 'text' : 'password'}
                value={pin}
                disabled={locked || submitting}
                onChange={(e) => setPin(e.target.value)}
                placeholder={locked ? 'Vault currently locked' : 'Enter secret PIN'}
                className="w-full bg-slate-900 border border-slate-700 disabled:opacity-50 disabled:cursor-not-allowed rounded-lg px-3.5 py-2.5 text-sm text-white focus:outline-none focus:border-amber-500 font-mono tracking-widest"
                autoFocus={!locked}
                required
              />
              <button
                type="button"
                disabled={locked}
                onClick={() => setShowPin(!showPin)}
                className="absolute right-3 top-3 text-slate-400 hover:text-white disabled:opacity-30"
              >
                {showPin ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            </div>
          </div>

          <div className="flex items-center justify-end gap-2 pt-2">
            <button
              type="button"
              onClick={closeModal}
              className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-xs font-bold transition"
            >
              Close
            </button>
            <button
              type="submit"
              disabled={submitting || locked || !pin}
              className="px-5 py-2 bg-amber-600 hover:bg-amber-500 disabled:opacity-50 disabled:cursor-not-allowed text-white rounded-lg text-xs font-bold flex items-center gap-2 transition shadow-lg"
            >
              {isDownloadAction ? <Download className="w-4 h-4" /> : <Unlock className="w-4 h-4" />}
              {submitting ? 'Decrypting...' : locked ? 'Locked' : (isDownloadAction ? 'Decrypt & Download' : 'Unlock & View')}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
