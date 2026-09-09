import React, { useState } from 'react';
import { useApp } from '../context/AppContext';
import { fileApi } from '../api/fileApi';
import { Lock, Eye, EyeOff, X, Shield } from 'lucide-react';

export function PinLockModal({ onSuccess }) {
  const { activeModal, modalData, closeModal, showToast } = useApp();
  const [pin, setPin] = useState('');
  const [showPin, setShowPin] = useState(false);
  const [savePassword, setSavePassword] = useState(true);
  const [submitting, setSubmitting] = useState(false);

  if (activeModal !== 'pinLock' || !modalData) return null;

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!pin || pin.length < 4) {
      showToast('Encryption PIN must be at least 4 characters long.', 'warning');
      return;
    }

    setSubmitting(true);
    try {
      await fileApi.lockConfidential({
        file_id: modalData.id,
        pin,
        save_password: savePassword
      });
      showToast(`File "${modalData.filename}" encrypted and moved to Confidential Vault!`, 'success');
      closeModal();
      if (onSuccess) onSuccess();
    } catch (err) {
      showToast(err.message || 'Encryption failed.', 'error');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
      <div className="glass-card max-w-md w-full p-6 border border-amber-500/40 shadow-2xl relative animate-scale-up">
        <button
          onClick={closeModal}
          className="absolute top-4 right-4 text-slate-400 hover:text-white"
        >
          <X className="w-5 h-5" />
        </button>

        <div className="flex items-center gap-3 mb-4">
          <div className="p-2.5 rounded-xl bg-amber-950/80 border border-amber-500/40 text-amber-400">
            <Lock className="w-6 h-6" />
          </div>
          <div>
            <h3 className="text-base font-bold text-white">Encrypt Confidential File</h3>
            <p className="text-xs text-slate-400">AES-256-GCM Zero-Knowledge Protection</p>
          </div>
        </div>

        <p className="text-xs text-slate-300 mb-4 bg-slate-900/90 p-3 rounded-lg border border-slate-800">
          Target File: <strong className="text-amber-300">{modalData.filename}</strong>
        </p>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-xs font-semibold text-slate-300 mb-1.5">
              Set Decryption PIN / Passphrase:
            </label>
            <div className="relative">
              <input
                type={showPin ? 'text' : 'password'}
                value={pin}
                onChange={(e) => setPin(e.target.value)}
                placeholder="Enter 4-8 digit secure PIN"
                className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3.5 py-2 text-sm text-white focus:outline-none focus:border-amber-500 font-mono tracking-widest"
                required
              />
              <button
                type="button"
                onClick={() => setShowPin(!showPin)}
                className="absolute right-3 top-2.5 text-slate-400 hover:text-white"
              >
                {showPin ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            </div>
          </div>

          <label className="flex items-center gap-2 text-xs text-slate-300 cursor-pointer select-none bg-slate-900/50 p-2.5 rounded-lg border border-slate-800">
            <input
              type="checkbox"
              checked={savePassword}
              onChange={(e) => setSavePassword(e.target.checked)}
              className="rounded bg-slate-800 border-slate-700 text-amber-500 focus:ring-0"
            />
            <span>Save PIN to my Confidential Recovery Vault (Prevents permanent lockout)</span>
          </label>

          <div className="flex items-center justify-end gap-2 pt-2">
            <button
              type="button"
              onClick={closeModal}
              className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-xs font-bold"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={submitting}
              className="px-5 py-2 bg-amber-600 hover:bg-amber-500 text-white rounded-lg text-xs font-bold flex items-center gap-2"
            >
              {submitting ? 'Encrypting...' : 'Lock File with AES-256'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
