import React, { useState } from 'react';
import { authApi } from '../api/authApi';
import { useApp } from '../context/AppContext';
import { 
  ShieldAlert, Lock, AlertTriangle, X, CheckCircle2, 
  RefreshCw, LogOut, Share2, ShieldX, Key
} from 'lucide-react';

export function EmergencyLockdownModal({ isOpen, onClose }) {
  const { showToast, triggerCriticalAlert } = useApp();
  const [password, setPassword] = useState('');
  const [acknowledged, setAcknowledged] = useState(false);
  const [loading, setLoading] = useState(false);
  const [lockdownResult, setLockdownResult] = useState(null);

  if (!isOpen) return null;

  const handleExecuteLockdown = async (e) => {
    e.preventDefault();
    if (!acknowledged) {
      showToast('Please check the acknowledgement checkbox to proceed.', 'error');
      return;
    }

    setLoading(true);
    try {
      const res = await authApi.triggerEmergencyLockdown({
        password,
        acknowledgement: true
      });
      setLockdownResult(res.stats);
      showToast('🚨 EMERGENCY LOCKDOWN ACTIVE: All sessions terminated and public shares revoked!', 'error');
      triggerCriticalAlert({
        filename: 'Emergency Defense Mode Engaged',
        threat_score: 99.0,
        verdict: 'ACCOUNT_LOCKDOWN_ACTIVE'
      });
    } catch (err) {
      showToast(err.message || 'Lockdown initiation failed. Verify your password.', 'error');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black/90 backdrop-blur-md z-50 flex items-center justify-center p-4">
      <div className="glass-card max-w-lg w-full border border-rose-500/60 shadow-2xl p-6 space-y-5">
        {/* Header */}
        <div className="flex items-start justify-between gap-3 border-b border-slate-800 pb-4">
          <div className="flex items-center gap-3 text-rose-400">
            <div className="p-3 bg-rose-950/90 border border-rose-500/50 rounded-xl">
              <ShieldAlert className="w-7 h-7" />
            </div>
            <div>
              <h3 className="text-lg font-black text-white flex items-center gap-2">
                Emergency Account Lockdown
                <span className="px-2 py-0.5 bg-rose-950 border border-rose-500/40 text-rose-300 text-[10px] rounded font-mono">
                  DEFENSE PROTOCOL
                </span>
              </h3>
              <p className="text-xs text-rose-300/80 font-mono mt-0.5">
                Instant Zero-Trust Account Isolation
              </p>
            </div>
          </div>

          <button onClick={onClose} className="p-1.5 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800">
            <X className="w-5 h-5" />
          </button>
        </div>

        {lockdownResult ? (
          /* Success Screen */
          <div className="space-y-4">
            <div className="p-4 bg-rose-950/30 border border-rose-500/40 rounded-xl space-y-2 text-center">
              <CheckCircle2 className="w-10 h-10 text-rose-400 mx-auto" />
              <h4 className="text-base font-bold text-white">Emergency Lockdown Protocol Engaged</h4>
              <p className="text-xs text-slate-300">
                Your account is now in strict Zero-Trust isolation mode.
              </p>
            </div>

            <div className="grid grid-cols-3 gap-2 text-center font-mono text-xs">
              <div className="p-3 bg-slate-900 rounded-xl border border-slate-800">
                <div className="text-slate-500 text-[10px] uppercase">Sessions Killed</div>
                <div className="text-lg font-bold text-rose-400 mt-1">{lockdownResult.sessions_terminated}</div>
              </div>
              <div className="p-3 bg-slate-900 rounded-xl border border-slate-800">
                <div className="text-slate-500 text-[10px] uppercase">Shares Revoked</div>
                <div className="text-lg font-bold text-amber-400 mt-1">{lockdownResult.shared_links_revoked}</div>
              </div>
              <div className="p-3 bg-slate-900 rounded-xl border border-slate-800">
                <div className="text-slate-500 text-[10px] uppercase">Vaults Sealed</div>
                <div className="text-lg font-bold text-emerald-400 mt-1">AES-256</div>
              </div>
            </div>

            <button
              onClick={onClose}
              className="w-full py-2.5 bg-rose-600 hover:bg-rose-500 text-white rounded-xl text-xs font-bold transition"
            >
              Acknowledge & Close
            </button>
          </div>
        ) : (
          /* Confirmation Form */
          <form onSubmit={handleExecuteLockdown} className="space-y-4 text-xs">
            <div className="p-3.5 bg-rose-950/20 border border-rose-500/30 rounded-xl space-y-2 text-slate-300 leading-relaxed">
              <div className="font-bold text-rose-300 flex items-center gap-1.5">
                <AlertTriangle className="w-4 h-4 text-rose-400" /> Triggering Emergency Lockdown will immediately:
              </div>
              <ul className="list-disc pl-5 space-y-1 text-slate-300">
                <li>Terminate all active web login sessions across all devices and browsers.</li>
                <li>Immediately revoke and invalidate all active external public share links.</li>
                <li>Seal and lock all confidential file vaults with client-side PIN encryption.</li>
                <li>Dispatch a critical defense alert to the SOC Sentinel VM.</li>
              </ul>
            </div>

            <div>
              <label className="block text-slate-300 font-semibold mb-1">
                Confirm Account Password:
              </label>
              <div className="relative">
                <Key className="w-4 h-4 text-slate-500 absolute left-3 top-3" />
                <input
                  type="password"
                  placeholder="Enter current password to verify identity..."
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                  className="w-full bg-slate-900 border border-slate-700 rounded-xl pl-9 pr-3 py-2.5 text-white focus:outline-none focus:border-rose-500"
                />
              </div>
            </div>

            <label className="flex items-start gap-2.5 cursor-pointer pt-1">
              <input
                type="checkbox"
                checked={acknowledged}
                onChange={(e) => setAcknowledged(e.target.checked)}
                className="mt-0.5 rounded bg-slate-900 border-slate-700 text-rose-500 focus:ring-0"
              />
              <span className="text-slate-300 text-[11px] leading-snug">
                I understand that this action will terminate my active sessions, revoke external sharing, and lockdown this repository.
              </span>
            </label>

            <div className="flex items-center justify-end gap-2 pt-3 border-t border-slate-800">
              <button
                type="button"
                onClick={onClose}
                className="px-4 py-2 bg-slate-900 hover:bg-slate-800 text-slate-400 hover:text-white rounded-xl font-semibold"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={loading || !password || !acknowledged}
                className="px-5 py-2 bg-rose-600 hover:bg-rose-500 disabled:opacity-50 text-white rounded-xl font-bold shadow-lg flex items-center gap-1.5 transition"
              >
                {loading ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <ShieldAlert className="w-3.5 h-3.5" />}
                ENGAGE EMERGENCY LOCKDOWN
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
}
