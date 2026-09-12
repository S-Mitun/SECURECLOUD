import React, { useState, useEffect } from 'react';
import { adminApi } from '../api/adminApi';
import { useApp } from '../context/AppContext';
import { useAuth } from '../context/AuthContext';
import { 
  ShieldCheck, KeyRound, Copy, RefreshCw, Eye, EyeOff, 
  Lock, Check, X, ShieldAlert
} from 'lucide-react';

export function AdminSecurityConfigModal({ isOpen = true, onClose }) {
  const { showToast } = useApp();
  const { user: currentAdmin } = useAuth();
  const [currentCode, setCurrentCode] = useState('');
  const [showCode, setShowCode] = useState(false);
  const [loading, setLoading] = useState(false);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (isOpen) {
      loadSecurityCode();
    }
  }, [isOpen]);

  const loadSecurityCode = async () => {
    setLoading(true);
    try {
      const data = await adminApi.getAdminSecurityCode();
      setCurrentCode(data.admin_security_code || currentAdmin?.admin_security_code || '');
    } catch (err) {
      setCurrentCode(currentAdmin?.admin_security_code || '');
    } finally {
      setLoading(false);
    }
  };

  const handleCopyCode = () => {
    navigator.clipboard.writeText(currentCode);
    setCopied(true);
    showToast('Admin Dual Auth Key copied to clipboard!', 'success');
    setTimeout(() => setCopied(false), 2500);
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fade-in">
      <div className="glass-card max-w-md w-full border border-sky-500/40 shadow-2xl p-6 relative space-y-5 animate-scale-up">
        {/* Close Button */}
        <button
          onClick={onClose}
          className="absolute right-4 top-4 text-slate-400 hover:text-white p-1 rounded-lg hover:bg-slate-800 transition"
        >
          <X className="w-5 h-5" />
        </button>

        {/* Header */}
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-sky-950 border border-sky-500/40 flex items-center justify-center text-sky-400 shrink-0">
            <KeyRound className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-base font-black text-white tracking-wide">
              Admin Dual-Auth Key
            </h2>
            <p className="text-[11px] text-slate-400 font-mono">
              Fixed Administrator Security Credential
            </p>
          </div>
        </div>

        {/* Informational Banner */}
        <div className="bg-sky-950/40 border border-sky-500/30 rounded-xl p-3 text-xs text-sky-200 leading-relaxed font-sans">
          This <strong>Admin Dual-Auth Key</strong> is permanently bound to your administrator account (like your password). It ensures strict cross-admin repository isolation and prevents other administrators from accessing, scanning, or viewing your files without this key.
        </div>

        {/* Current Active Fixed Key Display */}
        <div className="space-y-1.5">
          <label className="text-[11px] font-bold text-slate-300 font-mono uppercase tracking-wider flex items-center justify-between">
            <span>Your Permanent Dual-Auth Password / Key:</span>
            <span className="text-[10px] text-emerald-400">FIXED CREDENTIAL</span>
          </label>
          <div className="flex items-center gap-2 bg-slate-950 border border-slate-700 rounded-xl p-2.5">
            <span className="font-mono text-base font-black tracking-widest text-sky-400 flex-1 pl-2">
              {loading ? (
                <RefreshCw className="w-4 h-4 animate-spin text-slate-500" />
              ) : showCode ? (
                currentCode
              ) : (
                '••••••••••••'
              )}
            </span>

            <button
              type="button"
              onClick={() => setShowCode(!showCode)}
              className="p-1.5 text-slate-400 hover:text-white hover:bg-slate-800 rounded-lg transition"
              title={showCode ? 'Hide Key' : 'Show Key'}
            >
              {showCode ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
            </button>

            <button
              type="button"
              onClick={handleCopyCode}
              className="px-2.5 py-1.5 bg-slate-900 hover:bg-slate-800 text-slate-300 hover:text-white border border-slate-700 rounded-lg text-xs font-mono font-semibold flex items-center gap-1 transition"
              title="Copy Dual-Auth Key"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copied ? 'Copied' : 'Copy'}</span>
            </button>
          </div>
        </div>

        {/* Footer Note */}
        <div className="pt-3 border-t border-slate-800/80 flex items-center justify-between text-xs font-mono text-slate-400">
          <span className="flex items-center gap-1.5 text-slate-400">
            <Lock className="w-3.5 h-3.5 text-sky-400" /> Enforced by SOC Enclave
          </span>
          <button
            onClick={onClose}
            className="px-4 py-1.5 bg-slate-800 hover:bg-slate-700 text-white rounded-lg text-xs font-bold transition"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
}
