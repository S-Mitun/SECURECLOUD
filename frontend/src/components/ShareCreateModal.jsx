import React, { useState } from 'react';
import { useApp } from '../context/AppContext';
import { fileApi } from '../api/fileApi';
import { Share2, Clock, Lock, Copy, Check, X } from 'lucide-react';

export function ShareCreateModal({ onSuccess }) {
  const { activeModal, modalData, closeModal, showToast } = useApp();
  const [expiresInHours, setExpiresInHours] = useState(24);
  const [viewOnly, setViewOnly] = useState(false);
  const [password, setPassword] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [createdShare, setCreatedShare] = useState(null);
  const [copied, setCopied] = useState(false);

  if (activeModal !== 'shareCreate' || !modalData) return null;

  const handleSubmit = async (e) => {
    e.preventDefault();
    setSubmitting(true);
    try {
      const res = await fileApi.createShare({
        file_id: modalData.id,
        expires_in_hours: parseInt(expiresInHours),
        view_only: viewOnly,
        password: password || null
      });

      setCreatedShare(res.share);
      showToast('Secure sharing link generated successfully!', 'success');
      if (onSuccess) onSuccess();
    } catch (err) {
      showToast(err.message || 'Failed to create shared link.', 'error');
    } finally {
      setSubmitting(false);
    }
  };

  const copyToClipboard = () => {
    if (!createdShare) return;
    const url = `${window.location.origin}/public-share/${createdShare.id}`;
    navigator.clipboard.writeText(url);
    setCopied(true);
    showToast('Share link copied to clipboard!', 'success');
    setTimeout(() => setCopied(false), 3000);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
      <div className="glass-card max-w-md w-full p-6 border border-cyan-500/40 shadow-2xl relative animate-scale-up">
        <button
          onClick={closeModal}
          className="absolute top-4 right-4 text-slate-400 hover:text-white"
        >
          <X className="w-5 h-5" />
        </button>

        <div className="flex items-center gap-3 mb-4">
          <div className="p-2.5 rounded-xl bg-cyan-950/80 border border-cyan-500/40 text-cyan-400">
            <Share2 className="w-6 h-6" />
          </div>
          <div>
            <h3 className="text-base font-bold text-white">Generate Expiring Share Link</h3>
            <p className="text-xs text-slate-400">Zero-Trust Encrypted Public Sharing</p>
          </div>
        </div>

        {!createdShare ? (
          <form onSubmit={handleSubmit} className="space-y-4">
            <p className="text-xs text-slate-300 bg-slate-900/90 p-3 rounded-lg border border-slate-800">
              File: <strong className="text-cyan-300">{modalData.filename}</strong>
            </p>

            <div>
              <label className="block text-xs font-semibold text-slate-300 mb-1.5 flex items-center gap-1.5">
                <Clock className="w-3.5 h-3.5 text-cyan-400" /> Link Lifetime / Expiration:
              </label>
              <select
                value={expiresInHours}
                onChange={(e) => setExpiresInHours(e.target.value)}
                className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3.5 py-2 text-sm text-white focus:outline-none focus:border-cyan-500"
              >
                <option value={1}>1 Hour (Temporary)</option>
                <option value={6}>6 Hours</option>
                <option value={24}>24 Hours (1 Day)</option>
                <option value={72}>72 Hours (3 Days)</option>
                <option value={168}>7 Days (1 Week)</option>
              </select>
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-300 mb-1.5 flex items-center gap-1.5">
                <Lock className="w-3.5 h-3.5 text-cyan-400" /> Optional Password Protection:
              </label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Leave blank for no password"
                className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3.5 py-2 text-sm text-white focus:outline-none focus:border-cyan-500"
              />
            </div>

            <label className="flex items-center gap-2 text-xs text-slate-300 cursor-pointer select-none bg-slate-900/50 p-2.5 rounded-lg border border-slate-800">
              <input
                type="checkbox"
                checked={viewOnly}
                onChange={(e) => setViewOnly(e.target.checked)}
                className="rounded bg-slate-800 border-slate-700 text-cyan-500 focus:ring-0"
              />
              <span>Restrict to View-Only (Disable Direct Download Button)</span>
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
                className="btn-cyber px-5 py-2 rounded-lg text-xs font-bold"
              >
                {submitting ? 'Generating...' : 'Create Secure Link'}
              </button>
            </div>
          </form>
        ) : (
          <div className="space-y-4">
            <div className="p-4 rounded-xl bg-emerald-950/60 border border-emerald-500/40 text-emerald-100 text-xs">
              <strong>Link Active!</strong> This secure link will automatically expire in{' '}
              {expiresInHours} hours.
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-300 mb-1.5">
                Shareable Link URL:
              </label>
              <div className="flex items-center gap-2">
                <input
                  type="text"
                  readOnly
                  value={`${window.location.origin}/public-share/${createdShare.id}`}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-300 font-mono"
                />
                <button
                  onClick={copyToClipboard}
                  className="p-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg text-xs font-bold flex items-center gap-1 shrink-0"
                >
                  {copied ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
                </button>
              </div>
            </div>

            <div className="flex justify-end pt-2">
              <button
                onClick={closeModal}
                className="px-5 py-2 bg-slate-800 hover:bg-slate-700 text-white rounded-lg text-xs font-bold"
              >
                Done
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
