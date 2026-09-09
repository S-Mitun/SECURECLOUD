import React, { useState } from 'react';
import { useApp } from '../context/AppContext';
import { adminApi } from '../api/adminApi';
import { HardDrive, X } from 'lucide-react';

export function EditQuotaModal({ onSuccess }) {
  const { activeModal, modalData, closeModal, showToast } = useApp();
  const [quotaGb, setQuotaGb] = useState(() => modalData?.quota_gb || 10);
  const [submitting, setSubmitting] = useState(false);

  if (activeModal !== 'editQuota' || !modalData) return null;

  const handleSubmit = async (e) => {
    e.preventDefault();
    setSubmitting(true);
    try {
      await adminApi.updateUserQuota(modalData.id, quotaGb);
      showToast(`Storage quota for user "${modalData.username}" updated to ${quotaGb} GB!`, 'success');
      closeModal();
      if (onSuccess) onSuccess();
    } catch (err) {
      showToast(err.message || 'Failed to update quota.', 'error');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
      <div className="glass-card max-w-md w-full p-6 border border-slate-700 shadow-2xl relative animate-scale-up">
        <button
          onClick={closeModal}
          className="absolute top-4 right-4 text-slate-400 hover:text-white"
        >
          <X className="w-5 h-5" />
        </button>

        <div className="flex items-center gap-3 mb-4">
          <div className="p-2.5 rounded-xl bg-sky-950/80 border border-sky-500/40 text-sky-400">
            <HardDrive className="w-6 h-6" />
          </div>
          <div>
            <h3 className="text-base font-bold text-white">Adjust Storage Quota</h3>
            <p className="text-xs text-slate-400">User: <strong>{modalData.username}</strong> ({modalData.email})</p>
          </div>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-xs font-semibold text-slate-300 mb-1.5">
              Assigned Quota (in Gigabytes):
            </label>
            <input
              type="number"
              min="1"
              max="500"
              step="1"
              value={quotaGb}
              onChange={(e) => setQuotaGb(e.target.value)}
              className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3.5 py-2 text-sm text-white focus:outline-none focus:border-sky-500 font-mono"
              required
            />
          </div>

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
              {submitting ? 'Updating...' : 'Save Storage Quota'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
