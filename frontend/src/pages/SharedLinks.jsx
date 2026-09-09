import React, { useEffect, useState } from 'react';
import { useApp } from '../context/AppContext';
import { fileApi } from '../api/fileApi';
import { 
  Share2, Clock, Lock, Copy, Check, Trash2, RefreshCw, Eye, AlertCircle,
  ExternalLink, Send, Mail, MessageSquare
} from 'lucide-react';
import { SecurityBadge } from '../components/SecurityBadge';

export function SharedLinks() {
  const { showToast, openModal } = useApp();
  const [shares, setShares] = useState([]);
  const [loading, setLoading] = useState(true);
  const [currentTime, setCurrentTime] = useState(Date.now());
  const [mountTime] = useState(Date.now());
  const [copiedId, setCopiedId] = useState(null);

  const loadShares = async (isInitial = true) => {
    if (isInitial) setLoading(true);
    try {
      const data = await fileApi.listShares();
      setShares(Array.isArray(data) ? data : (data.shares || []));
    } catch (err) {
      if (isInitial) showToast(err.message || 'Failed to load shared links.', 'error');
    } finally {
      if (isInitial) setLoading(false);
    }
  };

  useEffect(() => {
    loadShares(true);
    const poller = setInterval(() => {
      loadShares(false);
    }, 2500);

    const interval = setInterval(() => {
      setCurrentTime(Date.now());
    }, 1000);

    return () => {
      clearInterval(poller);
      clearInterval(interval);
    };
  }, []);

  const handleRevoke = async (shareId) => {
    try {
      await fileApi.revokeShare(shareId);
      showToast('Shared link revoked immediately.', 'info');
      loadShares();
    } catch (err) {
      showToast(err.message || 'Failed to revoke link.', 'error');
    }
  };

  const getShareUrl = (shareId) => {
    return `${window.location.origin}/public-share/${shareId}`;
  };

  const copyShareUrl = (shareId) => {
    const url = getShareUrl(shareId);
    navigator.clipboard.writeText(url);
    setCopiedId(shareId);
    showToast('Share URL copied to clipboard!', 'success');
    setTimeout(() => setCopiedId(null), 2500);
  };

  const handleWhatsApp = (share) => {
    const url = getShareUrl(share.id);
    const text = `SecureCloud Shared Document: ${share.filename}\n${url}`;
    window.open(`https://api.whatsapp.com/send?text=${encodeURIComponent(text)}`, '_blank');
  };

  const handleEmail = (share) => {
    const url = getShareUrl(share.id);
    const subject = `Secure File: ${share.filename}`;
    const body = `View and access the shared document securely:\n\n${url}`;
    window.open(`mailto:?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`, '_blank');
  };

  const handleTelegram = (share) => {
    const url = getShareUrl(share.id);
    const text = `Secure file: ${share.filename}`;
    window.open(`https://t.me/share/url?url=${encodeURIComponent(url)}&text=${encodeURIComponent(text)}`, '_blank');
  };

  const calculateRemaining = (share) => {
    if (!share.expires_at || share.expires_at === 'Never') {
      return { label: 'Permanent', isExpired: false };
    }

    let remainingSec = 0;
    if (share.expires_at) {
      const expDate = new Date(share.expires_at.replace(' ', 'T') + 'Z').getTime();
      const diff = expDate - currentTime;
      remainingSec = Math.floor(diff / 1000);
    }

    if (isNaN(remainingSec) || remainingSec <= 0) {
      if (share.time_remaining_seconds !== undefined) {
        const elapsed = Math.floor((currentTime - mountTime) / 1000);
        remainingSec = Math.max(0, share.time_remaining_seconds - elapsed);
      }
    }

    if (remainingSec <= 0) {
      return { label: 'EXPIRED', isExpired: true };
    }

    const hours = Math.floor(remainingSec / 3600);
    const minutes = Math.floor((remainingSec % 3600) / 60);
    const seconds = remainingSec % 60;

    return {
      label: `${hours}h ${minutes.toString().padStart(2, '0')}m ${seconds.toString().padStart(2, '0')}s`,
      isExpired: false
    };
  };

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-6">
      {/* Header Banner */}
      <div className="glass-card p-6 border border-cyan-500/40 bg-gradient-to-r from-slate-900 via-cyan-950/20 to-slate-900 shadow-2xl">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="p-3 rounded-xl bg-cyan-950/90 border border-cyan-500/50 text-cyan-400">
              <Share2 className="w-8 h-8" />
            </div>
            <div>
              <h1 className="text-xl font-black text-white tracking-wide flex items-center gap-2">
                Active Shared Links & Expiring URLs
                <span className="px-2 py-0.5 bg-cyan-950 border border-cyan-500/50 text-cyan-300 text-[10px] rounded font-mono">
                  LIVE 1-SEC COUNTDOWN
                </span>
              </h1>
              <p className="text-xs text-slate-400 mt-1">
                Cryptographically enforced expiring endpoints. Each file countdown calculates independently from creation time.
              </p>
            </div>
          </div>
          <button
            onClick={loadShares}
            className="p-2 bg-slate-900 hover:bg-slate-800 text-slate-300 hover:text-white border border-slate-800 rounded-lg text-xs flex items-center gap-1.5 transition"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} /> Refresh Shares
          </button>
        </div>
      </div>

      {/* Shares Table */}
      <div className="glass-card overflow-hidden border border-slate-800 shadow-2xl">
        <div className="overflow-x-auto">
          <table className="soc-table">
            <thead>
              <tr>
                <th>Shared File</th>
                <th>Security / Mode</th>
                <th>Expires In (Live Countdown)</th>
                <th>Views</th>
                <th>Created (IST)</th>
                <th className="text-right">Share & Actions</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr>
                  <td colSpan="6" className="text-center py-16 text-slate-400 font-mono text-xs">
                    <RefreshCw className="w-5 h-5 animate-spin mx-auto mb-2 text-cyan-400" />
                    RETRIEVING ACTIVE SHARED ENDPOINTS...
                  </td>
                </tr>
              ) : shares.length > 0 ? (
                shares.map((share) => {
                  const countdown = calculateRemaining(share);
                  return (
                    <tr key={share.id}>
                      <td>
                        <div className="flex items-center gap-2.5">
                          <div className="p-2 rounded-lg bg-cyan-950/60 border border-cyan-500/30 text-cyan-400 shrink-0">
                            <Share2 className="w-4 h-4" />
                          </div>
                          <div>
                            <div className="font-bold text-white text-xs sm:text-sm">
                              {share.filename}
                            </div>
                            <div className="text-[10px] text-slate-500 font-mono">
                              ID: {String(share.id).substring(0, 16)}...
                            </div>
                          </div>
                        </div>
                      </td>
                      <td>
                        <div className="flex items-center gap-1.5 flex-wrap">
                          {share.is_password_protected ? (
                            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold bg-amber-950 text-amber-400 border border-amber-500/40">
                              <Lock className="w-3 h-3" /> Password
                            </span>
                          ) : (
                            <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-800 text-slate-300 border border-slate-700">
                              Public
                            </span>
                          )}
                          <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-slate-900 text-slate-400 border border-slate-800">
                            {share.view_only ? 'View Only' : 'Download Enabled'}
                          </span>
                        </div>
                      </td>
                      <td>
                        <div className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-mono font-bold ${
                          countdown.isExpired
                            ? 'bg-red-950/90 text-red-400 border border-red-500/40'
                            : 'bg-slate-900 text-cyan-400 border border-cyan-500/30'
                        }`}>
                          <Clock className="w-3.5 h-3.5 animate-pulse" />
                          <span>{countdown.label}</span>
                        </div>
                      </td>
                      <td className="font-mono text-xs text-slate-300">
                        {share.view_count || 0} views
                      </td>
                      <td className="font-mono text-xs text-slate-400">
                        {share.created_at ? (share.created_at.includes('IST') ? share.created_at : `${share.created_at} IST`) : 'Today'}
                      </td>
                      <td className="text-right">
                        <div className="flex items-center justify-end gap-1.5">
                          {/* WhatsApp */}
                          <button
                            onClick={() => handleWhatsApp(share)}
                            title="Share on WhatsApp"
                            className="p-1.5 bg-emerald-950 hover:bg-emerald-900 text-emerald-300 border border-emerald-500/40 rounded-lg transition"
                          >
                            <Send className="w-3.5 h-3.5" />
                          </button>

                          {/* Email */}
                          <button
                            onClick={() => handleEmail(share)}
                            title="Share via Email"
                            className="p-1.5 bg-slate-900 hover:bg-slate-800 text-slate-300 hover:text-white border border-slate-800 rounded-lg transition"
                          >
                            <Mail className="w-3.5 h-3.5" />
                          </button>

                          {/* Open Public Landing Page */}
                          <a
                            href={getShareUrl(share.id)}
                            target="_blank"
                            rel="noreferrer"
                            title="Open Public Landing Page"
                            className="p-1.5 bg-slate-900 hover:bg-slate-800 text-slate-300 hover:text-sky-300 border border-slate-800 rounded-lg transition"
                          >
                            <ExternalLink className="w-3.5 h-3.5" />
                          </a>

                          {/* Copy Link */}
                          <button
                            onClick={() => copyShareUrl(share.id)}
                            title="Copy Share Link"
                            className="p-1.5 bg-slate-900 hover:bg-slate-800 text-slate-300 hover:text-cyan-300 border border-slate-800 rounded-lg transition"
                          >
                            {copiedId === share.id ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                          </button>

                          {/* Revoke */}
                          <button
                            onClick={() => handleRevoke(share.id)}
                            title="Revoke Link Immediately"
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
                    <Share2 className="w-8 h-8 mx-auto mb-2 opacity-40 text-cyan-400" />
                    No active shared links. Go to "My Files" and click the Share icon on any file.
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
