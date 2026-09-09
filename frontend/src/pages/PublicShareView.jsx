import React, { useEffect, useState, useRef } from 'react';
import { useParams } from 'react-router-dom';
import { useApp } from '../context/AppContext';
import { 
  ShieldCheck, Share2, Download, Eye, Lock, Clock, FileText, 
  AlertTriangle, CheckCircle2, RefreshCw, Key, Send, Copy, ExternalLink,
  FileSpreadsheet, Presentation, Image as ImageIcon, Video, Music, Code, Maximize2, Minimize2
} from 'lucide-react';
import { SecurityBadge } from '../components/SecurityBadge';
import { PresentationViewer } from '../components/PresentationViewer';
import { API_BASE_URL } from '../api/apiClient';

export function PublicShareView() {
  const { id } = useParams();
  const { showToast } = useApp();
  const [shareInfo, setShareInfo] = useState(null);
  const [viewData, setViewData] = useState(null);
  const [password, setPassword] = useState('');
  const [isUnlocked, setIsUnlocked] = useState(false);
  const [loading, setLoading] = useState(true);
  const [verifying, setVerifying] = useState(false);
  const [error, setError] = useState(null);
  const [copied, setCopied] = useState(false);
  const [activeSheet, setActiveSheet] = useState('');
  const [blobStreamUrl, setBlobStreamUrl] = useState(null);
  const [isFullscreen, setIsFullscreen] = useState(false);
  const fetchedRef = useRef(false);

  const loadShare = async () => {
    if (!id) return;
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`${API_BASE_URL}/api/shares/public/${id}`);
      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.detail || 'Shared link is invalid or expired.');
      }
      const data = await res.json();
      setShareInfo(data);

      if (!data.is_password_protected) {
        setIsUnlocked(true);
        loadContent(data);
      }
    } catch (err) {
      setError(err.message || 'Shared link is invalid or expired.');
    } finally {
      setLoading(false);
    }
  };

  const loadContent = async (shareObj) => {
    try {
      // 1. Fetch structured metadata
      const res = await fetch(`${API_BASE_URL}/api/shares/public/${id}/view`);
      if (res.ok) {
        const vData = await res.json();
        setViewData(vData);
        if (vData.sheet_names && vData.sheet_names.length > 0) {
          setActiveSheet(vData.sheet_names[0]);
        }
      }

      // 2. Fetch authentic decrypted blob stream immediately for native browser blob view
      try {
        const sRes = await fetch(`${API_BASE_URL}/api/shares/public/${id}/stream`);
        if (sRes.ok) {
          const blob = await sRes.blob();
          const bUrl = URL.createObjectURL(blob);
          setBlobStreamUrl(bUrl);
        }
      } catch (sErr) {
        console.warn("Public stream blob notice:", sErr);
      }
    } catch (err) {
      console.warn("Public view content notice:", err);
    }
  };

  useEffect(() => {
    loadShare();
    return () => {
      if (blobStreamUrl && blobStreamUrl.startsWith('blob:')) {
        URL.revokeObjectURL(blobStreamUrl);
      }
    };
  }, [id]);

  const handleVerifyPassword = async (e) => {
    e.preventDefault();
    if (!password) return;
    setVerifying(true);
    try {
      const res = await fetch(`${API_BASE_URL}/api/shares/public/${id}/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password })
      });
      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.detail || 'Incorrect password.');
      }
      setIsUnlocked(true);
      showToast('Access granted to shared file!', 'success');
      loadContent(shareInfo);
    } catch (err) {
      showToast(err.message || 'Incorrect password.', 'error');
    } finally {
      setVerifying(false);
    }
  };

  const currentUrl = window.location.href;
  const shareText = `Secure file shared via SecureCloud: ${shareInfo?.filename || 'Document'}`;

  const handleCopyLink = () => {
    navigator.clipboard.writeText(currentUrl);
    setCopied(true);
    showToast('Public link copied to clipboard!', 'success');
    setTimeout(() => setCopied(false), 2500);
  };

  const handleWhatsAppShare = () => {
    const url = `https://api.whatsapp.com/send?text=${encodeURIComponent(shareText + '\n' + currentUrl)}`;
    window.open(url, '_blank');
  };

  const handleEmailShare = () => {
    const subject = encodeURIComponent(`Shared File: ${shareInfo?.filename || 'Document'}`);
    const body = encodeURIComponent(`${shareText}\n\nAccess Link: ${currentUrl}`);
    window.location.href = `mailto:?subject=${subject}&body=${body}`;
  };

  const handleTelegramShare = () => {
    const url = `https://t.me/share/url?url=${encodeURIComponent(currentUrl)}&text=${encodeURIComponent(shareText)}`;
    window.open(url, '_blank');
  };

  const toggleBrowserFullscreen = () => {
    if (!document.fullscreenElement) {
      document.documentElement.requestFullscreen().then(() => setIsFullscreen(true)).catch(() => {});
    } else {
      document.exitFullscreen().then(() => setIsFullscreen(false)).catch(() => {});
    }
  };

  const handlePopoutBlobUrl = () => {
    if (blobStreamUrl) {
      window.open(blobStreamUrl, '_blank');
    } else {
      window.open(`${API_BASE_URL}/api/shares/public/${id}/stream`, '_blank');
    }
  };

  if (loading) {
    return (
      <div className="w-screen h-screen bg-slate-950 flex flex-col items-center justify-center text-slate-400 font-mono text-xs gap-3">
        <RefreshCw className="w-8 h-8 text-sky-400 animate-spin" />
        <div>DECRYPTING SECURE PUBLIC STREAM...</div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="w-screen h-screen bg-slate-950 flex items-center justify-center p-4">
        <div className="glass-card p-8 max-w-md w-full text-center space-y-4 border border-rose-500/40 shadow-2xl">
          <AlertTriangle className="w-12 h-12 text-rose-400 mx-auto" />
          <h2 className="text-lg font-black text-white">Access Link Unavailable</h2>
          <p className="text-xs text-slate-400 font-mono leading-relaxed">{error}</p>
          <button
            onClick={loadShare}
            className="px-4 py-2 bg-slate-900 hover:bg-slate-800 text-slate-200 border border-slate-700 rounded-xl text-xs font-semibold"
          >
            Retry Access
          </button>
        </div>
      </div>
    );
  }

  // Password Unlock Screen
  if (shareInfo?.is_password_protected && !isUnlocked) {
    return (
      <div className="w-screen h-screen bg-slate-950 flex items-center justify-center p-4">
        <div className="glass-card p-8 max-w-md w-full border border-sky-500/40 shadow-2xl space-y-5">
          <div className="text-center space-y-2">
            <div className="w-12 h-12 rounded-2xl bg-sky-950 border border-sky-500/40 flex items-center justify-center mx-auto text-sky-400">
              <Lock className="w-6 h-6" />
            </div>
            <h2 className="text-xl font-black text-white">Password Protected File</h2>
            <p className="text-xs text-slate-400 font-mono">
              <strong>{shareInfo.filename}</strong> is protected with end-to-end access authentication.
            </p>
          </div>

          <form onSubmit={handleVerifyPassword} className="space-y-4">
            <div>
              <label className="block text-xs font-semibold text-slate-300 mb-1">
                Enter Decryption Password:
              </label>
              <div className="relative">
                <Key className="w-4 h-4 text-slate-500 absolute left-3 top-3" />
                <input
                  type="password"
                  placeholder="Password..."
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                  autoFocus
                  className="w-full bg-slate-900 border border-slate-700 rounded-xl pl-9 pr-3 py-2.5 text-white text-xs font-mono focus:outline-none focus:border-sky-500"
                />
              </div>
            </div>

            <button
              type="submit"
              disabled={verifying}
              className="btn-cyber w-full py-2.5 rounded-xl text-xs font-bold flex items-center justify-center gap-2"
            >
              {verifying ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Eye className="w-4 h-4" />}
              Unlock & View File
            </button>
          </form>
        </div>
      </div>
    );
  }

  if (!shareInfo) {
    return (
      <div className="w-screen h-screen bg-slate-950 flex flex-col items-center justify-center text-slate-400 font-mono text-xs gap-3">
        <RefreshCw className="w-8 h-8 text-sky-400 animate-spin" />
        <div>CONNECTING TO SECURE CLOUD STORAGE GATEWAY...</div>
      </div>
    );
  }

  const filename = shareInfo?.filename || 'Document';
  const ext = filename.split('.').pop()?.toLowerCase() || '';
  const isPdf = ext === 'pdf';
  const isDocx = ext === 'docx' || ext === 'doc';
  const isPptx = ext === 'pptx' || ext === 'ppt';
  const isXlsx = ext === 'xlsx' || ext === 'xls' || ext === 'csv';
  const isImage = ['jpg', 'jpeg', 'png', 'gif', 'webp', 'svg'].includes(ext);
  const isVideo = ['mp4', 'webm', 'ogg', 'mov'].includes(ext);
  const isAudio = ['mp3', 'wav', 'aac', 'flac'].includes(ext);
  const streamUrl = blobStreamUrl || `${API_BASE_URL}/api/shares/public/${id}/stream`;
  const downloadUrl = `${API_BASE_URL}/api/shares/public/${id}/download`;

  return (
    <div className="w-screen h-screen flex flex-col bg-slate-950 text-slate-100 overflow-hidden select-none">
      {/* Top Standalone Control Header */}
      <header className="h-14 bg-slate-950/95 border-b border-slate-800 px-4 sm:px-6 flex items-center justify-between gap-3 shrink-0 z-30 shadow-xl">
        {/* Left: Branding & File Info */}
        <div className="flex items-center gap-3 truncate">
          <div className="w-8 h-8 rounded-lg bg-sky-950 border border-sky-500/40 flex items-center justify-center text-sky-400 shrink-0">
            {isPdf ? <FileText className="w-4 h-4 text-red-400" /> :
             isPptx ? <Presentation className="w-4 h-4 text-amber-400" /> :
             isDocx ? <FileText className="w-4 h-4 text-blue-400" /> :
             isXlsx ? <FileSpreadsheet className="w-4 h-4 text-emerald-400" /> :
             isImage ? <ImageIcon className="w-4 h-4 text-purple-400" /> :
             isVideo ? <Video className="w-4 h-4 text-cyan-400" /> :
             isAudio ? <Music className="w-4 h-4 text-pink-400" /> :
             <FileText className="w-4 h-4 text-slate-400" />}
          </div>
          <div className="truncate">
            <h1 className="text-sm font-bold text-white tracking-wide truncate flex items-center gap-2">
              {filename}
            </h1>
            <div className="flex items-center gap-2 text-[10px] text-slate-400 font-mono">
              <span>{shareInfo?.file_size_formatted || ''}</span>
              <span>•</span>
              <span className="text-sky-400 font-semibold">{shareInfo?.views_count ?? shareInfo?.view_count ?? 1} views</span>
              <span>•</span>
              <span className="text-emerald-400">Encrypted Stream</span>
            </div>
          </div>
        </div>

        {/* Right: Actions */}
        <div className="flex items-center gap-2 shrink-0">
          {/* External Viewer */}
          <button
            onClick={handlePopoutBlobUrl}
            title="Open in new window"
            className="p-1.5 bg-slate-900 hover:bg-slate-800 text-slate-300 hover:text-white border border-slate-700 rounded-lg transition"
          >
            <ExternalLink className="w-4 h-4" />
          </button>

          {/* Fullscreen */}
          <button
            onClick={toggleBrowserFullscreen}
            title="Toggle Fullscreen"
            className="p-1.5 bg-slate-900 hover:bg-slate-800 text-slate-300 hover:text-white border border-slate-700 rounded-lg transition"
          >
            {isFullscreen ? <Minimize2 className="w-4 h-4" /> : <Maximize2 className="w-4 h-4" />}
          </button>

          {/* Download */}
          {shareInfo?.allow_download && !shareInfo?.view_only && (
            <a
              href={downloadUrl}
              download={filename}
              title="Download Original File"
              className="px-3 py-1.5 bg-sky-600 hover:bg-sky-500 text-white rounded-lg text-xs font-bold flex items-center gap-1 transition shadow"
            >
              <Download className="w-3.5 h-3.5" />
              <span className="hidden sm:inline">Download</span>
            </a>
          )}

          {/* Share Tools */}
          <button
            onClick={handleWhatsAppShare}
            title="Share via WhatsApp"
            className="p-1.5 bg-emerald-950 hover:bg-emerald-900 text-emerald-300 border border-emerald-500/40 rounded-lg transition hidden sm:flex"
          >
            <Send className="w-4 h-4" />
          </button>

          <button
            onClick={handleCopyLink}
            title="Copy Direct Link"
            className="p-1.5 bg-slate-900 hover:bg-slate-800 text-slate-300 hover:text-white border border-slate-700 rounded-lg transition"
          >
            <Copy className="w-4 h-4" />
          </button>
        </div>
      </header>

      {/* Main Full-Viewport Canvas View */}
      <main className="flex-1 w-full h-full relative overflow-hidden bg-slate-950 flex flex-col items-center justify-center">
        {/* PDF Multi-Page Interactive Engine */}
        {isPdf && (
          <iframe
            src={streamUrl}
            className="w-full h-full border-0 bg-white"
            title={filename}
          />
        )}

        {/* PowerPoint Slide Deck Interactive Canvas */}
        {isPptx && (
          <div className="w-full h-full p-2 sm:p-4 flex items-center justify-center">
            <PresentationViewer
              presentationData={viewData}
              filename={filename}
              isFullscreen={true}
            />
          </div>
        )}

        {/* Word Document (.docx / .doc) - Pure White Document Sheet with Black Typography */}
        {isDocx && (
          <div className="w-full h-full overflow-y-auto p-4 sm:p-8 flex justify-center bg-slate-900/80">
            <div className="max-w-4xl w-full bg-white text-slate-950 p-8 sm:p-14 rounded-lg shadow-2xl min-h-full my-auto" style={{ color: '#111827', backgroundColor: '#ffffff' }}>
              <div className="border-b-2 border-slate-200 pb-4 mb-6 flex items-center justify-between">
                <div>
                  <h1 className="text-2xl font-black text-slate-900 tracking-tight">{filename}</h1>
                  <div className="text-xs text-slate-500 mt-1 font-mono">SecureCloud Document Engine • Preserved Structure</div>
                </div>
                <span className="px-2.5 py-1 bg-slate-100 text-slate-800 text-xs font-bold rounded border border-slate-300 font-mono">DOCX</span>
              </div>

              {viewData?.html_content ? (
                <div className="docx-content space-y-4 leading-relaxed" style={{ color: '#111827' }} dangerouslySetInnerHTML={{ __html: viewData.html_content }} />
              ) : viewData?.paragraphs ? (
                <div className="space-y-4">
                  {viewData.paragraphs.map((p, idx) => (
                    <p key={idx} className="leading-relaxed" style={{ color: '#111827' }}>{p.text}</p>
                  ))}
                </div>
              ) : (
                <p className="text-slate-500 italic">Document text contents parsed and ready.</p>
              )}
            </div>
          </div>
        )}

        {/* Excel Spreadsheet Viewer */}
        {isXlsx && (
          <div className="w-full h-full flex flex-col overflow-hidden bg-slate-900">
            {viewData?.sheet_names && viewData.sheet_names.length > 1 && (
              <div className="px-4 py-2 bg-slate-950 border-b border-slate-800 flex items-center gap-2 overflow-x-auto">
                {viewData.sheet_names.map((s) => (
                  <button
                    key={s}
                    onClick={() => setActiveSheet(s)}
                    className={`px-3 py-1 rounded text-xs font-mono font-bold transition ${
                      activeSheet === s ? 'bg-emerald-600 text-white shadow' : 'bg-slate-900 text-slate-400 hover:text-white'
                    }`}
                  >
                    {s}
                  </button>
                ))}
              </div>
            )}
            <div className="flex-1 overflow-auto p-4">
              {viewData?.sheets?.[activeSheet] ? (
                <table className="w-full text-left text-xs border-collapse border border-slate-800 font-mono">
                  <tbody>
                    {viewData.sheets[activeSheet].map((row, rIdx) => (
                      <tr key={rIdx} className={rIdx === 0 ? 'bg-slate-950 font-bold text-emerald-400' : 'hover:bg-slate-800/50'}>
                        {row.map((cell, cIdx) => (
                          <td key={cIdx} className="border border-slate-800 p-2.5 whitespace-nowrap">
                            {cell ?? ''}
                          </td>
                        ))}
                      </tr>
                    ))}
                  </tbody>
                </table>
              ) : (
                <div className="text-center py-20 text-slate-500 font-mono text-xs">Loading Spreadsheet Matrix...</div>
              )}
            </div>
          </div>
        )}

        {/* Image High-Resolution Canvas */}
        {isImage && (
          <div className="w-full h-full flex items-center justify-center p-4 bg-black/90">
            <img
              src={streamUrl}
              alt={filename}
              className="max-h-[90vh] max-w-full object-contain rounded-xl shadow-2xl"
            />
          </div>
        )}

        {/* Video / Audio Media Streamer */}
        {isVideo && (
          <div className="w-full h-full flex items-center justify-center p-4 bg-black/95">
            <video
              src={streamUrl}
              controls
              autoPlay
              className="max-h-[85vh] max-w-full rounded-2xl shadow-2xl"
            />
          </div>
        )}

        {isAudio && (
          <div className="w-full h-full flex items-center justify-center p-6 bg-slate-900">
            <div className="glass-card p-8 max-w-md w-full text-center space-y-4 border border-slate-800 shadow-2xl">
              <Music className="w-16 h-16 text-purple-400 mx-auto" />
              <h3 className="font-bold text-white text-base">{filename}</h3>
              <audio src={streamUrl} controls autoPlay className="w-full mt-4" />
            </div>
          </div>
        )}

        {/* Text / Code File Format */}
        {!isPdf && !isPptx && !isDocx && !isXlsx && !isImage && !isVideo && !isAudio && (
          <div className="w-full h-full overflow-auto p-6 bg-slate-950 font-mono text-xs text-slate-300">
            {viewData?.content ? (
              <pre className="whitespace-pre-wrap leading-relaxed">{viewData.content}</pre>
            ) : (
              <div className="flex flex-col items-center justify-center h-full gap-4 text-center">
                <FileText className="w-16 h-16 text-slate-600" />
                <div className="text-sm font-bold text-white">{filename}</div>
                <p className="text-xs text-slate-400 max-w-sm">Binary file stream ready for inspection or download.</p>
                <button
                  onClick={handlePopoutBlobUrl}
                  className="btn-cyber px-5 py-2.5 rounded-xl text-xs font-bold flex items-center gap-2"
                >
                  <ExternalLink className="w-4 h-4" /> Open Native Blob Stream
                </button>
              </div>
            )}
          </div>
        )}
      </main>
    </div>
  );
}
