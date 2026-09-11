import React, { useEffect, useState } from 'react';
import { useApp } from '../context/AppContext';
import { useAuth } from '../context/AuthContext';
import { fileApi } from '../api/fileApi';
import { 
  X, Download, ExternalLink, ShieldCheck, ShieldAlert, AlertTriangle, 
  FileText, FileSpreadsheet, Presentation, Image as ImageIcon, Video, Music, Code,
  FolderArchive, Layers, Eye, Maximize2, RefreshCw, KeyRound, Terminal, Binary, Shield
} from 'lucide-react';
import { SecurityBadge } from './SecurityBadge';
import { PresentationViewer } from './PresentationViewer';

export function FileViewerModal() {
  const { activeModal, modalData, closeModal, openModal } = useApp();
  const { user: currentUser } = useAuth();
  const [loading, setLoading] = useState(false);
  const [viewData, setViewData] = useState(null);
  const [error, setError] = useState(null);
  const [activeSheet, setActiveSheet] = useState('');
  const [fontSize, setFontSize] = useState(14);
  const [blobStreamUrl, setBlobStreamUrl] = useState(null);
  const [imageError, setImageError] = useState(false);

  const isAdmin = currentUser?.role?.toUpperCase() === 'ADMIN';

  useEffect(() => {
    let currentBlob = null;
    setImageError(false);

    if (activeModal === 'fileViewer' && modalData) {
      const targetId = modalData.id || modalData.file_id;
      const fn = modalData.filename || modalData.original_filename || '';
      const ext = (fn.substring(fn.lastIndexOf('.')) || '').toLowerCase();
      const isMedia = ['.pdf', '.png', '.jpg', '.jpeg', '.gif', '.webp', '.svg', '.bmp', '.ico', '.mp3', '.wav', '.ogg', '.mp4', '.webm', '.mov', '.avi'].includes(ext);

      if (modalData.is_unlocked && modalData.viewPayload) {
        // Direct in-memory decrypted view payload
        const payload = modalData.viewPayload;
        setViewData(payload);
        if (payload.sheet_names && payload.sheet_names.length > 0) {
          setActiveSheet(payload.sheet_names[0]);
        }
        if (payload.stream_url) {
          setBlobStreamUrl(payload.stream_url);
        }
        setLoading(false);
      } else if (isMedia) {
        // Instant native media streaming - eliminate all blocking load delays
        const streamUrl = fileApi.getStreamUrl(targetId);
        setViewData({
          format: 'STREAMABLE_MEDIA',
          filename: fn,
          stream_url: streamUrl,
          file_size: modalData.file_size || 0
        });
        setBlobStreamUrl(streamUrl);
        setLoading(false);

        // Fetch deep telemetry / metadata non-blockingly in background
        fileApi.viewFile(targetId)
          .then(data => {
            if (data && data.format !== 'CONFIDENTIAL_LOCKED') {
              setViewData(prev => ({ ...prev, ...data }));
            }
          })
          .catch(() => {});
      } else if (targetId) {
        loadFile(targetId);
      }
    } else {
      setViewData(null);
      setError(null);
      setActiveSheet('');
      if (blobStreamUrl && blobStreamUrl.startsWith('blob:')) {
        URL.revokeObjectURL(blobStreamUrl);
      }
      setBlobStreamUrl(null);
    }

    return () => {
      if (currentBlob && currentBlob.startsWith('blob:')) {
        URL.revokeObjectURL(currentBlob);
      }
    };
  }, [activeModal, modalData]);

  const loadFile = async (fileId) => {
    setLoading(true);
    setError(null);
    try {
      const data = await fileApi.viewFile(fileId);
      setViewData(data);
      if (data && data.sheet_names && data.sheet_names.length > 0) {
        setActiveSheet(data.sheet_names[0]);
      }
      if (data && data.stream_url) {
        setBlobStreamUrl(data.stream_url);
      }
    } catch (err) {
      setError(err.message || 'Failed to render file preview.');
    } finally {
      setLoading(false);
    }
  };

  if (activeModal !== 'fileViewer' || !modalData) return null;

  const targetFileId = modalData.id || modalData.file_id;
  const downloadUrl = fileApi.getDownloadUrl(targetFileId);
  const activeStreamUrl = blobStreamUrl || (viewData?.stream_url) || fileApi.getStreamUrl(targetFileId);

  const filename = viewData?.filename || modalData.filename || modalData.original_filename || 'Document';
  const ext = (filename.substring(filename.lastIndexOf('.')) || '').toLowerCase();
  const mime = modalData.mime_type || viewData?.mime_type || '';

  const isPdf = ext === '.pdf' || mime.includes('pdf');
  const isImage = ['.png', '.jpg', '.jpeg', '.gif', '.webp', '.svg', '.bmp', '.ico'].includes(ext) || mime.startsWith('image/');
  const isVideo = ['.mp4', '.webm', '.mov', '.avi', '.mkv'].includes(ext) || mime.startsWith('video/');
  const isAudio = ['.mp3', '.wav', '.ogg', '.flac', '.m4a'].includes(ext) || mime.startsWith('audio/');
  const isDocx = ['.docx', '.doc'].includes(ext) || viewData?.format === 'DOCX_RENDERED' || viewData?.format === 'DOCX_FORMATTED';
  const isXlsx = ['.xlsx', '.xls'].includes(ext) || viewData?.format === 'XLSX_RENDERED';
  const isCsv = ext === '.csv' || viewData?.format === 'CSV_TABLE';
  const isPptx = ['.pptx', '.ppt', '.pps', '.ppsx', '.odp', '.pot', '.potx'].includes(ext) || viewData?.format === 'PRESENTATION_RENDERED' || viewData?.format === 'PPTX_RENDERED';
  const isZip = ['.zip', '.rar', '.7z', '.tar', '.gz'].includes(ext) || viewData?.format === 'ZIP_TREE';
  const isText = ['.txt', '.log', '.md', '.py', '.js', '.ts', '.html', '.css', '.sh', '.bat', '.ps1', '.java', '.c', '.cpp', '.sql', '.json', '.xml', '.yaml', '.yml', '.env'].includes(ext) || viewData?.format === 'TEXT' || viewData?.format === 'JSON';
  const isBinaryInspector = viewData?.format === 'BINARY_INSPECTOR' || ['.exe', '.dll', '.bin', '.elf', '.iso', '.sys'].includes(ext);

  // Determine if Admin is viewing another user's confidential file
  const isOwner = currentUser && (modalData.user_id === currentUser.id || modalData.owner_id === currentUser.id);
  const isAdminBlocked = isAdmin && !isOwner && (modalData.is_confidential || viewData?.format === 'CONFIDENTIAL_LOCKED');

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-2 sm:p-4 bg-black/90 backdrop-blur-md overflow-y-auto">
      <div className="glass-card w-full max-w-6xl max-h-[94vh] flex flex-col rounded-2xl border border-slate-700 shadow-2xl overflow-hidden animate-scale-up">
        {/* Modal Header */}
        <div className="p-3 sm:px-6 bg-slate-900 border-b border-slate-800 flex items-center justify-between gap-3 shrink-0">
          <div className="flex items-center gap-3 overflow-hidden">
            <div className="p-2.5 rounded-xl bg-sky-950/80 border border-sky-500/30 text-sky-400 shrink-0">
              {isPdf && <FileText className="w-5 h-5 text-red-400" />}
              {isDocx && <FileText className="w-5 h-5 text-sky-400" />}
              {(isXlsx || isCsv) && <FileSpreadsheet className="w-5 h-5 text-emerald-400" />}
              {isPptx && <Presentation className="w-5 h-5 text-orange-400" />}
              {isImage && <ImageIcon className="w-5 h-5 text-purple-400" />}
              {isVideo && <Video className="w-5 h-5 text-amber-400" />}
              {isAudio && <Music className="w-5 h-5 text-pink-400" />}
              {isZip && <FolderArchive className="w-5 h-5 text-yellow-400" />}
              {isText && <Code className="w-5 h-5 text-teal-400" />}
              {isBinaryInspector && <Binary className="w-5 h-5 text-red-400" />}
              {!isPdf && !isDocx && !isXlsx && !isCsv && !isPptx && !isImage && !isVideo && !isAudio && !isZip && !isText && !isBinaryInspector && (
                <FileText className="w-5 h-5 text-slate-400" />
              )}
            </div>
            <div className="truncate">
              <h3 className="text-sm sm:text-base font-bold text-white truncate">
                {filename}
              </h3>
              <div className="flex items-center gap-2 mt-0.5 text-xs text-slate-400 font-mono">
                <span>{modalData.file_size_formatted || modalData.size_formatted || `${Math.round((modalData.file_size || modalData.size_bytes || 0) / 1024)} KB`}</span>
                <span>•</span>
                <span className="uppercase">{ext.replace('.', '') || 'FILE'}</span>
                <span>•</span>
                <SecurityBadge status={modalData.security_status} score={modalData.threat_score} />
              </div>
            </div>
          </div>

          <div className="flex items-center gap-2 shrink-0">
            {/* View Outside Web Page / Native Tab */}
            {activeStreamUrl && (isPdf || isImage || isVideo || isAudio) && !imageError && (
              <a
                href={activeStreamUrl}
                target="_blank"
                rel="noreferrer"
                title="Open in new native tab"
                className="px-2.5 py-1.5 bg-slate-800 hover:bg-slate-700 text-sky-300 hover:text-white border border-slate-700 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition"
              >
                <ExternalLink className="w-3.5 h-3.5" />
                <span className="hidden md:inline">Fullscreen</span>
              </a>
            )}

            {!isAdminBlocked && (
              <a
                href={downloadUrl}
                download={filename}
                className="px-3 py-1.5 bg-sky-600 hover:bg-sky-500 text-white rounded-lg text-xs font-semibold flex items-center gap-1.5 transition shadow-md"
              >
                <Download className="w-3.5 h-3.5" />
                <span className="hidden sm:inline">Download</span>
              </a>
            )}

            <button
              onClick={closeModal}
              className="p-1.5 bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white rounded-lg transition"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Modal Body / Viewer Content */}
        <div className="flex-1 p-3 sm:p-6 overflow-y-auto bg-slate-950/90">
          {loading && (
            <div className="flex flex-col items-center justify-center py-24 text-slate-400">
              <RefreshCw className="w-8 h-8 text-sky-400 animate-spin mb-3" />
              <span className="text-xs font-mono tracking-wider">DECODING ORIGINAL FILE STREAM & PRESERVING FORMAT...</span>
            </div>
          )}

          {error && (
            <div className="p-6 rounded-xl bg-red-950/40 border border-red-500/40 text-red-200 text-center my-6 max-w-lg mx-auto">
              <AlertTriangle className="w-8 h-8 text-red-400 mx-auto mb-2" />
              <h4 className="font-bold text-sm">Preview Notice</h4>
              <p className="text-xs mt-1 text-red-300">{error}</p>
              <div className="mt-4 flex items-center justify-center gap-2">
                <a
                  href={downloadUrl}
                  download={filename}
                  className="inline-flex items-center gap-1.5 px-4 py-2 bg-slate-800 hover:bg-slate-700 text-sky-300 border border-slate-700 rounded-lg text-xs font-semibold"
                >
                  <Download className="w-4 h-4" /> Download File
                </a>
              </div>
            </div>
          )}

          {/* Admin Restricted Confidential Notice */}
          {isAdminBlocked && !loading && (
            <div className="max-w-lg mx-auto p-8 rounded-2xl glass-card border border-amber-500/50 text-center my-8 shadow-2xl bg-gradient-to-b from-slate-900 to-amber-950/20">
              <div className="w-16 h-16 bg-amber-950/90 border border-amber-500/50 rounded-2xl flex items-center justify-center mx-auto mb-4 text-amber-400 shadow-lg">
                <ShieldAlert className="w-8 h-8" />
              </div>
              <h4 className="font-bold text-white text-base mb-2">Confidential Zero-Knowledge Vault</h4>
              <div className="p-3 bg-amber-950/60 border border-amber-500/30 rounded-xl text-xs text-amber-200 font-mono mb-4 text-left leading-relaxed">
                ⛔ <strong>Admin Access Restricted:</strong> System administrators cannot access, view, or decrypt client-side encrypted confidential files without the owner's secret private key / PIN.
              </div>
              <p className="text-xs text-slate-400 leading-relaxed font-mono">
                Zero-Knowledge Cryptographic Isolation is maintained. Only the file owner possessing the client-side PIN can decrypt this content.
              </p>
            </div>
          )}

          {/* User Confidential Unlock Prompt */}
          {!isAdminBlocked && viewData?.format === 'CONFIDENTIAL_LOCKED' && !loading && (
            <div className="max-w-md mx-auto p-8 rounded-2xl glass-card border border-amber-500/40 text-center my-8 shadow-2xl">
              <div className="w-14 h-14 bg-amber-950/80 border border-amber-500/40 rounded-2xl flex items-center justify-center mx-auto mb-4 text-amber-400">
                <KeyRound className="w-7 h-7" />
              </div>
              <h4 className="font-bold text-white text-base mb-2">Confidential Zero-Knowledge File</h4>
              <p className="text-xs text-slate-400 mb-6 leading-relaxed">
                This document is encrypted with client-side AES-256-GCM. Enter your secret PIN to unlock and decrypt the content in-memory.
              </p>
              <button
                onClick={() => {
                  closeModal();
                  openModal('pinUnlock', { ...modalData, action: 'view' });
                }}
                className="w-full py-2.5 px-4 bg-amber-600 hover:bg-amber-500 text-white rounded-xl text-xs font-bold flex items-center justify-center gap-2 transition shadow-lg"
              >
                <KeyRound className="w-4 h-4" />
                Unlock with Secret PIN
              </button>
            </div>
          )}

          {viewData && !loading && !isAdminBlocked && viewData.format !== 'CONFIDENTIAL_LOCKED' && (
            <div className="w-full">
              {/* 1. PDF Document Rendering */}
              {(isPdf || viewData.format === 'PDF_VIEW' || (viewData.format === 'STREAMABLE_MEDIA' && isPdf)) && (
                <div className="w-full h-[78vh] rounded-xl overflow-hidden border border-slate-700 bg-slate-900 shadow-2xl flex flex-col">
                  <div className="px-4 py-2 bg-slate-900 border-b border-slate-800 flex items-center justify-between text-xs text-slate-400 font-mono">
                    <span className="flex items-center gap-2">
                      <FileText className="w-4 h-4 text-red-400" />
                      PDF Multi-Page Interactive Engine
                    </span>
                    <a
                      href={activeStreamUrl}
                      target="_blank"
                      rel="noreferrer"
                      className="text-sky-400 hover:text-sky-300 flex items-center gap-1"
                    >
                      <Maximize2 className="w-3 h-3" />
                      Pop-out View
                    </a>
                  </div>
                  <iframe
                    src={activeStreamUrl}
                    className="w-full flex-1 border-0 bg-white"
                    title={filename}
                  />
                </div>
              )}

              {/* 2. Word Document (.docx / .doc) — Pure White Document Sheet with Crisp Black Typography */}
              {(isDocx || viewData.format === 'DOCX_RENDERED' || viewData.format === 'DOCX_FORMATTED') && (
                <div className="max-w-4xl mx-auto space-y-4">
                  <div className="flex items-center justify-between px-2 text-xs text-slate-400 font-mono">
                    <span>Document View • Pure White Sheet Rendering</span>
                    <div className="flex items-center gap-2">
                      <span>Font Size:</span>
                      <button onClick={() => setFontSize(Math.max(12, fontSize - 1))} className="px-2 py-0.5 bg-slate-800 hover:bg-slate-700 rounded text-white">-</button>
                      <span>{fontSize}px</span>
                      <button onClick={() => setFontSize(Math.min(22, fontSize + 1))} className="px-2 py-0.5 bg-slate-800 hover:bg-slate-700 rounded text-white">+</button>
                    </div>
                  </div>

                  {/* Pure White Document Sheet */}
                  <div 
                    className="bg-white text-slate-950 p-8 sm:p-14 rounded-lg shadow-2xl border border-slate-300 min-h-[75vh]"
                    style={{ fontSize: `${fontSize}px`, color: '#111827', backgroundColor: '#ffffff' }}
                  >
                    <div className="border-b-2 border-slate-200 pb-4 mb-6 flex items-center justify-between">
                      <div>
                        <h1 className="text-2xl font-black text-slate-900 tracking-tight">{filename}</h1>
                        <div className="text-xs text-slate-500 mt-1 font-mono">
                          SecureCloud Document Engine • {viewData.paragraph_count || viewData.paragraphs?.length || 0} Paragraphs Preserved
                        </div>
                      </div>
                      <span className="px-2.5 py-1 bg-slate-100 text-slate-800 text-xs font-bold rounded border border-slate-300 font-mono">
                        DOCX
                      </span>
                    </div>

                    {viewData.html_content && viewData.html_content.trim().length > 0 ? (
                      <div 
                        className="docx-content space-y-4 leading-relaxed"
                        style={{ color: '#111827' }}
                        dangerouslySetInnerHTML={{ __html: viewData.html_content }}
                      />
                    ) : viewData.paragraphs && viewData.paragraphs.length > 0 ? (
                      <div className="space-y-4">
                        {viewData.paragraphs.map((p, idx) => (
                          <p key={idx} className="leading-relaxed" style={{ color: '#111827' }}>
                            {p.text}
                          </p>
                        ))}
                      </div>
                    ) : (
                      <p className="text-slate-500 italic">No text content could be extracted from this document.</p>
                    )}

                    {viewData.tables && viewData.tables.length > 0 && (
                      <div className="mt-8 space-y-6">
                        <h3 className="text-sm font-bold text-slate-900 uppercase tracking-wider border-b border-slate-200 pb-2">Document Tables</h3>
                        {viewData.tables.map((tbl, tIdx) => (
                          <div key={tIdx} className="overflow-x-auto border border-slate-300 rounded-lg">
                            <table className="w-full text-xs text-left border-collapse">
                              <tbody>
                                {tbl.map((row, rIdx) => (
                                  <tr key={rIdx} className={rIdx === 0 ? "bg-slate-100 font-bold border-b border-slate-300" : "border-b border-slate-200"}>
                                    {row.map((cell, cIdx) => (
                                      <td key={cIdx} className="p-2.5 border-r border-slate-200 text-slate-900" style={{ color: '#111827' }}>
                                        {cell}
                                      </td>
                                    ))}
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* 3. Spreadsheet / Excel Sheet / CSV Table */}
              {(isXlsx || isCsv || viewData.format === 'XLSX_RENDERED' || viewData.format === 'CSV_TABLE') && (
                <div className="glass-card overflow-hidden border border-slate-800 shadow-2xl">
                  {viewData.sheet_names && viewData.sheet_names.length > 1 && (
                    <div className="flex items-center gap-1 p-2 bg-slate-900 border-b border-slate-800 overflow-x-auto">
                      {viewData.sheet_names.map((name) => (
                        <button
                          key={name}
                          onClick={() => setActiveSheet(name)}
                          className={`px-3 py-1.5 text-xs rounded-lg font-mono transition ${
                            activeSheet === name
                              ? 'bg-sky-600 text-white font-bold'
                              : 'bg-slate-800 text-slate-400 hover:bg-slate-700 hover:text-slate-200'
                          }`}
                        >
                          {name}
                        </button>
                      ))}
                    </div>
                  )}

                  <div className="p-3 bg-slate-900/90 border-b border-slate-800 flex items-center justify-between text-xs font-mono text-slate-400">
                    <span className="flex items-center gap-2">
                      <FileSpreadsheet className="w-4 h-4 text-emerald-400" />
                      {activeSheet ? `Sheet: ${activeSheet}` : 'Spreadsheet Data Grid'}
                    </span>
                    <span>
                      {viewData.sheets && activeSheet && viewData.sheets[activeSheet]
                        ? `${viewData.sheets[activeSheet].length} Rows`
                        : viewData.rows ? `${viewData.rows.length} Rows` : 'Tabular Grid'}
                    </span>
                  </div>

                  <div className="overflow-x-auto max-h-[68vh]">
                    <table className="w-full text-xs text-left border-collapse">
                      <thead>
                        <tr className="bg-slate-900 text-slate-300 border-b border-slate-700 sticky top-0">
                          <th className="p-2 text-center text-slate-500 font-mono w-12 border-r border-slate-800">#</th>
                          {((viewData.sheets && activeSheet && viewData.sheets[activeSheet] && viewData.sheets[activeSheet][0]) || (viewData.rows && viewData.rows[0]) || []).map((col, idx) => (
                            <th key={idx} className="p-2 font-mono text-sky-400 border-r border-slate-800 uppercase tracking-wider">
                              Col {String.fromCharCode(65 + (idx % 26))}
                            </th>
                          ))}
                        </tr>
                      </thead>
                      <tbody>
                        {((viewData.sheets && activeSheet && viewData.sheets[activeSheet]) || viewData.rows || []).map((row, rIdx) => (
                          <tr key={rIdx} className="border-b border-slate-800/80 hover:bg-slate-900/60 transition">
                            <td className="p-2 text-center text-slate-600 font-mono bg-slate-900/40 border-r border-slate-800">{rIdx + 1}</td>
                            {row.map((cell, cIdx) => (
                              <td key={cIdx} className="p-2 text-slate-200 font-mono border-r border-slate-800/60 whitespace-nowrap">
                                {cell}
                              </td>
                            ))}
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {/* 4. Exact Visual Presentation Viewer (PPTX / PPT / ODP) */}
              {(isPptx || viewData.format === 'PRESENTATION_RENDERED' || viewData.format === 'PPTX_RENDERED') && (
                <PresentationViewer
                  data={viewData}
                  filename={filename}
                  downloadUrl={downloadUrl}
                />
              )}

              {/* 5. Image Preview with Safe Error Recovery */}
              {(isImage || (viewData.format === 'STREAMABLE_MEDIA' && isImage) || viewData.format === 'IMAGE_PREVIEW') && (
                <div className="flex flex-col items-center justify-center py-4">
                  {imageError ? (
                    <div className="glass-card max-w-md mx-auto p-8 text-center border border-slate-700 shadow-2xl">
                      <ImageIcon className="w-14 h-14 text-purple-400 mx-auto mb-3 opacity-70" />
                      <h4 className="font-bold text-white text-sm mb-1">{filename}</h4>
                      <p className="text-xs text-slate-400 mb-4 font-mono">
                        {modalData.file_size_formatted || modalData.size_formatted || 'Image File'} • PNG / Image Binary
                      </p>
                      <a
                        href={downloadUrl}
                        download={filename}
                        className="px-4 py-2 bg-purple-600 hover:bg-purple-500 text-white rounded-lg text-xs font-bold inline-flex items-center gap-1.5 transition"
                      >
                        <Download className="w-4 h-4" /> Download Raw Image
                      </a>
                    </div>
                  ) : (
                    <div className="p-2 bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl max-w-full">
                      <img
                        src={activeStreamUrl}
                        alt={filename}
                        onError={() => setImageError(true)}
                        className="max-h-[70vh] max-w-full rounded-xl object-contain shadow-inner"
                      />
                    </div>
                  )}
                </div>
              )}

              {/* 6. Video Player */}
              {(isVideo || (viewData.format === 'STREAMABLE_MEDIA' && isVideo) || viewData.format === 'VIDEO_PLAYER') && (
                <div className="flex justify-center items-center py-4">
                  <video
                    controls
                    autoPlay={false}
                    className="max-h-[70vh] max-w-full rounded-2xl shadow-2xl border border-slate-800 bg-black"
                  >
                    <source src={activeStreamUrl} type={mime || 'video/mp4'} />
                    Your browser does not support HTML5 video playback.
                  </video>
                </div>
              )}

              {/* 7. Audio Player */}
              {(isAudio || (viewData.format === 'STREAMABLE_MEDIA' && isAudio) || viewData.format === 'AUDIO_PLAYER') && (
                <div className="glass-card max-w-lg mx-auto p-8 text-center my-8 border border-pink-500/30 bg-gradient-to-b from-slate-900 to-pink-950/20">
                  <Music className="w-16 h-16 text-pink-400 mx-auto mb-4 animate-pulse" />
                  <h4 className="font-bold text-white text-base mb-1">{filename}</h4>
                  <div className="text-xs text-slate-400 font-mono mb-6">Original High-Fidelity Audio Stream</div>
                  <audio controls className="w-full">
                    <source src={activeStreamUrl} type={mime || 'audio/mpeg'} />
                    Your browser does not support HTML5 audio playback.
                  </audio>
                </div>
              )}

              {/* 8. Plaintext / Code / JSON / Markdown */}
              {(isText || viewData.format === 'TEXT' || viewData.format === 'JSON') && (
                <div className="glass-card rounded-xl border border-slate-800 overflow-hidden shadow-2xl">
                  <div className="px-4 py-2 bg-slate-900 border-b border-slate-800 flex items-center justify-between text-xs text-slate-400 font-mono">
                    <span>Syntax View • UTF-8 Source</span>
                    <span>{viewData.content?.length || 0} Characters</span>
                  </div>
                  <div className="p-4 bg-slate-950 font-mono text-xs text-slate-200 overflow-x-auto max-h-[70vh] leading-relaxed">
                    <pre className="whitespace-pre-wrap">{viewData.content || viewData.text || 'Empty file content.'}</pre>
                  </div>
                </div>
              )}

              {/* 9. ZIP Archive Hierarchy Tree */}
              {(isZip || viewData.format === 'ZIP_TREE') && (
                <div className="glass-card rounded-xl border border-slate-800 overflow-hidden shadow-2xl">
                  <div className="px-4 py-2.5 bg-slate-900 border-b border-slate-800 flex items-center justify-between text-xs text-slate-400 font-mono">
                    <span className="flex items-center gap-2">
                      <FolderArchive className="w-4 h-4 text-yellow-400" />
                      Archive Contents Listing
                    </span>
                    <span>{viewData.total_entries || viewData.entries?.length || 0} Entries</span>
                  </div>
                  <div className="overflow-x-auto max-h-[65vh]">
                    <table className="soc-table">
                      <thead>
                        <tr>
                          <th>File / Folder Path</th>
                          <th>Uncompressed Size</th>
                          <th>Compressed</th>
                          <th>Type</th>
                        </tr>
                      </thead>
                      <tbody>
                        {(viewData.entries || []).map((entry, idx) => (
                          <tr key={idx}>
                            <td className="font-mono text-xs text-white flex items-center gap-2">
                              {entry.is_dir ? (
                                <FolderArchive className="w-4 h-4 text-yellow-400 shrink-0" />
                              ) : (
                                <FileText className="w-4 h-4 text-slate-400 shrink-0" />
                              )}
                              {entry.filename}
                            </td>
                            <td className="font-mono text-xs text-slate-300">{entry.size_formatted || `${entry.size_bytes} B`}</td>
                            <td className="font-mono text-xs text-slate-400">{entry.compressed_size ? `${entry.compressed_size} B` : '-'}</td>
                            <td className="font-mono text-xs text-sky-400">{entry.is_dir ? 'Directory' : 'File'}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {/* 10. Binary & PE Executable Disassembly Inspector */}
              {(isBinaryInspector || viewData.format === 'BINARY_INSPECTOR') && (
                <div className="space-y-6">
                  {/* Hex Dump Section */}
                  <div className="glass-card rounded-xl border border-slate-800 overflow-hidden shadow-2xl">
                    <div className="px-4 py-2.5 bg-slate-900 border-b border-slate-800 flex items-center justify-between text-xs font-mono text-slate-300">
                      <span className="flex items-center gap-2 text-sky-400">
                        <Terminal className="w-4 h-4" /> Hexadecimal Memory Stream (First 512 Bytes)
                      </span>
                      <span>SHA-256: {viewData.file_hash?.substring(0, 16)}...</span>
                    </div>
                    <div className="p-4 bg-slate-950 font-mono text-[11px] text-emerald-400 overflow-x-auto leading-relaxed">
                      <pre className="whitespace-pre">{viewData.hex_dump || '00000000  4D 5A 90 00 03 00 00 00  04 00 00 00 FF FF 00 00  |MZ..............|'}</pre>
                    </div>
                  </div>

                  {/* Printable Extracted ASCII Strings */}
                  {viewData.strings && viewData.strings.length > 0 && (
                    <div className="glass-card rounded-xl border border-slate-800 overflow-hidden shadow-2xl">
                      <div className="px-4 py-2.5 bg-slate-900 border-b border-slate-800 flex items-center justify-between text-xs font-mono text-slate-300">
                        <span className="flex items-center gap-2 text-amber-400">
                          <Code className="w-4 h-4" /> Extracted Printable ASCII Strings ({viewData.strings.length})
                        </span>
                        <span className="text-slate-400">Static Binary Inspection</span>
                      </div>
                      <div className="p-4 bg-slate-950 font-mono text-xs text-slate-300 max-h-48 overflow-y-auto space-y-1">
                        {viewData.strings.map((str, idx) => (
                          <div key={idx} className="flex items-center gap-2">
                            <span className="text-slate-600 font-mono text-[10px] w-8">[{idx + 1}]</span>
                            <span className="text-slate-200">{str}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
