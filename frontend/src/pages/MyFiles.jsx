import React, { useEffect, useState, useRef } from 'react';
import { useAuth } from '../context/AuthContext';
import { useApp } from '../context/AppContext';
import { fileApi } from '../api/fileApi';
import { 
  UploadCloud, Search, Filter, HardDrive, FileText, Download, 
  Eye, Edit3, Lock, Share2, Trash2, RefreshCw, Plus, FileSpreadsheet,
  Presentation, Image as ImageIcon, Video, Music, Code, Archive, CheckCircle2, ShieldAlert, Zap
} from 'lucide-react';
import { SecurityBadge } from '../components/SecurityBadge';
import { QuotaBar } from '../components/QuotaBar';
import { FileViewerModal } from '../components/FileViewerModal';
import { PinLockModal } from '../components/PinLockModal';
import { ShareCreateModal } from '../components/ShareCreateModal';
import { RenameModal } from '../components/RenameModal';
import { FileRiskRadarModal } from '../components/FileRiskRadarModal';
import { EmergencyLockdownModal } from '../components/EmergencyLockdownModal';

export function MyFiles() {
  const { user, updateUserQuotaLocally, refreshUser } = useAuth();
  const { openModal, showToast, triggerCriticalAlert } = useApp();

  const [files, setFiles] = useState([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [category, setCategory] = useState('ALL');
  const [uploading, setUploading] = useState(false);
  const [uploadStage, setUploadStage] = useState('');
  const [selectedRadarFile, setSelectedRadarFile] = useState(null);
  const [showLockdownModal, setShowLockdownModal] = useState(false);
  const fileInputRef = useRef(null);

  const loadFiles = async (retryCount = 0) => {
    setLoading(true);
    try {
      const data = await fileApi.listFiles();
      const fileList = Array.isArray(data) ? data : (data.files || []);
      setFiles(fileList);
      if (data && data.storage) {
        updateUserQuotaLocally(data.storage);
      }
    } catch (err) {
      if (retryCount < 2) {
        setTimeout(() => loadFiles(retryCount + 1), 600);
        return;
      }
      showToast(err.message || 'Failed to load files.', 'error');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadFiles();
    const handleUpdate = () => loadFiles();
    window.addEventListener('files:updated', handleUpdate);
    return () => window.removeEventListener('files:updated', handleUpdate);
  }, []);

  const handleFileUpload = async (e) => {
    const selectedFiles = e.target.files;
    if (!selectedFiles || selectedFiles.length === 0) return;

    setUploading(true);
    setUploadStage('HASHING & UPLOADING...');

    for (let i = 0; i < selectedFiles.length; i++) {
      const file = selectedFiles[i];
      const formData = new FormData();
      formData.append('file', file);

      try {
        setUploadStage(`SCANNING (${file.name}): STATIC HEURISTICS • LIGHTGBM INFERENCE...`);
        const res = await fileApi.uploadFile(formData);

        showToast(`File "${file.name}" uploaded and scanned successfully!`, 'success');
        
        if (res.security_status === 'MALICIOUS' || (res.threat_score && res.threat_score >= 80)) {
          triggerCriticalAlert({
            filename: file.name,
            threat_score: res.threat_score,
            verdict: 'MALICIOUS_THREAT',
            file_id: res.file?.id
          });
        }
      } catch (err) {
        showToast(`Upload failed for "${file.name}": ${err.message}`, 'error');
      }
    }

    setUploading(false);
    setUploadStage('');
    if (fileInputRef.current) fileInputRef.current.value = '';
    loadFiles();
    refreshUser();
    window.dispatchEvent(new CustomEvent('files:updated'));
  };

  const handleDelete = async (file) => {
    if (!window.confirm(`Move "${file.filename}" to Recycle Bin?`)) return;
    try {
      await fileApi.deleteFile(file.id);
      showToast(`"${file.filename}" moved to Recycle Bin.`, 'info');
      loadFiles();
      refreshUser();
      window.dispatchEvent(new CustomEvent('files:updated'));
    } catch (err) {
      showToast(err.message || 'Failed to delete file.', 'error');
    }
  };

  const filteredFiles = files.filter((f) => {
    const matchesSearch = f.filename.toLowerCase().includes(search.toLowerCase());
    if (!matchesSearch) return false;

    if (category === 'ALL') return true;
    const ext = f.extension ? f.extension.toLowerCase() : '';
    if (category === 'DOCS') return ['.pdf', '.doc', '.docx', '.txt', '.rtf', '.odt'].includes(ext);
    if (category === 'SHEETS') return ['.xlsx', '.xls', '.csv', '.ods'].includes(ext);
    if (category === 'SLIDES') return ['.pptx', '.ppt', '.odp'].includes(ext);
    if (category === 'MEDIA') return ['.jpg', '.jpeg', '.png', '.gif', '.mp4', '.mov', '.mp3', '.wav'].includes(ext);
    if (category === 'ARCHIVES') return ['.zip', '.tar', '.gz', '.7z', '.rar'].includes(ext);
    if (category === 'CODE') return ['.py', '.js', '.ts', '.html', '.css', '.json', '.sql', '.sh', '.bat', '.ps1'].includes(ext);

    return true;
  });

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-6">
      {/* Storage Quota Bar */}
      <QuotaBar files={files} />

      {/* Action Header Banner */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 glass-card p-4">
        <div>
          <h1 className="text-xl font-black text-white flex items-center gap-2">
            <HardDrive className="w-5 h-5 text-sky-400" />
            Repository Files
          </h1>
          <p className="text-xs text-slate-400">
            Real-time LightGBM AI virus and malware heuristic threat classification engine.
          </p>
        </div>

        <div className="flex items-center gap-2 w-full sm:w-auto">
          <input
            type="file"
            ref={fileInputRef}
            onChange={handleFileUpload}
            multiple
            className="hidden"
          />

          <button
            onClick={() => fileInputRef.current && fileInputRef.current.click()}
            disabled={uploading}
            className="btn-cyber flex-1 sm:flex-initial flex items-center justify-center gap-2"
          >
            {uploading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <UploadCloud className="w-4 h-4" />}
            <span>{uploading ? uploadStage : 'Upload Files'}</span>
          </button>

          <button
            onClick={() => setShowLockdownModal(true)}
            className="px-3.5 py-2.5 rounded-xl text-xs font-bold bg-rose-950/80 hover:bg-rose-900 border border-rose-500/50 text-rose-300 hover:text-white flex items-center gap-1.5 transition shadow-lg shrink-0"
            title="Emergency Vault Quarantine & Revoke All Active Public Links"
          >
            <ShieldAlert className="w-4 h-4 text-rose-400" />
            <span className="hidden md:inline">Lockdown</span>
          </button>

          <button
            onClick={loadFiles}
            className="p-2.5 bg-slate-900 hover:bg-slate-800 text-slate-300 hover:text-white border border-slate-700 rounded-xl transition"
            title="Refresh File List"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-col md:flex-row items-stretch md:items-center justify-between gap-3">
        {/* Category Tabs */}
        <div className="flex items-center gap-1.5 overflow-x-auto pb-1 md:pb-0">
          {[
            { id: 'ALL', label: 'All Files' },
            { id: 'DOCS', label: 'Documents' },
            { id: 'SHEETS', label: 'Sheets' },
            { id: 'SLIDES', label: 'Slides' },
            { id: 'MEDIA', label: 'Media' },
            { id: 'ARCHIVES', label: 'Archives' },
            { id: 'CODE', label: 'Code' }
          ].map((cat) => (
            <button
              key={cat.id}
              onClick={() => setCategory(cat.id)}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold whitespace-nowrap transition ${
                category === cat.id
                  ? 'bg-sky-600 text-white shadow'
                  : 'bg-slate-900/80 text-slate-400 hover:text-white border border-slate-800'
              }`}
            >
              {cat.label}
            </button>
          ))}
        </div>

        {/* Search */}
        <div className="relative min-w-[240px]">
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search by filename..."
            className="w-full bg-slate-900 border border-slate-700 rounded-lg pl-9 pr-3.5 py-1.5 text-xs text-white focus:outline-none focus:border-sky-500"
          />
          <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-2.5" />
        </div>
      </div>

      {/* Files Table */}
      <div className="glass-card overflow-hidden border border-slate-800">
        <div className="overflow-x-auto">
          <table className="soc-table">
            <thead>
              <tr>
                <th>Filename</th>
                <th>File Size</th>
                <th>Security Scan Status</th>
                <th>Version</th>
                <th>Uploaded</th>
                <th className="text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr>
                  <td colSpan="6" className="text-center py-16 text-slate-400 font-mono text-xs">
                    <RefreshCw className="w-5 h-5 animate-spin mx-auto mb-2 text-sky-400" />
                    RETRIEVING ENCRYPTED FILE REGISTRY...
                  </td>
                </tr>
              ) : filteredFiles.length > 0 ? (
                filteredFiles.map((file) => (
                  <tr key={file.id}>
                    <td>
                      <div className="flex items-center gap-2.5">
                        <div className="p-2 rounded-lg bg-slate-900 border border-slate-800 text-sky-400 shrink-0">
                          <FileText className="w-4 h-4" />
                        </div>
                        <div>
                          <div className="font-bold text-white text-xs sm:text-sm hover:text-sky-300 cursor-pointer" onClick={() => openModal('fileViewer', file)}>
                            {file.filename}
                          </div>
                          <div className="text-[10px] text-slate-500 font-mono">
                            {file.mime_type || 'application/octet-stream'}
                          </div>
                        </div>
                      </div>
                    </td>
                    <td className="font-mono text-xs text-slate-300">
                      {file.file_size_formatted || file.size_formatted || `${Math.round((file.file_size || file.size_bytes || 0) / 1024)} KB`}
                    </td>
                    <td>
                      <SecurityBadge status={file.security_status} score={file.threat_score} />
                    </td>
                    <td className="font-mono text-xs text-sky-400">
                      {file.current_version || file.version || 'v1.0'}
                    </td>
                    <td className="font-mono text-xs text-slate-400">
                      {file.created_at ? new Date(file.created_at).toLocaleDateString() : 'Today'}
                    </td>
                    <td className="text-right">
                      <div className="flex items-center justify-end gap-1">
                        <button
                          onClick={() => setSelectedRadarFile(file)}
                          title="Multi-Factor Risk Radar"
                          className="p-1.5 bg-slate-900 hover:bg-indigo-950 text-slate-300 hover:text-indigo-300 border border-slate-800 hover:border-indigo-500/40 rounded-lg transition"
                        >
                          <Zap className="w-4 h-4" />
                        </button>
                        <button
                          onClick={() => openModal('fileViewer', file)}
                          title="View Original Format"
                          className="p-1.5 bg-slate-900 hover:bg-sky-950 text-slate-300 hover:text-sky-300 border border-slate-800 hover:border-sky-500/40 rounded-lg transition"
                        >
                          <Eye className="w-4 h-4" />
                        </button>
                        <a
                          href={fileApi.getDownloadUrl(file.id)}
                          download
                          title="Download"
                          className="p-1.5 bg-slate-900 hover:bg-slate-800 text-slate-300 hover:text-white border border-slate-800 rounded-lg transition"
                        >
                          <Download className="w-4 h-4" />
                        </a>
                        <button
                          onClick={() => openModal('rename', file)}
                          title="Rename File"
                          className="p-1.5 bg-slate-900 hover:bg-slate-800 text-slate-300 hover:text-white border border-slate-800 rounded-lg transition"
                        >
                          <Edit3 className="w-4 h-4" />
                        </button>
                        <button
                          onClick={() => openModal('pinLock', file)}
                          title="Move to Confidential Vault (PIN Lock)"
                          className="p-1.5 bg-slate-900 hover:bg-amber-950 text-slate-300 hover:text-amber-300 border border-slate-800 hover:border-amber-500/40 rounded-lg transition"
                        >
                          <Lock className="w-4 h-4" />
                        </button>
                        <button
                          onClick={() => openModal('shareCreate', file)}
                          title="Generate Expiring Share Link"
                          className="p-1.5 bg-slate-900 hover:bg-cyan-950 text-slate-300 hover:text-cyan-300 border border-slate-800 hover:border-cyan-500/40 rounded-lg transition"
                        >
                          <Share2 className="w-4 h-4" />
                        </button>
                        <button
                          onClick={() => handleDelete(file)}
                          title="Move to Recycle Bin"
                          className="p-1.5 bg-slate-900 hover:bg-red-950 text-slate-300 hover:text-red-300 border border-slate-800 hover:border-red-500/40 rounded-lg transition"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan="6" className="text-center py-12 text-slate-500 text-xs">
                    No files found matching your filter criteria. Click "Upload Files" to get started.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Global Modals for File Page */}
      <FileViewerModal />
      <PinLockModal onSuccess={loadFiles} />
      <ShareCreateModal />
      <RenameModal onSuccess={loadFiles} />
      <FileRiskRadarModal
        file={selectedRadarFile}
        isOpen={!!selectedRadarFile}
        onClose={() => setSelectedRadarFile(null)}
      />
      <EmergencyLockdownModal
        isOpen={showLockdownModal}
        onClose={() => {
          setShowLockdownModal(false);
          loadFiles();
        }}
      />
    </div>
  );
}
