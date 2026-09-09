import React, { useState, useEffect, useRef } from 'react';
import { adminApi } from '../../api/adminApi';
import { fileApi } from '../../api/fileApi';
import { useApp } from '../../context/AppContext';
import { useAuth } from '../../context/AuthContext';
import {
  UploadCloud, FileText, CheckCircle2, AlertTriangle, ShieldAlert,
  Shield, User, Users, RefreshCw, X, ArrowRight, Eye, Info, Database,
  HardDrive, Lock, ShieldCheck, Check, Sparkles, Download
} from 'lucide-react';
import { AdminIngestionModal } from '../../components/AdminIngestionModal';
import { FileViewerModal } from '../../components/FileViewerModal';

export function AdminFileUpload() {
  const { showToast, triggerCriticalAlert, openModal } = useApp();
  const { user: currentAdmin } = useAuth();
  const [users, setUsers] = useState([]);
  const [loadingUsers, setLoadingUsers] = useState(true);
  const [selectedUserId, setSelectedUserId] = useState('');
  const [searchUser, setSearchUser] = useState('');
  
  const [stagedFiles, setStagedFiles] = useState([]);
  const [uploading, setUploading] = useState(false);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [currentStage, setCurrentStage] = useState('');
  const [ingestionHistory, setIngestionHistory] = useState([]);
  
  const [userFiles, setUserFiles] = useState([]);
  const [loadingUserFiles, setLoadingUserFiles] = useState(false);
  
  const fileInputRef = useRef(null);

  // Load registered users list (excluding other admins)
  const loadUsers = async () => {
    setLoadingUsers(true);
    try {
      const data = await adminApi.listUsers();
      const allUsers = data || [];
      setUsers(allUsers);
      const validTargets = allUsers.filter(u => u.role !== 'ADMIN' || u.id === currentAdmin?.id);
      let targetId = selectedUserId;
      if (validTargets.length > 0 && (!selectedUserId || !validTargets.some(u => u.id.toString() === selectedUserId))) {
        targetId = validTargets[0].id.toString();
        setSelectedUserId(targetId);
      }
      if (targetId) {
        loadUserFiles(targetId);
      }
    } catch (err) {
      showToast(err.message || 'Failed to load users list.', 'error');
    } finally {
      setLoadingUsers(false);
    }
  };

  const loadUserFiles = async (userId) => {
    if (!userId) {
      setUserFiles([]);
      return;
    }
    setLoadingUserFiles(true);
    try {
      const data = await adminApi.getUserFiles(userId);
      setUserFiles(Array.isArray(data) ? data : (data.files || []));
    } catch (err) {
      console.warn("Could not load user files:", err);
      setUserFiles([]);
    } finally {
      setLoadingUserFiles(false);
    }
  };

  useEffect(() => {
    loadUsers();
  }, []);

  useEffect(() => {
    if (selectedUserId) {
      loadUserFiles(selectedUserId);
    }
  }, [selectedUserId]);

  useEffect(() => {
    const handleFilesUpdated = () => {
      loadUsers();
      if (selectedUserId) loadUserFiles(selectedUserId);
    };
    window.addEventListener('files:updated', handleFilesUpdated);
    return () => window.removeEventListener('files:updated', handleFilesUpdated);
  }, [selectedUserId]);

  const handleFileDrop = (e) => {
    e.preventDefault();
    const files = Array.from(e.dataTransfer.files || []);
    if (files.length > 0) {
      setStagedFiles(prev => [...prev, ...files]);
    }
  };

  const handleFileSelect = (e) => {
    const files = Array.from(e.target.files || []);
    if (files.length > 0) {
      setStagedFiles(prev => [...prev, ...files]);
    }
  };

  const removeStagedFile = (idx) => {
    setStagedFiles(prev => prev.filter((_, i) => i !== idx));
  };

  const selectedUserObj = users.find(u => u.id.toString() === selectedUserId);

  const handleStartIngestion = async () => {
    if (!selectedUserId) {
      showToast('Please select a target user account first.', 'warning');
      return;
    }
    if (stagedFiles.length === 0) {
      showToast('Please stage at least one file to upload.', 'warning');
      return;
    }

    setUploading(true);
    setUploadProgress(10);
    setCurrentStage('INITIALIZING SECURE ENCLAVE & VIRUS PIPELINE...');

    try {
      const results = [];
      const total = stagedFiles.length;

      for (let i = 0; i < total; i++) {
        const file = stagedFiles[i];
        
        setCurrentStage(`[${i+1}/${total}] STAGE 1/4: SHA-256 HASHING (${file.name})...`);
        setUploadProgress(Math.round(((i * 4 + 1) / (total * 4)) * 100));
        await new Promise(r => setTimeout(r, 200));

        setCurrentStage(`[${i+1}/${total}] STAGE 2/4: STATIC HEURISTICS & ENTROPY SCAN...`);
        setUploadProgress(Math.round(((i * 4 + 2) / (total * 4)) * 100));
        await new Promise(r => setTimeout(r, 200));

        setCurrentStage(`[${i+1}/${total}] STAGE 3/4: LIGHTGBM EMBER2024 INFERENCE...`);
        setUploadProgress(Math.round(((i * 4 + 3) / (total * 4)) * 100));

        const formData = new FormData();
        formData.append('target_user_id', selectedUserId);
        formData.append('file', file);

        const res = await adminApi.uploadFileForUser(formData);
        
        setCurrentStage(`[${i+1}/${total}] STAGE 4/4: REPOSITORY INDEXED.`);
        setUploadProgress(Math.round(((i * 4 + 4) / (total * 4)) * 100));

        if (res.scan && res.scan.security_status === 'MALICIOUS') {
          triggerCriticalAlert({
            filename: file.name,
            threat_score: res.scan.threat_score || 85.0
          });
        }

        results.push({
          ...res.file,
          scan: res.scan,
          uploadedAt: new Date().toLocaleTimeString('en-US', { hour12: false }) + ' IST'
        });
      }

      setIngestionHistory(prev => [...results, ...prev]);
      setStagedFiles([]);
      showToast(`Successfully ingested and scanned ${results.length} file(s) for user "${selectedUserObj?.username}"!`, 'success');
      loadUsers(); // Refresh user quotas
      loadUserFiles(selectedUserId); // Refresh user files
    } catch (err) {
      showToast(err.message || 'File ingestion failed.', 'error');
    } finally {
      setUploading(false);
      setUploadProgress(0);
      setCurrentStage('');
      if (fileInputRef.current) fileInputRef.current.value = '';
    }
  };

  const availableUsers = users.filter(u => u.role !== 'ADMIN' || u.id === currentAdmin?.id);

  const filteredUsers = availableUsers.filter(u => 
    u.username.toLowerCase().includes(searchUser.toLowerCase()) ||
    u.email.toLowerCase().includes(searchUser.toLowerCase()) ||
    u.role.toLowerCase().includes(searchUser.toLowerCase())
  );

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-6 animate-fade-in">
      {/* Header Banner */}
      <div className="glass-card p-6 border border-sky-500/40 bg-gradient-to-r from-slate-900 via-sky-950/20 to-slate-900 shadow-2xl flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="p-3 rounded-xl bg-sky-950/90 border border-sky-500/50 text-sky-400">
            <UploadCloud className="w-8 h-8" />
          </div>
          <div>
            <h1 className="text-xl font-black text-white tracking-wide flex items-center gap-2">
              Admin File Ingestion Hub
              <span className="px-2 py-0.5 bg-sky-950 border border-sky-500/50 text-sky-300 text-[10px] rounded font-mono">
                MULTI-USER DISPATCHER
              </span>
            </h1>
            <p className="text-xs text-slate-400 mt-1">
              Ingest files directly into any user's workspace with real-time multi-stage machine learning threat inspection.
            </p>
          </div>
        </div>

        <button
          onClick={() => {
            loadUsers();
            if (selectedUserId) loadUserFiles(selectedUserId);
          }}
          className="p-2 bg-slate-900 hover:bg-slate-800 text-slate-300 hover:text-white border border-slate-800 rounded-lg text-xs flex items-center gap-1.5 transition"
        >
          <RefreshCw className={`w-4 h-4 ${loadingUsers || loadingUserFiles ? 'animate-spin' : ''}`} /> Refresh Directory & Files
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column: Target User Selector & Details */}
        <div className="glass-card p-5 border border-slate-800 space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800">
            <h2 className="text-xs font-bold text-slate-300 uppercase tracking-wider font-mono flex items-center gap-1.5">
              <Users className="w-4 h-4 text-sky-400" /> Target Destination User
            </h2>
            <span className="text-[10px] text-slate-500 font-mono">{users.length} Active Accounts</span>
          </div>

          <div className="space-y-3">
            <div>
              <label className="text-[11px] text-slate-400 font-mono block mb-1.5">Select User Account:</label>
              <input
                type="text"
                placeholder="Search username or email..."
                value={searchUser}
                onChange={(e) => setSearchUser(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-white placeholder-slate-600 mb-2 focus:outline-none focus:border-sky-500"
              />

              <select
                value={selectedUserId}
                onChange={(e) => {
                  const newId = e.target.value;
                  setSelectedUserId(newId);
                  loadUserFiles(newId);
                }}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-xs text-white font-mono focus:outline-none focus:border-sky-500"
              >
                {filteredUsers.map(u => (
                  <option key={u.id} value={u.id}>
                    {u.username} ({u.role}) • {u.used_quota_formatted} / {u.quota_formatted}
                  </option>
                ))}
              </select>
            </div>

            {selectedUserObj && (
              <div className="p-4 bg-slate-950 rounded-xl border border-slate-800 space-y-3">
                <div className="flex items-center gap-3">
                  <div className="w-9 h-9 rounded-lg bg-sky-950 border border-sky-500/40 flex items-center justify-center font-bold text-sky-400 text-sm">
                    {selectedUserObj.username[0].toUpperCase()}
                  </div>
                  <div>
                    <div className="text-xs font-bold text-white flex items-center gap-1.5">
                      {selectedUserObj.username}
                      <span className={`px-1.5 py-0.2 rounded text-[9px] font-mono ${
                        selectedUserObj.role === 'ADMIN' ? 'bg-indigo-950 text-indigo-300 border border-indigo-500/40' : 'bg-slate-800 text-slate-300'
                      }`}>
                        {selectedUserObj.role}
                      </span>
                    </div>
                    <div className="text-[10px] text-slate-500 font-mono">{selectedUserObj.email}</div>
                  </div>
                </div>

                <div className="space-y-1.5 pt-2 border-t border-slate-900">
                  <div className="flex items-center justify-between text-[10px] font-mono">
                    <span className="text-slate-400">Allocated Quota Usage:</span>
                    <span className="text-sky-400 font-bold">{selectedUserObj.usage_percentage}%</span>
                  </div>
                  <div className="w-full h-1.5 bg-slate-900 rounded-full overflow-hidden border border-slate-800">
                    <div
                      style={{ width: `${Math.min(100, Math.max(2, selectedUserObj.usage_percentage || 0))}%` }}
                      className="bg-sky-500 h-full rounded-full"
                    ></div>
                  </div>
                  <div className="flex items-center justify-between text-[9px] text-slate-500 font-mono">
                    <span>Used: {selectedUserObj.used_quota_formatted}</span>
                    <span>Max: {selectedUserObj.quota_formatted}</span>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Center & Right Column: Dropzone, Pipeline Telemetry & User Files */}
        <div className="lg:col-span-2 space-y-6">
          {/* Dropzone Card */}
          <div className="glass-card p-6 border border-slate-800 space-y-4">
            <div
              onDragOver={(e) => e.preventDefault()}
              onDrop={handleFileDrop}
              onClick={() => fileInputRef.current && fileInputRef.current.click()}
              className="border-2 border-dashed border-sky-500/40 hover:border-sky-400 hover:bg-sky-950/10 rounded-2xl p-8 text-center cursor-pointer transition flex flex-col items-center justify-center space-y-3"
            >
              <input
                type="file"
                ref={fileInputRef}
                onChange={handleFileSelect}
                multiple
                className="hidden"
              />
              <div className="w-14 h-14 rounded-2xl bg-sky-950/80 border border-sky-500/50 flex items-center justify-center text-sky-400 shadow-lg">
                <UploadCloud className="w-7 h-7 animate-bounce" />
              </div>
              <div>
                <div className="text-sm font-bold text-white">
                  Drag & Drop Files Here or <span className="text-sky-400 underline">Browse Local Storage</span>
                </div>
                <div className="text-[11px] text-slate-500 mt-1">
                  Supported Formats: PDF, DOCX, PPTX, XLSX, TXT, PY, JS, EXE, ZIP, PNG, JPG (All extensions scanned)
                </div>
              </div>
            </div>

            {/* Staged Files List */}
            {stagedFiles.length > 0 && (
              <div className="space-y-2 pt-2">
                <div className="flex items-center justify-between text-xs font-mono text-slate-400">
                  <span>Staged for Ingestion ({stagedFiles.length} files):</span>
                  <button
                    onClick={() => setStagedFiles([])}
                    className="text-rose-400 hover:text-rose-300 text-[10px]"
                  >
                    Clear All
                  </button>
                </div>

                <div className="max-h-40 overflow-y-auto space-y-1.5 pr-1">
                  {stagedFiles.map((file, idx) => (
                    <div
                      key={idx}
                      className="flex items-center justify-between p-2.5 bg-slate-950 rounded-xl border border-slate-800 text-xs font-mono"
                    >
                      <div className="flex items-center gap-2 truncate">
                        <FileText className="w-4 h-4 text-sky-400 shrink-0" />
                        <span className="text-white truncate max-w-[240px]">{file.name}</span>
                        <span className="text-slate-500 text-[10px]">({(file.size / 1024).toFixed(1)} KB)</span>
                      </div>
                      <button
                        onClick={() => removeStagedFile(idx)}
                        className="text-slate-500 hover:text-rose-400 p-1"
                      >
                        <X className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  ))}
                </div>

                {/* Ingestion Trigger Button */}
                <button
                  onClick={handleStartIngestion}
                  disabled={uploading}
                  className="w-full py-3 bg-gradient-to-r from-sky-600 via-cyan-600 to-sky-500 hover:from-sky-500 hover:to-cyan-400 text-white rounded-xl text-xs font-bold font-mono tracking-wider uppercase flex items-center justify-center gap-2 shadow-lg transition disabled:opacity-50"
                >
                  {uploading ? (
                    <>
                      <RefreshCw className="w-4 h-4 animate-spin" /> Ingesting & Scanning Pipeline...
                    </>
                  ) : (
                    <>
                      <ShieldCheck className="w-4 h-4" /> Ingest {stagedFiles.length} File(s) into {selectedUserObj?.username}'s Vault
                    </>
                  )}
                </button>
              </div>
            )}

            {/* Live Pipeline Progress Indicator */}
            {uploading && (
              <div className="p-4 bg-slate-950 rounded-xl border border-sky-500/40 space-y-2 font-mono">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-sky-400 font-bold">{currentStage}</span>
                  <span className="text-white font-black">{uploadProgress}%</span>
                </div>
                <div className="w-full h-2 bg-slate-900 rounded-full overflow-hidden">
                  <div
                    style={{ width: `${uploadProgress}%` }}
                    className="bg-gradient-to-r from-sky-500 to-cyan-400 h-full rounded-full transition-all duration-300"
                  ></div>
                </div>
              </div>
            )}
          </div>

          {/* Target Destination User's Workspace Files Table */}
          <div className="glass-card p-5 border border-slate-800 space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-xs font-bold text-slate-300 uppercase tracking-wider font-mono flex items-center gap-1.5">
                <Database className="w-4 h-4 text-sky-400" /> Target User Files: {selectedUserObj?.username || 'Select User'}
              </h3>
              <span className="text-[10px] text-slate-500 font-mono">{userFiles.length} Files Stored</span>
            </div>

            <div className="overflow-x-auto">
              {loadingUserFiles ? (
                <div className="text-center py-8 text-slate-400 text-xs font-mono">
                  <RefreshCw className="w-4 h-4 animate-spin mx-auto mb-2 text-sky-400" />
                  LOADING REPOSITORY FILES...
                </div>
              ) : userFiles.length > 0 ? (
                <table className="cyber-table w-full text-xs">
                  <thead>
                    <tr>
                      <th>FILE NAME</th>
                      <th>SIZE</th>
                      <th>SECURITY STATUS</th>
                      <th>THREAT SCORE</th>
                      <th>UPLOADED (IST)</th>
                      <th className="text-right">ACTIONS</th>
                    </tr>
                  </thead>
                  <tbody>
                    {userFiles.map((file) => (
                      <tr key={file.id}>
                        <td>
                          <div className="flex items-center gap-2 flex-wrap">
                            <FileText className="w-4 h-4 text-sky-400 shrink-0" />
                            <span 
                              className="font-bold text-white truncate max-w-[180px] hover:text-sky-400 cursor-pointer"
                              onClick={() => openModal('fileViewer', file)}
                              title={file.filename}
                            >
                              {file.filename}
                            </span>
                            {file.is_confidential && (
                              <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[9px] font-bold bg-amber-950/80 text-amber-300 border border-amber-500/40">
                                <Lock className="w-2.5 h-2.5 text-amber-400" /> CONFIDENTIAL
                              </span>
                            )}
                          </div>
                        </td>
                        <td className="font-mono text-slate-300">
                          {file.file_size_formatted || `${Math.round((file.file_size || 0) / 1024)} KB`}
                        </td>
                        <td>
                          <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${
                            file.security_status === 'MALICIOUS' ? 'bg-rose-950 text-rose-300 border-rose-500/40' :
                            file.security_status === 'SUSPICIOUS' ? 'bg-amber-950 text-amber-300 border-amber-500/40' :
                            'bg-emerald-950 text-emerald-300 border-emerald-500/40'
                          }`}>
                            {file.security_status || 'CLEAN'}
                          </span>
                        </td>
                        <td className="font-mono font-bold">
                          <span className={(file.threat_score || 0) >= 70 ? 'text-rose-400' : (file.threat_score || 0) >= 40 ? 'text-amber-400' : 'text-emerald-400'}>
                            {file.threat_score ?? 0}%
                          </span>
                        </td>
                        <td className="font-mono text-slate-400 text-[10px]">
                          {file.created_at || 'Recent'}
                        </td>
                        <td className="text-right">
                          <div className="flex items-center justify-end gap-1.5">
                            <button
                              onClick={() => openModal('fileViewer', file)}
                              className="p-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white rounded transition"
                              title="Preview Content"
                            >
                              <Eye className="w-3.5 h-3.5" />
                            </button>
                            <button
                              onClick={() => openModal('adminIngestionDetails', { ...file, target_username: selectedUserObj?.username })}
                              className="p-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white rounded transition"
                              title="Inspect Ingestion & Intrinsic Health"
                            >
                              <Info className="w-3.5 h-3.5" />
                            </button>
                            <a
                              href={fileApi.getDownloadUrl(file.id || file.file_id)}
                              download={file.filename}
                              className="p-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white rounded transition"
                              title="Download File"
                            >
                              <Download className="w-3.5 h-3.5" />
                            </a>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              ) : (
                <div className="text-center py-6 text-slate-500 text-xs font-mono">
                  No files uploaded for {selectedUserObj?.username || 'this user'} yet. Drag & drop files above to ingest.
                </div>
              )}
            </div>
          </div>

          {/* Session Ingestion Results Feed */}
          {ingestionHistory.length > 0 && (
            <div className="glass-card p-5 border border-slate-800 space-y-3">
              <div className="flex items-center justify-between">
                <h3 className="text-xs font-bold text-slate-300 uppercase tracking-wider font-mono flex items-center gap-1.5">
                  <Sparkles className="w-4 h-4 text-emerald-400" /> Recent Ingestion Activity (This Session)
                </h3>
                <span className="text-[10px] text-slate-500 font-mono">{ingestionHistory.length} Ingested</span>
              </div>

              <div className="overflow-x-auto">
                <table className="cyber-table w-full text-xs">
                  <thead>
                    <tr>
                      <th>FILE NAME</th>
                      <th>TARGET USER</th>
                      <th>VERDICT</th>
                      <th>THREAT SCORE</th>
                      <th>TIME</th>
                      <th>ACTIONS</th>
                    </tr>
                  </thead>
                  <tbody>
                    {ingestionHistory.map((item, idx) => (
                      <tr key={idx}>
                        <td>
                          <div className="flex items-center gap-2 flex-wrap">
                            <FileText className="w-4 h-4 text-sky-400 shrink-0" />
                            <span className="font-bold text-white truncate max-w-[180px]">{item.filename}</span>
                            {item.is_confidential && (
                              <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[9px] font-bold bg-amber-950/80 text-amber-300 border border-amber-500/40">
                                <Lock className="w-2.5 h-2.5 text-amber-400" /> CONFIDENTIAL
                              </span>
                            )}
                          </div>
                        </td>
                        <td className="font-mono text-slate-300">
                          {item.target_username}
                        </td>
                        <td>
                          <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${
                            item.security_status === 'MALICIOUS' ? 'bg-rose-950 text-rose-300 border-rose-500/40' :
                            item.security_status === 'SUSPICIOUS' ? 'bg-amber-950 text-amber-300 border-amber-500/40' :
                            'bg-emerald-950 text-emerald-300 border-emerald-500/40'
                          }`}>
                            {item.security_status}
                          </span>
                        </td>
                        <td className="font-mono font-bold">
                          <span className={item.threat_score >= 70 ? 'text-rose-400' : item.threat_score >= 40 ? 'text-amber-400' : 'text-emerald-400'}>
                            {item.threat_score}%
                          </span>
                        </td>
                        <td className="font-mono text-slate-400 text-[10px]">
                          {item.uploadedAt}
                        </td>
                        <td>
                          <div className="flex items-center gap-1">
                            <button
                              onClick={() => openModal('fileViewer', item)}
                              className="p-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded transition"
                              title="Preview Content"
                            >
                              <Eye className="w-3.5 h-3.5" />
                            </button>
                            <button
                              onClick={() => openModal('adminIngestionDetails', item)}
                              className="p-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded transition"
                              title="Inspect Ingestion & Intrinsic Health"
                            >
                              <Info className="w-3.5 h-3.5" />
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Global Modals */}
      <FileViewerModal />
      <AdminIngestionModal onUpdate={() => { if (selectedUserId) loadUserFiles(selectedUserId); }} />
    </div>
  );
}

