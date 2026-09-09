# Build UserWiseFiles.jsx
import os

part1 = """import React, { useEffect, useState, useRef } from 'react';
import { adminApi } from '../../api/adminApi';
import { fileApi } from '../../api/fileApi';
import { useApp } from '../../context/AppContext';
import { 
  GitBranch, User, Files, RefreshCw, Eye, ShieldCheck, ShieldAlert, 
  AlertTriangle, History, Cpu, FileText, CheckCircle2, Lock, Unlock,
  UploadCloud, KeyRound, Sparkles, X, ChevronDown, ChevronRight
} from 'lucide-react';
import { SecurityBadge } from '../../components/SecurityBadge';
import { FileViewerModal } from '../../components/FileViewerModal';
import { ScanHistoryModal } from '../../components/ScanHistoryModal';
import { SecurityDetailsModal } from '../../components/SecurityDetailsModal';
import { AdminSecurityConfigModal } from '../../components/AdminSecurityConfigModal';

export function UserWiseFiles() {
  const { openModal, showToast, triggerCriticalAlert } = useApp();
  const [userGroups, setUserGroups] = useState([]);
  const [loading, setLoading] = useState(true);
  const [activeScans, setActiveScans] = useState({});
  const [dualAdminModal, setDualAdminModal] = useState(null);
  const [unlockVaultModal, setUnlockVaultModal] = useState(null);
  const [unlockedAdminIds, setUnlockedAdminIds] = useState({});
  const [showConfigModal, setShowConfigModal] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [uploadStage, setUploadStage] = useState('');
  const fileInputRef = useRef(null);

  const loadGroupedFiles = async () => {
    setLoading(true);
    try {
      const data = await adminApi.getUserGroupedFiles();
      setUserGroups(Array.isArray(data) ? data : (data.users || []));
    } catch (err) {
      showToast(err.message || 'Failed to load user-wise files.', 'error');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadGroupedFiles();
  }, []);

  const handleAdminFileUpload = async (e) => {
    const files = Array.from(e.target.files || []);
    if (files.length === 0) return;

    setUploading(true);
    try {
      for (let i = 0; i < files.length; i++) {
        const file = files[i];
        setUploadStage('Processing ' + file.name + ' (' + (i + 1) + '/' + files.length + ')...');
        const res = await fileApi.uploadFile(file, (pct) => {
          setUploadStage('Uploading ' + file.name + ': ' + pct + '% (ML Threat Inference)...');
        });

        if (res.scan && res.scan.security_status === 'MALICIOUS') {
          triggerCriticalAlert({
            filename: file.name,
            threat_score: res.scan.threat_score || 85.0
          });
        }
      }
      showToast('Successfully uploaded & scanned ' + files.length + ' file(s) into Admin Vault!', 'success');
      loadGroupedFiles();
    } catch (err) {
      showToast(err.message || 'Upload failed.', 'error');
    } finally {
      setUploading(false);
      setUploadStage('');
      if (fileInputRef.current) fileInputRef.current.value = '';
    }
  };

  const handleUnlockAdminVaultSubmit = async (e) => {
    e.preventDefault();
    if (!unlockVaultModal || !unlockVaultModal.pin) return;

    const targetUser = unlockVaultModal.user;
    try {
      await adminApi.unlockAdminVault(targetUser.user_id, unlockVaultModal.pin);
      setUnlockedAdminIds((prev) => ({
        ...prev,
        [targetUser.user_id]: unlockVaultModal.pin
      }));
      setUnlockVaultModal(null);
      showToast('Dual-Admin Authorization granted! Unlocked ' + targetUser.username + ' repository.', 'success');
    } catch (err) {
      showToast(err.message || 'Invalid Admin Security PIN.', 'error');
    }
  };

  const handleInitiateScan = (file, userObj) => {
    const savedPin = unlockedAdminIds[userObj ? userObj.user_id : null];
    if (userObj && userObj.is_admin_protected && !savedPin) {
      setDualAdminModal({
        file,
        user: userObj,
        authCode: ''
      });
      return;
    }
    handleExecuteScan(file, savedPin || '');
  };

  const handleExecuteScan = async (file, adminAuthCode = '') => {
    const fileId = file.id;
    setDualAdminModal(null);

    setActiveScans((prev) => ({
      ...prev,
      [fileId]: { status: 'SCANNING', stage_label: 'HASHING & STATIC ANALYSIS', progress_percent: 25 }
    }));

    try {
      setTimeout(() => {
        setActiveScans((prev) => ({
          ...prev,
          [fileId]: { status: 'SCANNING', stage_label: 'STATIC HEURISTIC ANALYSIS (50%)', progress_percent: 50 }
        }));
      }, 350);

      setTimeout(() => {
        setActiveScans((prev) => ({
          ...prev,
          [fileId]: { status: 'SCANNING', stage_label: 'PE STRUCTURAL & LIGHTGBM (75%)', progress_percent: 75 }
        }));
      }, 700);

      const res = await adminApi.scanFile(fileId, adminAuthCode);

      setActiveScans((prev) => ({
        ...prev,
        [fileId]: {
          status: 'COMPLETED',
          stage_label: 'ANALYSIS COMPLETED (100%)',
          progress_percent: 100,
          result: res.scan
        }
      }));

      showToast('Scan complete for ' + file.filename + ': ' + res.scan.security_status + ' (Score: ' + res.scan.threat_score + '%)', 'success');

      if (res.scan && res.scan.security_status === 'MALICIOUS') {
        triggerCriticalAlert({
          filename: file.filename,
          threat_score: res.scan.threat_score
        });
      }

      loadGroupedFiles();
    } catch (err) {
      setActiveScans((prev) => ({
        ...prev,
        [fileId]: { status: 'ERROR', stage_label: err.message || 'Scan Pipeline Failed' }
      }));
      showToast(err.message || 'Scan failed.', 'error');
    }
  };

  const handleExecuteRescan = async (file, userObj) => {
    const fileId = file.id;
    const adminAuthCode = unlockedAdminIds[userObj ? userObj.user_id : null] || '';

    if (userObj && userObj.is_admin_protected && !adminAuthCode) {
      setDualAdminModal({
        file,
        user: userObj,
        authCode: ''
      });
      return;
    }

    setActiveScans((prev) => ({
      ...prev,
      [fileId]: { status: 'SCANNING', stage_label: 'QUEUED & RE-CALCULATING METADATA', progress_percent: 25 }
    }));

    try {
      setTimeout(() => {
        setActiveScans((prev) => ({
          ...prev,
          [fileId]: { status: 'SCANNING', stage_label: 'DYNAMIC ML EMBER INFERENCE (60%)', progress_percent: 60 }
        }));
      }, 400);

      const res = await adminApi.rescanFile(fileId, adminAuthCode);

      setActiveScans((prev) => ({
        ...prev,
        [fileId]: {
          status: 'COMPLETED',
          stage_label: 'RESCAN COMPLETED',
          progress_percent: 100,
          result: res.scan
        }
      }));

      showToast('Rescan complete for ' + file.filename + ': ' + res.scan.security_status, 'success');
      loadGroupedFiles();
    } catch (err) {
      setActiveScans((prev) => ({
        ...prev,
        [fileId]: { status: 'ERROR', stage_label: err.message || 'Rescan Failed' }
      }));
      showToast(err.message || 'Rescan failed.', 'error');
    }
  };
"""