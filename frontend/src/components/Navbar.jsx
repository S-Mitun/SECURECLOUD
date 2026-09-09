import React, { useState, useRef } from 'react';
import { AdminSecurityConfigModal } from './AdminSecurityConfigModal';
import { fileApi } from '../api/fileApi';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { useApp } from '../context/AppContext';
import { 
  ShieldCheck, HardDrive, Lock, KeyRound, Share2, UploadCloud, RefreshCw, Trash2, Clock, 
  Activity, Gauge, GitBranch, Users, ShieldAlert, Archive, 
  Shield, Key, List, LogOut, Volume2, VolumeX, Network, Zap, UserCheck, Upload
} from 'lucide-react';

export function Navbar() {
  const [showPinModal, setShowPinModal] = useState(false);
  const [adminUploading, setAdminUploading] = useState(false);
  const adminFileInputRef = useRef(null);

  const { user, isAdmin, logout } = useAuth();
  const { criticalAlert, isAudioMuted, toggleAudioMute, dismissCriticalAlert, triggerCriticalAlert, showToast } = useApp();
  const location = useLocation();
  const navigate = useNavigate();

  const handleAdminNavUpload = async (e) => {
    const files = Array.from(e.target.files || []);
    if (files.length === 0) return;

    setAdminUploading(true);
    try {
      for (let i = 0; i < files.length; i++) {
        const file = files[i];
        const formData = new FormData();
        formData.append('file', file);
        const res = await fileApi.uploadFile(formData);
        if (res.scan && res.scan.security_status === 'MALICIOUS') {
          triggerCriticalAlert({
            filename: file.name,
            threat_score: res.scan.threat_score || 85.0
          });
        }
      }
      showToast(`Successfully uploaded & scanned ${files.length} file(s) into Admin Vault!`, 'success');
      window.dispatchEvent(new CustomEvent('files:updated'));
    } catch (err) {
      const msg = err.message || (typeof err === 'object' ? JSON.stringify(err) : String(err));
      showToast(`Upload Failed: ${msg}`, 'error');
    } finally {
      setAdminUploading(false);
      if (adminFileInputRef.current) adminFileInputRef.current.value = '';
    }
  };

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  const isActive = (path) => location.pathname === path;

  return (
    <>
      {/* Top 3-Second Military Base Breach Siren Alert Banner */}
      {criticalAlert && (
        <div className="siren-banner p-3 px-6 text-white flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 shadow-2xl z-50">
          <div className="flex items-center gap-3">
            <span className="p-1 px-2.5 bg-red-600 font-black rounded text-xs tracking-wider animate-pulse uppercase">
              3-SECOND BASE BREACH ALARM
            </span>
            <span className="text-xs sm:text-sm font-semibold">
              Malicious threat in <strong>"{criticalAlert.filename}"</strong> (Score: {criticalAlert.threat_score}%) - Isolated in Quarantine Vault.
            </span>
          </div>
          <div className="flex items-center gap-2 self-end sm:self-auto">
            <button
              onClick={toggleAudioMute}
              className="p-1 px-3 bg-red-950/90 border border-red-400 rounded text-xs flex items-center gap-1 hover:bg-red-900 text-white font-medium"
            >
              {isAudioMuted ? <VolumeX className="w-4 h-4" /> : <Volume2 className="w-4 h-4" />}
              <span>{isAudioMuted ? 'Unmute Alarm' : 'Mute Alarm'}</span>
            </button>
            <button
              onClick={dismissCriticalAlert}
              className="p-1 px-3 bg-black/50 hover:bg-black/70 border border-white/30 rounded text-xs text-white font-bold"
            >
              Acknowledge
            </button>
          </div>
        </div>
      )}

      {/* Main Navigation Bar */}
      <header className="border-b border-slate-800 bg-slate-950/95 backdrop-blur sticky top-0 z-40">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          {/* Logo & Branding */}
          <Link
            to={isAdmin ? '/admin' : '/my-files'}
            className="flex items-center gap-3 cursor-pointer select-none shrink-0"
          >
            <div className="w-10 h-10 rounded-lg bg-gradient-to-tr from-sky-600 to-cyan-400 p-0.5 shadow-lg shadow-sky-500/20">
              <div className="w-full h-full bg-slate-950 rounded-[7px] flex items-center justify-center">
                <ShieldCheck className="w-5 h-5 text-sky-400" />
              </div>
            </div>
            <div>
              <span className="font-black tracking-wider text-lg text-white">
                SECURE<span className="text-sky-400">CLOUD</span>
              </span>
              <p className="text-[10px] text-slate-400 uppercase tracking-widest -mt-1 font-mono">
                Automated ML Threat Platform
              </p>
            </div>
          </Link>

          {/* Navigation Links */}
          {user && (
            <nav className="hidden md:flex items-center gap-1 bg-slate-900/90 p-1 rounded-xl border border-slate-800 overflow-x-auto max-w-3xl">
              {isAdmin ? (
                <>
                  <Link
                    to="/admin"
                    className={`px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition ${
                      isActive('/admin') ? 'bg-cyan-600 text-white shadow' : 'text-cyan-400 hover:bg-cyan-950/40'
                    }`}
                  >
                    <Activity className="w-3.5 h-3.5" /> SOC
                  </Link>
                  <Link
                    to="/admin/sentinel"
                    className={`px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition ${
                      isActive('/admin/sentinel') ? 'bg-sky-600 text-white shadow' : 'text-slate-300 hover:text-white hover:bg-slate-800'
                    }`}
                  >
                    <Gauge className="w-3.5 h-3.5" /> Sentinel VM
                  </Link>
                  <Link
                    to="/admin/upload-files"
                    className={`px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition ${
                      isActive('/admin/upload-files') ? 'bg-sky-600 text-white shadow' : 'text-sky-300 hover:text-white hover:bg-slate-800'
                    }`}
                  >
                    <UploadCloud className="w-3.5 h-3.5" /> Upload Files for Admin
                  </Link>
                  <Link
                    to="/admin/user-wise-files"
                    className={`px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition ${
                      isActive('/admin/user-wise-files') ? 'bg-indigo-600 text-white shadow' : 'text-indigo-300 hover:text-white hover:bg-slate-800'
                    }`}
                  >
                    <GitBranch className="w-3.5 h-3.5" /> User-Wise Files
                  </Link>
                  <Link
                    to="/admin/users"
                    className={`px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition ${
                      isActive('/admin/users') ? 'bg-sky-600 text-white shadow' : 'text-slate-300 hover:text-white hover:bg-slate-800'
                    }`}
                  >
                    <Users className="w-3.5 h-3.5" /> Users
                  </Link>
                  <Link
                    to="/admin/correlation"
                    className={`px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition ${
                      isActive('/admin/correlation') ? 'bg-rose-600 text-white shadow' : 'text-rose-400 hover:bg-rose-950/40'
                    }`}
                  >
                    <Network className="w-3.5 h-3.5" /> Threat Correlation
                  </Link>

                  <Link
                    to="/admin/risk-profiling"
                    className={`px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition ${
                      isActive('/admin/risk-profiling') ? 'bg-purple-600 text-white shadow' : 'text-purple-400 hover:bg-purple-950/40'
                    }`}
                  >
                    <UserCheck className="w-3.5 h-3.5" /> User Risk Matrix
                  </Link>
                  <Link
                    to="/admin/quarantine"
                    className={`px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition ${
                      isActive('/admin/quarantine') ? 'bg-rose-700 text-white shadow' : 'text-slate-300 hover:text-white hover:bg-slate-800'
                    }`}
                  >
                    <Archive className="w-3.5 h-3.5" /> Quarantine
                  </Link>
                  <Link
                    to="/admin/verified-artifacts"
                    className={`px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition ${
                      isActive('/admin/verified-artifacts') ? 'bg-emerald-600 text-white shadow' : 'text-emerald-400 hover:text-white hover:bg-emerald-950/40'
                    }`}
                  >
                    <ShieldCheck className="w-3.5 h-3.5" /> Verified Trust
                  </Link>
                  <Link
                    to="/admin/ip-guard"
                    className={`px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition ${
                      isActive('/admin/ip-guard') ? 'bg-amber-600 text-white shadow' : 'text-slate-300 hover:text-white hover:bg-slate-800'
                    }`}
                  >
                    <Shield className="w-3.5 h-3.5" /> IP Guard
                  </Link>
                  <Link
                    to="/admin/sessions"
                    className={`px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition ${
                      isActive('/admin/sessions') ? 'bg-cyan-600 text-white shadow' : 'text-slate-300 hover:text-white hover:bg-slate-800'
                    }`}
                  >
                    <Key className="w-3.5 h-3.5" /> Sessions
                  </Link>
                  <Link
                    to="/admin/audit-logs"
                    className={`px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition ${
                      isActive('/admin/audit-logs') ? 'bg-sky-600 text-white shadow' : 'text-slate-300 hover:text-white hover:bg-slate-800'
                    }`}
                  >
                    <List className="w-3.5 h-3.5" /> Audit Logs
                  </Link>
                </>
              ) : (
                <>
                  <Link
                    to="/my-files"
                    className={`px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition ${
                      isActive('/my-files') ? 'bg-sky-600 text-white shadow' : 'text-slate-300 hover:text-white hover:bg-slate-800'
                    }`}
                  >
                    <HardDrive className="w-3.5 h-3.5" /> My Files
                  </Link>
                  <Link
                    to="/confidential"
                    className={`px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition ${
                      isActive('/confidential') ? 'bg-amber-600 text-white shadow' : 'text-amber-400 hover:text-white hover:bg-slate-800'
                    }`}
                  >
                    <Lock className="w-3.5 h-3.5" /> Confidential
                  </Link>
                  <Link
                    to="/password-saves"
                    className={`px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition ${
                      isActive('/password-saves') ? 'bg-amber-600 text-white shadow' : 'text-amber-400 hover:text-white hover:bg-slate-800'
                    }`}
                  >
                    <KeyRound className="w-3.5 h-3.5" /> Password Saves
                  </Link>
                  <Link
                    to="/shares"
                    className={`px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition ${
                      isActive('/shares') ? 'bg-sky-600 text-white shadow' : 'text-slate-300 hover:text-white hover:bg-slate-800'
                    }`}
                  >
                    <Share2 className="w-3.5 h-3.5" /> Shared Links
                  </Link>
                  <Link
                    to="/recycle-bin"
                    className={`px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition ${
                      isActive('/recycle-bin') ? 'bg-sky-600 text-white shadow' : 'text-slate-300 hover:text-white hover:bg-slate-800'
                    }`}
                  >
                    <Trash2 className="w-3.5 h-3.5" /> Recycle Bin
                  </Link>
                  <Link
                    to="/activity"
                    className={`px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition ${
                      isActive('/activity') ? 'bg-sky-600 text-white shadow' : 'text-slate-300 hover:text-white hover:bg-slate-800'
                    }`}
                  >
                    <Clock className="w-3.5 h-3.5" /> Activity
                  </Link>
                </>
              )}
            </nav>
          )}

          {/* Right Header Controls: User Info + Logout */}
          <div className="flex items-center gap-3">
            {user && (
              <div className="flex items-center gap-2 pl-2">
                {user.role === 'ADMIN' && (
                  <button
                    onClick={() => setShowPinModal(true)}
                    className="p-1.5 px-2.5 bg-sky-950/80 hover:bg-sky-900 border border-sky-500/40 text-sky-300 rounded-lg text-xs font-mono font-semibold flex items-center gap-1.5 transition shadow"
                    title="View Your Permanent Admin Dual-Auth Key"
                  >
                    <KeyRound className="w-3.5 h-3.5 text-sky-400" />
                    <span className="hidden md:inline">Dual-Auth Key</span>
                  </button>
                )}
                <div className="text-right hidden sm:block">
                  <div className="text-xs font-bold text-white">{user.username}</div>
                  <div className="text-[10px] text-slate-400 font-mono uppercase">{user.role}</div>
                </div>
                <button
                  onClick={handleLogout}
                  className="p-2 text-slate-400 hover:text-rose-400 hover:bg-slate-900 rounded-lg transition"
                  title="Sign Out"
                >
                  <LogOut className="w-4 h-4" />
                </button>
              </div>
            )}
          </div>
        </div>
      </header>

      {showPinModal && (
        <AdminSecurityConfigModal onClose={() => setShowPinModal(false)} />
      )}
    </>
  );
}
