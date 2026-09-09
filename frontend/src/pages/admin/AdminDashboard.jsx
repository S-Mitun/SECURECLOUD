import React, { useEffect, useState } from 'react';
import { adminApi } from '../../api/adminApi';
import { useApp } from '../../context/AppContext';
import { Link } from 'react-router-dom';
import { 
  ShieldCheck, ShieldAlert, Cpu, HardDrive, Users, Activity, 
  RefreshCw, Files, AlertTriangle, CheckCircle2, ArrowRight,
  Radio, GitBranch, Gauge, PieChart, FileText, Film, Archive, Folder
} from 'lucide-react';

export function AdminDashboard() {
  const { telemetry, showToast } = useApp();
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);

  const loadStats = async (isSilent = false) => {
    if (!isSilent) setLoading(true);
    try {
      const data = await adminApi.getDashboard();
      setStats(data);
    } catch (err) {
      if (!isSilent) showToast(err.message || 'Failed to fetch SOC dashboard metrics.', 'error');
    } finally {
      if (!isSilent) setLoading(false);
    }
  };

  useEffect(() => {
    loadStats();
    const interval = setInterval(() => {
      loadStats(true);
    }, 3000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-6 animate-fade-in">
      {/* Header Banner */}
      <div className="glass-card p-6 border border-cyan-500/40 bg-gradient-to-r from-slate-900 via-cyan-950/20 to-slate-900 shadow-2xl flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="p-3 rounded-2xl bg-cyan-950/90 border border-cyan-500/50 text-cyan-400">
            <ShieldCheck className="w-8 h-8" />
          </div>
          <div>
            <h1 className="text-xl font-black text-white tracking-wide flex items-center gap-2">
              SOC Security Operations & Storage Center
              <span className="px-2 py-0.5 bg-cyan-950 border border-cyan-500/40 text-cyan-300 text-[10px] rounded font-mono">
                REAL-TIME TELEMETRY
              </span>
            </h1>
            <p className="text-xs text-slate-400 mt-1">
              Real-time threat monitoring, ML inference telemetry, and cloud storage compliance.
            </p>
          </div>
        </div>

        <button
          onClick={() => loadStats(false)}
          className="p-2 bg-slate-900 hover:bg-slate-800 text-slate-300 hover:text-white border border-slate-700 rounded-xl text-xs flex items-center gap-1.5 transition shadow"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} /> Refresh Telemetry
        </button>
      </div>

      {/* Top Telemetry Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="glass-card p-5 border-l-4 border-l-sky-500 shadow-xl">
          <div className="flex items-center justify-between text-slate-400 text-xs font-semibold mb-1">
            <span>Identity Directory</span>
            <Users className="w-4 h-4 text-sky-400" />
          </div>
          <div className="text-2xl font-black text-white font-mono">{stats?.total_users ?? stats?.stats?.total_users ?? 0}</div>
          <div className="text-[10px] text-sky-400 mt-1 font-mono">
            {stats?.active_users ?? stats?.stats?.active_users ?? 0} Active Identities
          </div>
        </div>

        <div className="glass-card p-5 border-l-4 border-l-cyan-500 shadow-xl">
          <div className="flex items-center justify-between text-slate-400 text-xs font-semibold mb-1">
            <span>Indexed Vault Files</span>
            <Files className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-2xl font-black text-white font-mono">{stats?.total_files ?? stats?.stats?.total_files ?? 0}</div>
          <div className="text-[10px] text-slate-400 mt-1 font-mono">
            {stats?.clean_files ?? stats?.stats?.clean_files ?? 0} Clean • {stats?.suspicious_files ?? stats?.stats?.suspicious_files ?? 0} Suspicious
          </div>
        </div>

        <div className="glass-card p-5 border-l-4 border-l-red-500 shadow-xl">
          <div className="flex items-center justify-between text-slate-400 text-xs font-semibold mb-1">
            <span>Threats Neutralized</span>
            <ShieldAlert className="w-4 h-4 text-red-400" />
          </div>
          <div className="text-2xl font-black text-red-400 font-mono">{stats?.total_threats ?? stats?.stats?.total_threats ?? 0}</div>
          <div className="text-[10px] text-red-400/80 mt-1 font-mono">
            {stats?.total_quarantined ?? stats?.stats?.quarantined_count ?? 0} Quarantined
          </div>
        </div>

        <div className="glass-card p-5 border-l-4 border-l-emerald-500 shadow-xl">
          <div className="flex items-center justify-between text-slate-400 text-xs font-semibold mb-1">
            <span>Storage Occupied</span>
            <HardDrive className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-black text-emerald-400 font-mono">
            {stats?.storage_used_formatted || stats?.storage_occupied_formatted || '0 B'}
          </div>
          <div className="text-[10px] text-slate-400 mt-1 font-mono">
            of {stats?.total_allocated_quota_formatted || '50 GB'} Total Quota
          </div>
        </div>
      </div>

      {/* Admin Cloud Storage Center Breakdown */}
      <div className="glass-card p-6 border border-slate-800 shadow-2xl space-y-4">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2 border-b border-slate-800 pb-3">
          <div className="flex items-center gap-2">
            <HardDrive className="w-5 h-5 text-emerald-400" />
            <h2 className="text-sm font-bold text-white uppercase tracking-wider">
              Admin Cloud Storage Center & Volume Breakdown
            </h2>
          </div>
          <span className="text-xs font-mono text-slate-400">
            Platform Usage: <strong className="text-emerald-400">{stats?.storage_percentage ?? 0}%</strong>
          </span>
        </div>

        {/* Global Progress Bar */}
        <div className="space-y-1.5">
          <div className="w-full bg-slate-900 rounded-full h-3 overflow-hidden border border-slate-800 p-0.5">
            <div
              className="h-full bg-gradient-to-r from-emerald-500 via-teal-500 to-sky-500 rounded-full transition-all duration-700"
              style={{ width: `${Math.min(100, Math.max(2, stats?.storage_percentage || 0))}%` }}
            />
          </div>
          <div className="flex justify-between text-[11px] font-mono text-slate-400">
            <span>Used: <strong className="text-white">{stats?.storage_used_formatted || '0 B'}</strong></span>
            <span>Allocated Quota: <strong className="text-white">{stats?.total_allocated_quota_formatted || '50.0 GB'}</strong></span>
          </div>
        </div>

        {/* Category Breakdown Cards */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-2">
          <div className="p-3 bg-slate-900/90 border border-slate-800 rounded-xl">
            <div className="flex items-center gap-2 text-sky-400 text-xs font-bold mb-1">
              <FileText className="w-4 h-4" /> Documents
            </div>
            <div className="text-base font-bold text-white font-mono">
              {stats?.storage_breakdown?.documents_formatted || '0 B'}
            </div>
            <div className="text-[10px] text-slate-500 font-mono mt-0.5">PDF, DOCX, XLSX, PPTX</div>
          </div>

          <div className="p-3 bg-slate-900/90 border border-slate-800 rounded-xl">
            <div className="flex items-center gap-2 text-purple-400 text-xs font-bold mb-1">
              <Film className="w-4 h-4" /> Media & Images
            </div>
            <div className="text-base font-bold text-white font-mono">
              {stats?.storage_breakdown?.media_formatted || '0 B'}
            </div>
            <div className="text-[10px] text-slate-500 font-mono mt-0.5">PNG, JPG, MP4, MP3</div>
          </div>

          <div className="p-3 bg-slate-900/90 border border-slate-800 rounded-xl">
            <div className="flex items-center gap-2 text-amber-400 text-xs font-bold mb-1">
              <Archive className="w-4 h-4" /> Archives
            </div>
            <div className="text-base font-bold text-white font-mono">
              {stats?.storage_breakdown?.archives_formatted || '0 B'}
            </div>
            <div className="text-[10px] text-slate-500 font-mono mt-0.5">ZIP, TAR, GZ, 7Z</div>
          </div>

          <div className="p-3 bg-slate-900/90 border border-slate-800 rounded-xl">
            <div className="flex items-center gap-2 text-emerald-400 text-xs font-bold mb-1">
              <Folder className="w-4 h-4" /> Other / Code
            </div>
            <div className="text-base font-bold text-white font-mono">
              {stats?.storage_breakdown?.other_formatted || '0 B'}
            </div>
            <div className="text-[10px] text-slate-500 font-mono mt-0.5">JSON, CSV, Scripts</div>
          </div>
        </div>
      </div>

      {/* Quick Navigation Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Link
          to="/admin/user-wise-files"
          className="glass-card p-5 hover:border-indigo-500/50 transition group flex flex-col justify-between shadow-xl"
        >
          <div>
            <div className="p-2.5 rounded-xl bg-indigo-950/80 border border-indigo-500/30 text-indigo-400 w-fit mb-3">
              <GitBranch className="w-5 h-5" />
            </div>
            <h3 className="text-sm font-bold text-white group-hover:text-indigo-400 transition flex items-center justify-between">
              <span>User-Wise File Segregation</span>
              <ArrowRight className="w-4 h-4 transform group-hover:translate-x-1 transition" />
            </h3>
            <p className="text-xs text-slate-400 mt-1.5 leading-relaxed">
              Inspect each user's isolated file repository with independent real-time Scan and Rescan controls.
            </p>
          </div>
          <div className="mt-4 pt-3 border-t border-slate-800 text-[11px] text-indigo-300 font-mono">
            Zero-Knowledge Privacy Maintained
          </div>
        </Link>

        <Link
          to="/admin/sentinel"
          className="glass-card p-5 hover:border-sky-500/50 transition group flex flex-col justify-between shadow-xl"
        >
          <div>
            <div className="p-2.5 rounded-xl bg-sky-950/80 border border-sky-500/30 text-sky-400 w-fit mb-3">
              <Gauge className="w-5 h-5" />
            </div>
            <h3 className="text-sm font-bold text-white group-hover:text-sky-400 transition flex items-center justify-between">
              <span>Sentinel VM Telemetry</span>
              <ArrowRight className="w-4 h-4 transform group-hover:translate-x-1 transition" />
            </h3>
            <p className="text-xs text-slate-400 mt-1.5 leading-relaxed">
              HTML5 Canvas resource waveforms with 5-phase workload spike simulation controls and audio voice dispatch.
            </p>
          </div>
          <div className="mt-4 pt-3 border-t border-slate-800 text-[11px] text-sky-300 font-mono">
            Live Stream: {telemetry ? `CPU ${telemetry.cpu_percent}% / RAM ${telemetry.ram_percent}%` : 'Connecting...'}
          </div>
        </Link>

        <Link
          to="/admin/threats"
          className="glass-card p-5 hover:border-red-500/50 transition group flex flex-col justify-between shadow-xl"
        >
          <div>
            <div className="p-2.5 rounded-xl bg-red-950/80 border border-red-500/30 text-red-400 w-fit mb-3">
              <ShieldAlert className="w-5 h-5" />
            </div>
            <h3 className="text-sm font-bold text-white group-hover:text-red-400 transition flex items-center justify-between">
              <span>Threat Center & Quarantine</span>
              <ArrowRight className="w-4 h-4 transform group-hover:translate-x-1 transition" />
            </h3>
            <p className="text-xs text-slate-400 mt-1.5 leading-relaxed">
              Examine LightGBM structural threat scores and manage isolated malware payloads safely.
            </p>
          </div>
          <div className="mt-4 pt-3 border-t border-slate-800 text-[11px] text-red-400 font-mono">
            3-Second Siren Integration Active
          </div>
        </Link>
      </div>
    </div>
  );
}
