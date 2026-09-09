import React, { useEffect, useState } from 'react';
import { adminApi } from '../../api/adminApi';
import { useApp } from '../../context/AppContext';
import { 
  Users, RefreshCw, Shield, Edit3, UserCheck, UserX, HardDrive, 
  Search, ShieldAlert, KeyRound, CheckCircle2, AlertTriangle
} from 'lucide-react';
import { EditQuotaModal } from '../../components/EditQuotaModal';

export function UsersManagement() {
  const { openModal, showToast } = useApp();
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');

  const loadUsers = async () => {
    setLoading(true);
    try {
      const data = await adminApi.listUsers();
      setUsers(Array.isArray(data) ? data : (data.users || []));
    } catch (err) {
      showToast(err.message || 'Failed to load user directory.', 'error');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadUsers();
  }, []);

  const handleToggleStatus = async (user) => {
    const actionName = user.is_active ? 'suspend' : 'activate';
    if (!window.confirm(`Are you sure you want to ${actionName} user "${user.username}"?`)) return;

    try {
      await adminApi.toggleUserStatus(user.id);
      showToast(`User "${user.username}" ${actionName}ed successfully!`, 'success');
      loadUsers();
    } catch (err) {
      showToast(err.message || `Failed to ${actionName} user.`, 'error');
    }
  };

  const filtered = users.filter((u) =>
    (u.username || '').toLowerCase().includes(search.toLowerCase()) ||
    (u.email || '').toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-6">
      {/* Header Banner */}
      <div className="glass-card p-6 border border-sky-500/40 bg-gradient-to-r from-slate-900 via-sky-950/20 to-slate-900 shadow-2xl flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="p-3 rounded-xl bg-sky-950/90 border border-sky-500/50 text-sky-400">
            <Users className="w-8 h-8" />
          </div>
          <div>
            <h1 className="text-xl font-black text-white tracking-wide flex items-center gap-2">
              Identity & Access Management (IAM)
              <span className="px-2 py-0.5 bg-sky-950 border border-sky-500/40 text-sky-300 text-[10px] rounded font-mono">
                RBAC ACTIVE
              </span>
            </h1>
            <p className="text-xs text-slate-400 mt-1">
              Manage user accounts, risk posture, active status, and custom cloud storage quotas.
            </p>
          </div>
        </div>
        <button
          onClick={loadUsers}
          className="p-2 bg-slate-900 hover:bg-slate-800 text-slate-300 hover:text-white border border-slate-800 rounded-lg text-xs flex items-center gap-1.5 transition"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} /> Refresh Accounts
        </button>
      </div>

      {/* Search Filter */}
      <div className="glass-card p-4">
        <div className="relative">
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search by username or email address..."
            className="w-full bg-slate-900 border border-slate-700 rounded-lg pl-9 pr-3.5 py-2 text-xs text-white focus:outline-none focus:border-sky-500"
          />
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
        </div>
      </div>

      {/* Users IAM Table */}
      <div className="glass-card overflow-hidden border border-slate-800 shadow-2xl">
        <div className="overflow-x-auto">
          <table className="soc-table">
            <thead>
              <tr>
                <th>Account Identity</th>
                <th>Portal Role</th>
                <th>Storage Quota</th>
                <th>Security Risk</th>
                <th>Status</th>
                <th>Last Login</th>
                <th className="text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr>
                  <td colSpan="7" className="text-center py-16 text-slate-400 font-mono text-xs">
                    <RefreshCw className="w-5 h-5 animate-spin mx-auto mb-2 text-sky-400" />
                    FETCHING IDENTITY PROVIDER DIRECTORY...
                  </td>
                </tr>
              ) : filtered.length > 0 ? (
                filtered.map((u) => {
                  const lastLoginDisplay = u.last_login_at || u.last_login || (u.created_at ? `${u.created_at}` : 'Active');

                  return (
                    <tr key={u.id}>
                      <td>
                        <div className="flex items-center gap-2.5">
                          <div className="w-8 h-8 rounded-lg bg-sky-950 border border-sky-500/30 flex items-center justify-center text-sky-400 font-bold text-xs">
                            {(u.username || 'U').substring(0, 2).toUpperCase()}
                          </div>
                          <div>
                            <div className="font-bold text-white text-xs sm:text-sm">
                              {u.username}
                            </div>
                            <div className="text-[10px] text-slate-400 font-mono">
                              {u.email}
                            </div>
                          </div>
                        </div>
                      </td>
                      <td>
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase font-mono ${
                            u.role === 'ADMIN'
                              ? 'bg-cyan-950 border border-cyan-500/50 text-cyan-300'
                              : 'bg-slate-800 text-slate-300'
                          }`}
                        >
                          {u.role}
                        </span>
                      </td>
                      <td className="font-mono text-xs text-slate-300">
                        <div>{u.used_quota_formatted || '0 B'} / {u.quota_formatted || '10 GB'}</div>
                      </td>
                      <td>
                        <span
                          className={`px-2 py-0.5 rounded text-xs font-mono font-bold ${
                            (u.risk_score || 0) > 50
                              ? 'bg-red-950/80 text-red-400 border border-red-500/40'
                              : 'bg-emerald-950/80 text-emerald-400 border border-emerald-500/40'
                          }`}
                        >
                          {u.risk_score || 0}% Risk
                        </span>
                      </td>
                      <td>
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                            u.is_active
                              ? 'bg-emerald-950/80 text-emerald-400 border border-emerald-500/40'
                              : 'bg-red-950/80 text-red-400 border border-red-500/40'
                          }`}
                        >
                          {u.is_active ? 'ACTIVE' : 'SUSPENDED'}
                        </span>
                      </td>
                      <td className="font-mono text-xs text-slate-400">
                        {lastLoginDisplay}
                      </td>
                      <td className="text-right">
                        <div className="flex items-center justify-end gap-1.5">
                          <button
                            onClick={() => openModal('editQuota', u)}
                            title="Adjust Storage Quota"
                            className="p-1.5 bg-slate-800 hover:bg-sky-950 text-slate-300 hover:text-sky-300 border border-slate-700 hover:border-sky-500/40 rounded-lg transition"
                          >
                            <Edit3 className="w-3.5 h-3.5" />
                          </button>
                          <button
                            onClick={() => handleToggleStatus(u)}
                            title={u.is_active ? 'Suspend Account' : 'Activate Account'}
                            className={`p-1.5 rounded-lg border transition ${
                              u.is_active
                                ? 'bg-slate-800 hover:bg-red-950 text-slate-300 hover:text-red-300 border-slate-700 hover:border-red-500/40'
                                : 'bg-slate-800 hover:bg-emerald-950 text-slate-300 hover:text-emerald-300 border-slate-700 hover:border-emerald-500/40'
                            }`}
                          >
                            {u.is_active ? <UserX className="w-3.5 h-3.5" /> : <UserCheck className="w-3.5 h-3.5" />}
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })
              ) : (
                <tr>
                  <td colSpan="7" className="text-center py-12 text-slate-500 text-xs">
                    No accounts found matching your query.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      <EditQuotaModal onSuccess={loadUsers} />
    </div>
  );
}
