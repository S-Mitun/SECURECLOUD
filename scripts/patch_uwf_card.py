with open("frontend/src/pages/admin/UserWiseFiles.jsx", "r", encoding="utf-8") as f:
    text = f.read()

# 1. Update user card header badges
old_role_badge = """                        <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase border ${
                          group.role === 'ADMIN'
                            ? 'bg-cyan-950/80 border-cyan-500 text-cyan-300'
                            : 'bg-slate-900 border-slate-700 text-slate-300'
                        }`}>
                          {group.role}
                        </span>"""

new_role_badge = """                        <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase border ${
                          group.role === 'ADMIN'
                            ? 'bg-cyan-950/80 border-cyan-500 text-cyan-300'
                            : 'bg-slate-900 border-slate-700 text-slate-300'
                        }`}>
                          {group.role}
                        </span>

                        {group.is_admin_protected && (
                          <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold flex items-center gap-1 border ${
                            unlockedAdminIds[group.user_id]
                              ? 'bg-emerald-950 border-emerald-500/50 text-emerald-300'
                              : 'bg-amber-950 border-amber-500/50 text-amber-300 animate-pulse'
                          }`}>
                            {unlockedAdminIds[group.user_id] ? <Unlock className="w-3 h-3" /> : <Lock className="w-3 h-3" />}
                            {unlockedAdminIds[group.user_id] ? 'Dual-Auth Unlocked' : 'Dual-Auth Protected'}
                          </span>
                        )}"""

if "{group.is_admin_protected && (" not in text:
    text = text.replace(old_role_badge, new_role_badge)

# 2. Add Unlock/Lock Vault button in header
old_file_count_badge = """                    {/* Total Files Stored */}
                    <div className="bg-slate-900/90 border border-slate-800 px-3 py-1.5 rounded-xl font-mono text-xs">
                      <span className="text-slate-400">Files: </span>
                      <span className="text-sky-300 font-bold">{group.files?.length || 0}</span>
                    </div>"""

new_file_count_badge = """                    {/* Total Files Stored */}
                    <div className="bg-slate-900/90 border border-slate-800 px-3 py-1.5 rounded-xl font-mono text-xs">
                      <span className="text-slate-400">Files: </span>
                      <span className="text-sky-300 font-bold">{group.files?.length || 0}</span>
                    </div>

                    {group.is_admin_protected && (
                      <button
                        onClick={() => {
                          if (unlockedAdminIds[group.user_id]) {
                            const copy = { ...unlockedAdminIds };
                            delete copy[group.user_id];
                            setUnlockedAdminIds(copy);
                            showToast(`Re-locked ${group.username}'s repository.`, 'info');
                          } else {
                            setUnlockVaultModal({ user: group, pin: '' });
                          }
                        }}
                        className={`px-3 py-1.5 rounded-xl text-xs font-mono font-bold flex items-center gap-1.5 transition border ${
                          unlockedAdminIds[group.user_id]
                            ? 'bg-slate-900 hover:bg-slate-800 text-slate-300 border-slate-700'
                            : 'bg-amber-950/80 hover:bg-amber-900 text-amber-300 hover:text-white border-amber-500/50 shadow-lg'
                        }`}
                      >
                        {unlockedAdminIds[group.user_id] ? <Lock className="w-3.5 h-3.5" /> : <Unlock className="w-3.5 h-3.5" />}
                        <span>{unlockedAdminIds[group.user_id] ? 'Lock Vault' : 'Unlock Repository'}</span>
                      </button>
                    )}"""

if "group.is_admin_protected && (" not in text or "Lock Vault" not in text:
    text = text.replace(old_file_count_badge, new_file_count_badge)

with open("frontend/src/pages/admin/UserWiseFiles.jsx", "w", encoding="utf-8") as f:
    f.write(text)

print("[OK] Successfully patched UserWiseFiles card header!")
