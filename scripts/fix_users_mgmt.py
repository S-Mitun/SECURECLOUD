with open("frontend/src/pages/admin/UsersManagement.jsx", "r", encoding="utf-8") as f:
    text = f.read()

old_block = """                        <button
                          onClick={() => handleToggleStatus(u)}
                          title={u.is_active ? 'Suspend Account' : 'Activate Account'}
                          className={`p-1.5 rounded-lg border transition ${
                            u.is_active
                              ? 'bg-slate-800 hover:bg-red-950 text-slate-300 hover:text-red-300 border-slate-700 hover:border-red-500/40'
                              : 'bg-slate-800 hover:bg-emerald-950 text-slate-300 hover:text-emerald-300 border-slate-700 hover:border-emerald-500/40'
                          }`}
                        >
                          {u.is_active ? <UserX className="w-3.5 h-3.5" /> : <UserCheck className="w-3.5 h-3.5" />}
                        </button>"""

new_block = """                        <button
                          onClick={() => {
                            if (u.role === 'ADMIN') {
                              showToast('Security Policy: Administrators cannot suspend other Administrator accounts.', 'warning');
                              return;
                            }
                            handleToggleStatus(u);
                          }}
                          disabled={u.role === 'ADMIN'}
                          title={u.role === 'ADMIN' ? 'Administrator accounts cannot be suspended' : (u.is_active ? 'Suspend Account' : 'Activate Account')}
                          className={`p-1.5 rounded-lg border transition ${
                            u.role === 'ADMIN'
                              ? 'bg-slate-900 text-slate-600 border-slate-800 cursor-not-allowed opacity-50'
                              : u.is_active
                              ? 'bg-slate-800 hover:bg-red-950 text-slate-300 hover:text-red-300 border-slate-700 hover:border-red-500/40'
                              : 'bg-slate-800 hover:bg-emerald-950 text-slate-300 hover:text-emerald-300 border-slate-700 hover:border-emerald-500/40'
                          }`}
                        >
                          {u.is_active ? <UserX className="w-3.5 h-3.5" /> : <UserCheck className="w-3.5 h-3.5" />}
                        </button>"""

text = text.replace(old_block, new_block)

with open("frontend/src/pages/admin/UsersManagement.jsx", "w", encoding="utf-8") as f:
    f.write(text)

print("[OK] Updated UsersManagement.jsx disable suspend for admins!")
