with open("frontend/src/pages/admin/UserRiskProfiling.jsx", "r", encoding="utf-8") as f:
    text = f.read()

# Add handlers
action_handlers = """
  const handleEnforce2FA = async (profile) => {
    try {
      const res = await adminApi.enforceUser2FA(profile.user_id);
      showToast(`🛡️ Forced 2FA verified & armed for ${profile.username}`, 'success');
      
      // Update local profile state
      setData(prev => ({
        ...prev,
        profiles: prev.profiles.map(p => p.user_id === profile.user_id ? {
          ...p,
          two_factor_enforced: true,
          risk_score: Math.max(5, p.risk_score - 20),
          risk_tier: (p.risk_score - 20) >= 75 ? 'CRITICAL' : ((p.risk_score - 20) >= 50 ? 'HIGH' : ((p.risk_score - 20) >= 25 ? 'MEDIUM' : 'LOW'))
        } : p)
      }));
    } catch (err) {
      showToast(err.message || 'Failed to enforce 2FA.', 'error');
    }
  };

  const handleLockdownUser = async (profile) => {
    if (!window.confirm(`Initiate Emergency Account Lockdown for user "${profile.username}"? All active sessions will be terminated.`)) return;
    try {
      const res = await adminApi.lockdownUserProfile(profile.user_id, 'Admin Risk Matrix Trigger');
      showToast(`🚨 Account lockdown mode active for ${profile.username}. ${res.sessions_terminated || 0} session(s) severed.`, 'success');
      
      // Update local profile state
      setData(prev => ({
        ...prev,
        profiles: prev.profiles.map(p => p.user_id === profile.user_id ? {
          ...p,
          is_active: false,
          is_locked_down: true
        } : p)
      }));
    } catch (err) {
      showToast(err.message || 'Lockdown failed.', 'error');
    }
  };
"""

if "handleEnforce2FA" not in text:
    text = text.replace(
        "const filteredProfiles = data?.profiles?.filter((p) => {",
        action_handlers + "\n  const filteredProfiles = data?.profiles?.filter((p) => {"
    )

old_buttons = """                <button
                  onClick={() => showToast(`🛡️ Forced 2FA verification policy sent to ${p.username}`, 'info')}
                  className="px-2.5 py-1 bg-slate-900 hover:bg-slate-800 text-slate-300 hover:text-white border border-slate-800 rounded-lg text-[11px] font-mono transition"
                >
                  Enforce 2FA
                </button>
                <button
                  onClick={() => showToast(`🚨 Account lockdown mode initiated for ${p.username}`, 'error')}
                  className="px-2.5 py-1 bg-rose-950 hover:bg-rose-900 text-rose-300 hover:text-white border border-rose-500/40 rounded-lg text-[11px] font-mono transition"
                >
                  Lockdown User
                </button>"""

new_buttons = """                <button
                  onClick={() => handleEnforce2FA(p)}
                  disabled={p.two_factor_enforced}
                  className={`px-2.5 py-1 rounded-lg text-[11px] font-mono transition border ${
                    p.two_factor_enforced
                      ? 'bg-emerald-950/60 text-emerald-400 border-emerald-500/40 cursor-default'
                      : 'bg-slate-900 hover:bg-slate-800 text-slate-300 hover:text-white border-slate-800'
                  }`}
                >
                  {p.two_factor_enforced ? '✓ 2FA Enforced' : 'Enforce 2FA'}
                </button>
                <button
                  onClick={() => handleLockdownUser(p)}
                  disabled={p.is_locked_down || p.is_active === false}
                  className={`px-2.5 py-1 rounded-lg text-[11px] font-mono transition border ${
                    p.is_locked_down || p.is_active === false
                      ? 'bg-slate-900 text-slate-500 border-slate-800 cursor-not-allowed'
                      : 'bg-rose-950 hover:bg-rose-900 text-rose-300 hover:text-white border-rose-500/40'
                  }`}
                >
                  {p.is_locked_down || p.is_active === false ? '🔒 Locked Down' : 'Lockdown User'}
                </button>"""

if old_buttons in text:
    text = text.replace(old_buttons, new_buttons)

with open("frontend/src/pages/admin/UserRiskProfiling.jsx", "w", encoding="utf-8") as f:
    f.write(text)

print("[OK] Updated UserRiskProfiling.jsx with real 2FA and Lockdown actions!")
