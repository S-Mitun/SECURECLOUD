with open("frontend/src/pages/admin/SecurityPolicies.jsx", "r", encoding="utf-8") as f:
    text = f.read()

# Add state for history modal and running policy
state_add = """  const [viewingHistory, setViewingHistory] = useState(null); // { policy, history: [] }
  const [runningPolicyId, setRunningPolicyId] = useState(null);"""

if "const [viewingHistory, setViewingHistory]" not in text:
    text = text.replace(
        "const [showCreateModal, setShowCreateModal] = useState(false);",
        "const [showCreateModal, setShowCreateModal] = useState(false);\n" + state_add
    )

# Add handler functions
handler_funcs = """
  const handleViewHistory = async (policy) => {
    try {
      const res = await adminApi.getPolicyHistory(policy.id);
      setViewingHistory(res);
    } catch (err) {
      showToast(err.message || 'Failed to fetch policy execution history.', 'error');
    }
  };

  const handleManualTrigger = async (policyId) => {
    setRunningPolicyId(policyId);
    try {
      const res = await adminApi.triggerPolicyExecution(policyId);
      showToast(`⚡ ${res.message}`, 'success');
      loadPolicies();
    } catch (err) {
      showToast(err.message || 'Failed to trigger policy.', 'error');
    } finally {
      setRunningPolicyId(null);
    }
  };
"""

if "handleViewHistory" not in text:
    text = text.replace(
        "const handleCreatePolicy = async (e) => {",
        handler_funcs + "\n  const handleCreatePolicy = async (e) => {"
    )

# Add action buttons in card footer
card_footer_old = """                  <div className="pt-3 border-t border-slate-800 flex items-center justify-between">
                    <span className="text-[10px] text-slate-500 font-mono">
                      Executed: <strong className="text-slate-300">{p.execution_count || 0} times</strong>
                    </span>
                    <div className="flex items-center gap-1.5">
                      <button
                        onClick={() => handleToggle(p.id)}
                        className={`p-1.5 rounded-lg border transition ${
                          p.is_active ? 'bg-amber-950/60 text-amber-300 border-amber-500/40 hover:bg-amber-900' : 'bg-slate-800 text-slate-400 border-slate-700'
                        }`}
                        title={p.is_active ? 'Deactivate Policy' : 'Activate Policy'}
                      >
                        {p.is_active ? <ToggleRight className="w-4 h-4 text-emerald-400" /> : <ToggleLeft className="w-4 h-4 text-slate-500" />}
                      </button>
                      <button
                        onClick={() => handleDelete(p.id)}
                        className="p-1.5 bg-slate-800 hover:bg-rose-950 text-slate-400 hover:text-rose-400 border border-slate-700 hover:border-rose-500/40 rounded-lg transition"
                        title="Delete Policy"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </div>"""

card_footer_new = """                  <div className="pt-3 border-t border-slate-800 flex flex-wrap items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <span className="text-[10px] text-slate-400 font-mono">
                        Executed: <strong className="text-amber-400">{p.execution_count || 0} times</strong>
                      </span>
                      <button
                        onClick={() => handleViewHistory(p)}
                        className="px-2 py-0.5 bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white rounded text-[10px] font-mono border border-slate-700 flex items-center gap-1 transition"
                        title="View Chronological Execution Logs"
                      >
                        <Sliders className="w-3 h-3 text-sky-400" /> Logs
                      </button>
                    </div>
                    <div className="flex items-center gap-1.5">
                      <button
                        onClick={() => handleManualTrigger(p.id)}
                        disabled={runningPolicyId === p.id}
                        className="px-2.5 py-1 bg-amber-600 hover:bg-amber-500 text-white rounded-lg text-xs font-mono font-bold flex items-center gap-1 transition shadow"
                        title="Trigger Automated Policy Test Execution"
                      >
                        {runningPolicyId === p.id ? <RefreshCw className="w-3 h-3 animate-spin" /> : <Play className="w-3 h-3" />}
                        <span>Run Test</span>
                      </button>

                      <button
                        onClick={() => handleToggle(p.id)}
                        className={`p-1.5 rounded-lg border transition ${
                          p.is_active ? 'bg-amber-950/60 text-amber-300 border-amber-500/40 hover:bg-amber-900' : 'bg-slate-800 text-slate-400 border-slate-700'
                        }`}
                        title={p.is_active ? 'Deactivate Policy' : 'Activate Policy'}
                      >
                        {p.is_active ? <ToggleRight className="w-4 h-4 text-emerald-400" /> : <ToggleLeft className="w-4 h-4 text-slate-500" />}
                      </button>
                      <button
                        onClick={() => handleDelete(p.id)}
                        className="p-1.5 bg-slate-800 hover:bg-rose-950 text-slate-400 hover:text-rose-400 border border-slate-700 hover:border-rose-500/40 rounded-lg transition"
                        title="Delete Policy"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </div>"""

if card_footer_old in text:
    text = text.replace(card_footer_old, card_footer_new)

# Add Execution History Modal at bottom
history_modal = """
      {/* Policy Execution History Modal */}
      {viewingHistory && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fade-in">
          <div className="glass-card max-w-2xl w-full border border-amber-500/40 shadow-2xl p-6 relative space-y-4 animate-scale-up max-h-[85vh] flex flex-col">
            <button
              onClick={() => setViewingHistory(null)}
              className="absolute right-4 top-4 text-slate-400 hover:text-white p-1 rounded-lg"
            >
              <X className="w-5 h-5" />
            </button>

            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-xl bg-amber-950 border border-amber-500/40 flex items-center justify-center text-amber-400">
                <Zap className="w-5 h-5" />
              </div>
              <div>
                <h3 className="text-base font-black text-white">{viewingHistory.policy_name}</h3>
                <p className="text-xs text-slate-400 font-mono">
                  Autonomous SOAR Execution History • Total Triggers: {viewingHistory.execution_count}
                </p>
              </div>
            </div>

            <div className="flex-1 overflow-y-auto space-y-2.5 pr-1">
              {viewingHistory.history?.map((log, idx) => (
                <div key={idx} className="p-3 bg-slate-950 rounded-xl border border-slate-800 space-y-1 font-mono text-xs">
                  <div className="flex items-center justify-between">
                    <span className="text-amber-400 font-bold">{log.trigger_event}</span>
                    <span className="text-[10px] text-slate-500">{log.timestamp}</span>
                  </div>
                  <div className="text-slate-300">Target: <span className="text-white font-semibold">{log.target}</span></div>
                  <div className="text-slate-400 text-[11px] leading-relaxed">{log.details}</div>
                  <div className="flex items-center gap-1.5 pt-1">
                    <span className="px-1.5 py-0.2 bg-emerald-950 border border-emerald-500/40 text-emerald-300 text-[10px] rounded">
                      SUCCESS
                    </span>
                    {log.actions_applied?.map((act, i) => (
                      <span key={i} className="px-1.5 py-0.2 bg-slate-900 border border-slate-700 text-slate-300 text-[10px] rounded">
                        {act}
                      </span>
                    ))}
                  </div>
                </div>
              ))}
            </div>

            <div className="flex justify-end pt-2 border-t border-slate-800">
              <button
                onClick={() => setViewingHistory(null)}
                className="px-4 py-2 bg-slate-900 hover:bg-slate-800 text-slate-300 rounded-xl text-xs font-semibold"
              >
                Close Logs
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}"""

if "{viewingHistory && (" not in text:
    text = text.replace("    </div>\n  );\n}", history_modal)

with open("frontend/src/pages/admin/SecurityPolicies.jsx", "w", encoding="utf-8") as f:
    f.write(text)

print("[OK] Updated SecurityPolicies.jsx with execution history modal and manual test trigger!")
