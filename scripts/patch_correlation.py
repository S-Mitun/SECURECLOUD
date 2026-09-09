with open("frontend/src/pages/admin/ThreatCorrelation.jsx", "r", encoding="utf-8") as f:
    text = f.read()

# Add mitigationReport state and modal
state_add = """  const [mitigationReport, setMitigationReport] = useState(null); // { cluster, actions_taken, message }"""

if "const [mitigationReport, setMitigationReport]" not in text:
    text = text.replace(
        "const [executingAction, setExecutingAction] = useState(null);",
        "const [executingAction, setExecutingAction] = useState(null);\n" + state_add
    )

old_exec_action = """  const handleExecuteAction = (actionText) => {
    setExecutingAction(actionText);
    setTimeout(() => {
      showToast(`⚡ Automated Mitigation Executed: "${actionText}"`, 'success');
      setExecutingAction(null);
    }, 1200);
  };"""

new_exec_action = """  const handleExecuteAction = async (actionText) => {
    if (!selectedCluster) return;
    setExecutingAction(actionText);
    try {
      const res = await adminApi.mitigateThreatCluster(selectedCluster.cluster_id, actionText);
      
      // Update local cluster state to MITIGATED
      setSelectedCluster(prev => ({
        ...prev,
        status: 'MITIGATED & RESOLVED',
        threat_score: 0.0
      }));
      
      if (data && data.clusters) {
        setData(prev => ({
          ...prev,
          clusters: prev.clusters.map(c => c.cluster_id === selectedCluster.cluster_id ? {
            ...c,
            status: 'MITIGATED & RESOLVED',
            threat_score: 0.0
          } : c)
        }));
      }
      
      setMitigationReport({
        cluster: selectedCluster,
        action: actionText,
        actions_taken: res.actions_taken || [actionText],
        message: res.message
      });
      showToast(`Proactive Mitigation Executed: "${actionText}"`, 'success');
    } catch (err) {
      showToast(err.message || 'Mitigation execution failed.', 'error');
    } finally {
      setExecutingAction(null);
    }
  };"""

text = text.replace(old_exec_action, new_exec_action)

# Add mitigation report modal at bottom
report_modal = """
      {/* Automated Mitigation Execution Report Modal */}
      {mitigationReport && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fade-in">
          <div className="glass-card max-w-lg w-full border border-emerald-500/50 shadow-2xl p-6 relative space-y-4 animate-scale-up">
            <button
              onClick={() => setMitigationReport(null)}
              className="absolute right-4 top-4 text-slate-400 hover:text-white p-1 rounded-lg"
            >
              <X className="w-5 h-5" />
            </button>

            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-xl bg-emerald-950 border border-emerald-500/50 flex items-center justify-center text-emerald-400">
                <CheckCircle2 className="w-6 h-6" />
              </div>
              <div>
                <h3 className="text-base font-black text-white">Automated Mitigation Completed</h3>
                <p className="text-xs text-emerald-300 font-mono">
                  {mitigationReport.cluster.cluster_id} • RESOLVED
                </p>
              </div>
            </div>

            <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-2 font-mono text-xs">
              <div className="text-slate-400"><strong>Target Policy / Action:</strong> {mitigationReport.action}</div>
              <div className="text-slate-400"><strong>Enforcement Status:</strong> <span className="text-emerald-400 font-bold">ACTIVE & APPLIED</span></div>
              <div className="pt-2 border-t border-slate-800 space-y-1.5">
                <div className="text-[10px] text-slate-500 uppercase font-bold">Actions Applied:</div>
                {mitigationReport.actions_taken.map((act, idx) => (
                  <div key={idx} className="flex items-start gap-1.5 text-slate-300">
                    <span className="text-emerald-400 font-bold">✓</span>
                    <span>{act}</span>
                  </div>
                ))}
              </div>
            </div>

            <div className="flex justify-end pt-2">
              <button
                onClick={() => setMitigationReport(null)}
                className="btn-cyber px-5 py-2 rounded-xl text-xs font-bold"
              >
                Done
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}"""

if "{mitigationReport && (" not in text:
    text = text.replace("    </div>\n  );\n}", report_modal)

with open("frontend/src/pages/admin/ThreatCorrelation.jsx", "w", encoding="utf-8") as f:
    f.write(text)

print("[OK] Updated ThreatCorrelation.jsx with real mitigation execution and report modal!")
