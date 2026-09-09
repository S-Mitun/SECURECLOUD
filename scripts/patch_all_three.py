# 1. Patch QuarantineVault.jsx
with open("frontend/src/pages/admin/QuarantineVault.jsx", "r", encoding="utf-8") as f:
    q_text = f.read()

old_q_td = """                <td>
                  <div className="space-y-1 max-w-[150px]">
                    <div className="flex items-center justify-between text-[10px] font-mono">
                      <span className="text-rose-400 font-bold">{score}% Malicious</span>
                      <span className="text-slate-400">{probs.CLEAN?.toFixed(0) || 0}% Clean</span>
                    </div>
                    <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden flex">
                      <div style={{ width: `${probs.MALICIOUS || score}%` }} className="bg-rose-500 h-full"></div>
                      <div style={{ width: `${probs.SUSPICIOUS || 10}%` }} className="bg-amber-500 h-full"></div>
                      <div style={{ width: `${probs.CLEAN || 5}%` }} className="bg-emerald-500 h-full"></div>
                    </div>
                  </div>
                </td>"""

new_q_td = """                <td>
                  <div className="space-y-1.5 min-w-[130px] max-w-[170px]">
                    <div className="flex items-center justify-between text-xs font-mono font-bold">
                      {score >= 70 ? (
                        <span className="text-rose-400 font-black">Malicious {score}%</span>
                      ) : score >= 40 ? (
                        <span className="text-amber-400 font-black">Suspicious {score}%</span>
                      ) : (
                        <span className="text-emerald-400 font-black">Clean {score}%</span>
                      )}
                    </div>
                    <div className="w-full h-2 bg-slate-800 rounded-full overflow-hidden">
                      <div
                        style={{ width: `${Math.min(100, Math.max(5, score))}%` }}
                        className={`h-full rounded-full transition-all duration-300 ${
                          score >= 70 ? 'bg-rose-500 shadow-rose-500/50 shadow' : score >= 40 ? 'bg-amber-500' : 'bg-emerald-500'
                        }`}
                      ></div>
                    </div>
                  </div>
                </td>"""

if old_q_td in q_text:
    q_text = q_text.replace(old_q_td, new_q_td)
    with open("frontend/src/pages/admin/QuarantineVault.jsx", "w", encoding="utf-8") as f:
        f.write(q_text)
    print("[OK] Replaced probability TD in QuarantineVault.jsx")
else:
    print("[WARN] old_q_td not found in QuarantineVault.jsx, checking alternate...")
    # Alternate replace
    import re
    q_text = re.sub(
        r'<td>\s*<div className="space-y-1 max-w-\[150px\]">.*?</div>\s*</td>',
        new_q_td.strip(),
        q_text,
        flags=re.DOTALL
    )
    with open("frontend/src/pages/admin/QuarantineVault.jsx", "w", encoding="utf-8") as f:
        f.write(q_text)
    print("[OK] Regex replaced probability TD in QuarantineVault.jsx")

# 2. Patch SecurityDetailsModal.jsx
with open("frontend/src/components/SecurityDetailsModal.jsx", "r", encoding="utf-8") as f:
    s_text = f.read()

old_ml_section = """        {/* ML Probability Class Distribution */}
        {details?.latest_scan?.ml_probabilities && (
          <div className="glass-card p-4 border border-slate-800">
            <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider mb-3 font-mono">
              Model Classification Confidence
            </h4>
            <div className="grid grid-cols-3 gap-3 text-center">
              <div className="p-3 bg-slate-950 rounded-xl border border-slate-800">
                <div className="text-[10px] text-slate-400 font-mono">CLEAN CONFIDENCE</div>
                <div className="text-sm font-bold text-emerald-400 mt-1">
                  {details.latest_scan.ml_probabilities.CLEAN ?? 0}%
                </div>
              </div>
              <div className="p-3 bg-slate-950 rounded-xl border border-slate-800">
                <div className="text-[10px] text-slate-400 font-mono">SUSPICIOUS SCORE</div>
                <div className="text-sm font-bold text-amber-400 mt-1">
                  {details.latest_scan.ml_probabilities.SUSPICIOUS ?? 0}%
                </div>
              </div>
              <div className="p-3 bg-slate-950 rounded-xl border border-slate-800">
                <div className="text-[10px] text-slate-400 font-mono">MALICIOUS SCORE</div>
                <div className="text-sm font-bold text-red-400 mt-1">
                  {details.latest_scan.ml_probabilities.MALICIOUS ?? 0}%
                </div>
              </div>
            </div>
          </div>
        )}"""

new_ml_section = """        {/* Machine Learning Threat Breakdown */}
        {details?.latest_scan && (
          <div className="glass-card p-4 border border-slate-800 space-y-3">
            <div className="flex items-center justify-between">
              <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider font-mono">
                ML Threat Assessment Verdict
              </h4>
              <span className={`px-2 py-0.5 rounded text-xs font-mono font-bold border ${
                (details.latest_scan.threat_score || 0) >= 70
                  ? 'bg-rose-950 border-rose-500 text-rose-300'
                  : (details.latest_scan.threat_score || 0) >= 40
                  ? 'bg-amber-950 border-amber-500 text-amber-300'
                  : 'bg-emerald-950 border-emerald-500 text-emerald-300'
              }`}>
                {(details.latest_scan.threat_score || 0) >= 70
                  ? `MALICIOUS (${details.latest_scan.threat_score || 85}%)`
                  : (details.latest_scan.threat_score || 0) >= 40
                  ? `SUSPICIOUS (${details.latest_scan.threat_score || 50}%)`
                  : `CLEAN (${details.latest_scan.threat_score || 0}%)`}
              </span>
            </div>

            <div className="space-y-1.5">
              <div className="flex items-center justify-between text-xs font-mono">
                <span className="text-slate-400">Calculated Risk Index:</span>
                <span className="font-bold text-white font-mono">{details.latest_scan.threat_score || 0}%</span>
              </div>
              <div className="w-full h-2.5 bg-slate-900 rounded-full overflow-hidden border border-slate-800">
                <div
                  style={{ width: `${Math.min(100, Math.max(5, details.latest_scan.threat_score || 0))}%` }}
                  className={`h-full rounded-full transition-all duration-300 ${
                    (details.latest_scan.threat_score || 0) >= 70
                      ? 'bg-rose-500 shadow-rose-500/50 shadow'
                      : (details.latest_scan.threat_score || 0) >= 40
                      ? 'bg-amber-500'
                      : 'bg-emerald-500'
                  }`}
                ></div>
              </div>
            </div>
          </div>
        )}"""

if old_ml_section in s_text:
    s_text = s_text.replace(old_ml_section, new_ml_section)
    with open("frontend/src/components/SecurityDetailsModal.jsx", "w", encoding="utf-8") as f:
        f.write(s_text)
    print("[OK] Replaced ML breakdown in SecurityDetailsModal.jsx")
else:
    print("[WARN] old_ml_section not found in SecurityDetailsModal.jsx")
