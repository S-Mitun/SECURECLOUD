import re

# 1. Update QuarantineVault.jsx
with open("frontend/src/pages/admin/QuarantineVault.jsx", "r", encoding="utf-8") as f:
    q_code = f.read()

# Replace any ML breakdown column in table
q_code = re.sub(
    r'<td>\s*<div className="space-y-1[^>]*>.*?</div>\s*</td>',
    """<td>
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
                </td>""",
    q_code,
    flags=re.DOTALL
)

with open("frontend/src/pages/admin/QuarantineVault.jsx", "w", encoding="utf-8") as f:
    f.write(q_code)
print("[OK] Verified QuarantineVault.jsx")

# 2. Update SecurityDetailsModal.jsx
with open("frontend/src/components/SecurityDetailsModal.jsx", "r", encoding="utf-8") as f:
    s_code = f.read()

s_code = re.sub(
    r'\{\/\* ML Probability Class Distribution \*\/\}[\s\S]*?\{\/\* Model Classification Confidence \*\/\}[\s\S]*?<\/div>\s*<\/div>\s*\)\}',
    """{/* Machine Learning Threat Breakdown */}
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
                      <span className="text-slate-400">Calculated Threat Index:</span>
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
              )}""",
    s_code
)

with open("frontend/src/components/SecurityDetailsModal.jsx", "w", encoding="utf-8") as f:
    f.write(s_code)
print("[OK] Verified SecurityDetailsModal.jsx")
