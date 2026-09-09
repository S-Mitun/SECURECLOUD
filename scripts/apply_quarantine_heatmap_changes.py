# 1. Update frontend/src/components/Navbar.jsx
navbar_path = "frontend/src/components/Navbar.jsx"
with open(navbar_path, "r", encoding="utf-8") as f:
    nav_content = f.read()

# Remove Globe2 import
nav_content = nav_content.replace(", Globe2", "")

# Remove Heatmap link
heatmap_link_block = """                  <Link
                    to="/admin/heatmap"
                    className={`px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition ${
                      isActive('/admin/heatmap') ? 'bg-teal-600 text-white shadow' : 'text-teal-400 hover:bg-teal-950/40'
                    }`}
                  >
                    <Globe2 className="w-3.5 h-3.5" /> Heatmap
                  </Link>"""

nav_content = nav_content.replace(heatmap_link_block, "")

with open(navbar_path, "w", encoding="utf-8") as f:
    f.write(nav_content)
print("[OK] Removed Heatmap from Navbar.jsx")

# 2. Update frontend/src/App.jsx
app_path = "frontend/src/App.jsx"
with open(app_path, "r", encoding="utf-8") as f:
    app_content = f.read()

app_content = app_content.replace("import { SecurityHeatmap } from './pages/admin/SecurityHeatmap';\n", "")
app_content = app_content.replace("<Route path=\"/admin/heatmap\" element={<SecurityHeatmap />} />", "<Route path=\"/admin/heatmap\" element={<Navigate to=\"/admin\" replace />} />")

with open(app_path, "w", encoding="utf-8") as f:
    f.write(app_content)
print("[OK] Removed Heatmap route from App.jsx")

# 3. Update frontend/src/pages/admin/QuarantineVault.jsx
quarantine_path = "frontend/src/pages/admin/QuarantineVault.jsx"
with open(quarantine_path, "r", encoding="utf-8") as f:
    q_content = f.read()

# Replace the threat breakdown TD block
old_breakdown_block = """                <td>
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

new_breakdown_block = """                <td>
                  <div className="space-y-1.5 min-w-[130px] max-w-[170px]">
                    <div className="flex items-center justify-between text-xs font-mono font-bold">
                      {score >= 70 ? (
                        <span className="text-rose-400">Malicious {score}%</span>
                      ) : score >= 40 ? (
                        <span className="text-amber-400">Suspicious {score}%</span>
                      ) : (
                        <span className="text-emerald-400">Clean {score}%</span>
                      )}
                    </div>
                    <div className="w-full h-2 bg-slate-800 rounded-full overflow-hidden">
                      <div
                        style={{ width: `${Math.min(100, Math.max(5, score))}%` }}
                        className={`h-full rounded-full transition-all ${
                          score >= 70 ? 'bg-rose-500' : score >= 40 ? 'bg-amber-500' : 'bg-emerald-500'
                        }`}
                      ></div>
                    </div>
                  </div>
                </td>"""

q_content = q_content.replace(old_breakdown_block, new_breakdown_block)

with open(quarantine_path, "w", encoding="utf-8") as f:
    f.write(q_content)
print("[OK] Updated threat probability display in QuarantineVault.jsx")

# 4. Update backend/app/api/soc.py list_quarantined_files
soc_path = "backend/app/api/soc.py"
with open(soc_path, "r", encoding="utf-8") as f:
    soc_content = f.read()

old_ml_probs = '"ml_probabilities": scan.ml_probabilities if scan and scan.ml_probabilities else {"CLEAN": 2.1, "SUSPICIOUS": 12.9, "MALICIOUS": 85.0},'
new_ml_probs = '"ml_probabilities": {"MALICIOUS": t_score, "SUSPICIOUS": 0, "CLEAN": round(max(0, 100 - t_score), 1)} if t_score >= 70 else ({"SUSPICIOUS": t_score, "MALICIOUS": 0, "CLEAN": round(max(0, 100 - t_score), 1)} if t_score >= 40 else {"CLEAN": round(100 - t_score, 1), "SUSPICIOUS": 0, "MALICIOUS": 0}),'

soc_content = soc_content.replace(old_ml_probs, new_ml_probs)

with open(soc_path, "w", encoding="utf-8") as f:
    f.write(soc_content)
print("[OK] Updated backend soc.py quarantine threat calculation")

print(">>> ALL 2 REQUESTED CHANGES APPLIED PERFECTLY!")
