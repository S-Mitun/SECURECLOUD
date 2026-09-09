with open("frontend/src/pages/admin/ThreatCorrelation.jsx", "r", encoding="utf-8") as f:
    text = f.read()

# Fix imports to include X and Link
text = text.replace(
    "import React, { useEffect, useState } from 'react';",
    "import React, { useEffect, useState } from 'react';\nimport { Link } from 'react-router-dom';"
)

text = text.replace(
    "FileWarning, Globe, Hash, Zap, Check",
    "FileWarning, Globe, Hash, Zap, Check, X, ExternalLink, ShieldCheck, Lock"
)

# Enhanced mitigation war room report modal
enhanced_war_room_modal = """      {/* Automated Mitigation War-Room Execution Modal */}
      {mitigationReport && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/85 backdrop-blur-md animate-fade-in">
          <div className="glass-card max-w-xl w-full border border-emerald-500/60 shadow-2xl p-6 relative space-y-4 animate-scale-up bg-slate-950/95">
            <button
              onClick={() => setMitigationReport(null)}
              className="absolute right-4 top-4 text-slate-400 hover:text-white p-1 rounded-lg bg-slate-900 border border-slate-800 transition"
            >
              <X className="w-4 h-4" />
            </button>

            <div className="flex items-center gap-3">
              <div className="w-12 h-12 rounded-xl bg-emerald-950 border border-emerald-500/60 flex items-center justify-center text-emerald-400 shadow-lg shadow-emerald-950/50">
                <ShieldCheck className="w-6 h-6 animate-pulse" />
              </div>
              <div>
                <h3 className="text-base font-black text-white flex items-center gap-2">
                  SOC Mitigation War-Room
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-950 text-emerald-300 border border-emerald-500/40">
                    ENFORCED
                  </span>
                </h3>
                <p className="text-xs text-emerald-300 font-mono">
                  {mitigationReport.cluster?.cluster_id || 'THREAT CLUSTER'} • STATUS: RESOLVED (0% ACTIVE RISK)
                </p>
              </div>
            </div>

            <div className="bg-slate-900/90 p-4 rounded-xl border border-slate-800 space-y-3 font-mono text-xs">
              <div className="flex items-center justify-between pb-2 border-b border-slate-800">
                <span className="text-slate-400">Triggered Directive:</span>
                <span className="font-bold text-white text-right max-w-[300px] truncate">{mitigationReport.action}</span>
              </div>
              
              <div className="space-y-2">
                <div className="text-[10px] text-slate-500 uppercase font-bold tracking-wider">Applied Countermeasures:</div>
                {mitigationReport.actions_taken?.map((act, idx) => (
                  <div key={idx} className="flex items-start gap-2 text-slate-200 bg-slate-950 p-2 rounded-lg border border-slate-800/80">
                    <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                    <span className="leading-snug">{act}</span>
                  </div>
                ))}
              </div>

              <div className="pt-2 border-t border-slate-800 flex flex-wrap items-center gap-2">
                <span className="text-[10px] text-slate-500">Live Verification Hubs:</span>
                <Link
                  to="/admin/ip-guard"
                  className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-sky-300 rounded text-[10px] font-mono flex items-center gap-1 transition"
                >
                  <Globe className="w-3 h-3 text-sky-400" /> IP Guard Rules
                </Link>
                <Link
                  to="/admin/quarantine"
                  className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-rose-300 rounded text-[10px] font-mono flex items-center gap-1 transition"
                >
                  <ShieldAlert className="w-3 h-3 text-rose-400" /> Quarantine Vault
                </Link>
              </div>
            </div>

            <div className="flex justify-end pt-1">
              <button
                onClick={() => setMitigationReport(null)}
                className="btn-cyber px-6 py-2 rounded-xl text-xs font-bold font-mono tracking-wider"
              >
                Close War-Room
              </button>
            </div>
          </div>
        </div>
      )}"""

# Replace the previous mitigation modal
import re
text = re.sub(
    r'\{\/\* Automated Mitigation Execution Report Modal \*\/\}[\s\S]*?className="btn-cyber px-5 py-2 rounded-xl text-xs font-bold"\s*>[\s\S]*?<\/div>\s*<\/div>\s*\)\}',
    enhanced_war_room_modal.strip(),
    text
)

with open("frontend/src/pages/admin/ThreatCorrelation.jsx", "w", encoding="utf-8") as f:
    f.write(text)

print("[OK] Updated ThreatCorrelation.jsx with War-Room modal and fixed icon imports!")
