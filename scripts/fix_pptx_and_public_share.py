# 1. Patch frontend/src/components/PresentationViewer.jsx
with open("frontend/src/components/PresentationViewer.jsx", "r", encoding="utf-8") as f:
    pv_text = f.read()

old_pv_sig = "export function PresentationViewer({ presentationData, filename, isFullscreen = false }) {"
new_pv_sig = """export function PresentationViewer({ presentationData, data, filename, isFullscreen = false, downloadUrl }) {
  const pData = presentationData || data || {};"""

pv_text = pv_text.replace(old_pv_sig, new_pv_sig)
pv_text = pv_text.replace("const slides = presentationData?.slides || [];", "const slides = pData?.slides || [];")
pv_text = pv_text.replace("const aspectRatio = presentationData?.aspect_ratio || 1.778;", "const aspectRatio = pData?.aspect_ratio || 1.778;")
pv_text = pv_text.replace("if (!presentationData || totalSlides === 0) {", "if (!pData || totalSlides === 0) {")

with open("frontend/src/components/PresentationViewer.jsx", "w", encoding="utf-8") as f:
    f.write(pv_text)
print("[OK] Patched PresentationViewer.jsx to support both presentationData and data props!")

# 2. Patch frontend/src/components/FileViewerModal.jsx
with open("frontend/src/components/FileViewerModal.jsx", "r", encoding="utf-8") as f:
    fv_text = f.read()

old_fv_pv = """        {(isPptx || viewData.format === 'PRESENTATION_RENDERED' || viewData.format === 'PPTX_RENDERED') && (
          <PresentationViewer
            data={viewData}
            filename={filename}
            downloadUrl={downloadUrl}
          />
        )}"""

new_fv_pv = """        {(isPptx || viewData.format === 'PRESENTATION_RENDERED' || viewData.format === 'PPTX_RENDERED') && (
          <PresentationViewer
            presentationData={viewData}
            data={viewData}
            filename={filename}
            downloadUrl={downloadUrl}
          />
        )}"""

if old_fv_pv in fv_text:
    fv_text = fv_text.replace(old_fv_pv, new_fv_pv)
    with open("frontend/src/components/FileViewerModal.jsx", "w", encoding="utf-8") as f:
        f.write(fv_text)
    print("[OK] Patched FileViewerModal.jsx PPTX invocation!")

# 3. Patch frontend/src/pages/PublicShareView.jsx
with open("frontend/src/pages/PublicShareView.jsx", "r", encoding="utf-8") as f:
    ps_text = f.read()

# Import API_BASE_URL
if "import { API_BASE_URL } from '../api/apiClient';" not in ps_text:
    ps_text = ps_text.replace(
        "import React, { useState, useEffect, useRef } from 'react';",
        "import React, { useState, useEffect, useRef } from 'react';\nimport { API_BASE_URL } from '../api/apiClient';"
    )

# Replace all hardcoded http://127.0.0.1:8000
ps_text = ps_text.replace("http://127.0.0.1:8000", "${API_BASE_URL}")

# Fix optional chaining across header and main
ps_text = ps_text.replace("shareInfo.views_count", "shareInfo?.views_count")
ps_text = ps_text.replace("shareInfo.is_expiring", "shareInfo?.is_expiring")
ps_text = ps_text.replace("shareInfo.expires_in_hours", "shareInfo?.expires_in_hours")
ps_text = ps_text.replace("shareInfo.allow_download", "shareInfo?.allow_download")
ps_text = ps_text.replace("shareInfo.view_only", "shareInfo?.view_only")

# Fix null shareInfo guard
old_null_guard = """  if (shareInfo?.is_password_protected && !isUnlocked) {
    return (
      <div className="w-screen h-screen bg-slate-950 flex items-center justify-center p-4">
        <div className="glass-card p-8 max-w-md w-full border border-sky-500/40 shadow-2xl space-y-5">
          <div className="text-center space-y-2">
            <div className="w-12 h-12 rounded-2xl bg-sky-950 border border-sky-500/40 flex items-center justify-center mx-auto text-sky-400">
              <Lock className="w-6 h-6" />
            </div>
            <h2 className="text-xl font-black text-white">Password Protected File</h2>
            <p className="text-xs text-slate-400 font-mono">
              <strong>{shareInfo.filename}</strong> is protected with end-to-end access authentication.
            </p>
          </div>

          <form onSubmit={handleVerifyPassword} className="space-y-4">
            <div>
              <label className="block text-xs font-semibold text-slate-300 mb-1">
                Enter Decryption Password:
              </label>
              <div className="relative">
                <Key className="w-4 h-4 text-slate-500 absolute left-3 top-3" />
                <input
                  type="password"
                  placeholder="Password..."
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                  autoFocus
                  className="w-full bg-slate-900 border border-slate-700 rounded-xl pl-9 pr-3 py-2.5 text-white text-xs font-mono focus:outline-none focus:border-sky-500"
                />
              </div>
            </div>

            <button
              type="submit"
              disabled={verifying}
              className="btn-cyber w-full py-2.5 rounded-xl text-xs font-bold flex items-center justify-center gap-2"
            >
              {verifying ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Eye className="w-4 h-4" />}
              Unlock & View File
            </button>
          </form>
        </div>
      </div>
    );
  }"""

new_null_guard = old_null_guard + """

  if (!shareInfo) {
    return (
      <div className="w-screen h-screen bg-slate-950 flex flex-col items-center justify-center text-slate-400 font-mono text-xs gap-3">
        <RefreshCw className="w-8 h-8 text-sky-400 animate-spin" />
        <div>CONNECTING TO SECURE CLOUD STORAGE GATEWAY...</div>
      </div>
    );
  }"""

ps_text = ps_text.replace(old_null_guard, new_null_guard)

with open("frontend/src/pages/PublicShareView.jsx", "w", encoding="utf-8") as f:
    f.write(ps_text)

print("[OK] Patched PublicShareView.jsx with API_BASE_URL, safe chaining, and fallback!")
