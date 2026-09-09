with open("frontend/src/pages/admin/UserWiseFiles.jsx", "r", encoding="utf-8") as f:
    text = f.read()

# 1. Imports
if "fileApi" not in text:
    text = text.replace(
        "import { adminApi } from '../../api/adminApi';",
        "import { adminApi } from '../../api/adminApi';\nimport { fileApi } from '../../api/fileApi';"
    )

if "AdminSecurityConfigModal" not in text:
    text = text.replace(
        "import { SecurityDetailsModal } from '../../components/SecurityDetailsModal';",
        "import { SecurityDetailsModal } from '../../components/SecurityDetailsModal';\nimport { AdminSecurityConfigModal } from '../../components/AdminSecurityConfigModal';"
    )

if "useRef" not in text:
    text = text.replace(
        "import React, { useEffect, useState } from 'react';",
        "import React, { useEffect, useState, useRef } from 'react';"
    )

if "UploadCloud" not in text:
    text = text.replace(
        "CheckCircle2, Lock",
        "CheckCircle2, Lock, Unlock, UploadCloud, KeyRound, Sparkles, X"
    )

# 2. Add state
if "uploading" not in text:
    text = text.replace(
        "const [dualAdminModal, setDualAdminModal] = useState(null);",
        "const [dualAdminModal, setDualAdminModal] = useState(null);\n  const [unlockVaultModal, setUnlockVaultModal] = useState(null);\n  const [unlockedAdminIds, setUnlockedAdminIds] = useState({});\n  const [showConfigModal, setShowConfigModal] = useState(false);\n  const [uploading, setUploading] = useState(false);\n  const [uploadStage, setUploadStage] = useState('');\n  const fileInputRef = useRef(null);"
    )

# 3. Add admin upload & unlock functions
helper_funcs = """
  const handleAdminFileUpload = async (e) => {
    const files = Array.from(e.target.files || []);
    if (files.length === 0) return;

    setUploading(true);
    try {
      for (let i = 0; i < files.length; i++) {
        const file = files[i];
        setUploadStage(`Processing ${file.name} (${i + 1}/${files.length})...`);
        const res = await fileApi.uploadFile(file, (pct) => {
          setUploadStage(`Uploading ${file.name}: ${pct}% (ML Threat Inference)...`);
        });

        if (res.scan && res.scan.security_status === 'MALICIOUS') {
          triggerCriticalAlert({
            filename: file.name,
            threat_score: res.scan.threat_score || 85.0
          });
        }
      }
      showToast(`Successfully uploaded & scanned ${files.length} file(s) into Admin Vault!`, 'success');
      loadGroupedFiles();
    } catch (err) {
      showToast(err.message || 'Upload failed.', 'error');
    } finally {
      setUploading(false);
      setUploadStage('');
      if (fileInputRef.current) fileInputRef.current.value = '';
    }
  };

  const handleUnlockAdminVaultSubmit = async (e) => {
    e.preventDefault();
    if (!unlockVaultModal || !unlockVaultModal.pin) return;

    const targetUser = unlockVaultModal.user;
    try {
      await adminApi.unlockAdminVault(targetUser.user_id, unlockVaultModal.pin);
      setUnlockedAdminIds((prev) => ({
        ...prev,
        [targetUser.user_id]: unlockVaultModal.pin
      }));
      setUnlockVaultModal(null);
      showToast(`Dual-Admin Authorization granted! Unlocked ${targetUser.username}'s repository.`, 'success');
    } catch (err) {
      showToast(err.message || 'Invalid Admin Security PIN.', 'error');
    }
  };
"""

if "handleAdminFileUpload" not in text:
    text = text.replace(
        "useEffect(() => {",
        helper_funcs + "\n  useEffect(() => {"
    )

# 4. Update scan initiate to use unlockedAdminIds
if "const savedPin = unlockedAdminIds" not in text:
    text = text.replace(
        "const handleInitiateScan = (file, userObj) => {",
        "const handleInitiateScan = (file, userObj) => {\n    const savedPin = unlockedAdminIds[userObj ? userObj.user_id : null];\n    if (userObj && userObj.is_admin_protected && !savedPin) {\n      setDualAdminModal({ file, user: userObj, authCode: '' });\n      return;\n    }\n    handleExecuteScan(file, savedPin || '');\n  };\n  const _orig_handleInitiateScan = (file, userObj) => {"
    )

# 5. Add Header buttons
header_buttons = """
        <div className="flex flex-wrap items-center gap-2">
          <button
            onClick={() => setShowConfigModal(true)}
            className="px-3.5 py-2 bg-indigo-950/80 hover:bg-indigo-900 border border-indigo-500/50 text-indigo-300 hover:text-white rounded-xl text-xs font-bold flex items-center gap-1.5 transition shadow"
            title="Configure Your Admin Dual-Authorization PIN"
          >
            <KeyRound className="w-4 h-4 text-indigo-400" />
            <span>Admin PIN / Dual Auth</span>
          </button>

          <input
            type="file"
            ref={fileInputRef}
            onChange={handleAdminFileUpload}
            multiple
            className="hidden"
          />
          <button
            onClick={() => fileInputRef.current && fileInputRef.current.click()}
            disabled={uploading}
            className="btn-cyber px-4 py-2 rounded-xl text-xs font-bold flex items-center gap-1.5 shadow"
          >
            {uploading ? (
              <>
                <RefreshCw className="w-4 h-4 animate-spin" /> Uploading & Scanning...
              </>
            ) : (
              <>
                <UploadCloud className="w-4 h-4" /> Upload Files (Admin Vault)
              </>
            )}
          </button>

          <button
            onClick={loadGroupedFiles}
            disabled={loading}
            className="p-2 bg-slate-900 hover:bg-slate-800 text-slate-300 hover:text-white border border-slate-700 rounded-xl text-xs font-semibold flex items-center gap-1 transition"
            title="Refresh All Repositories"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin text-sky-400' : ''}`} />
          </button>
        </div>
"""

if "Upload Files (Admin Vault)" not in text:
    old_refresh_btn = """        <button
          onClick={loadGroupedFiles}
          disabled={loading}
          className="px-3 py-2 bg-slate-900 hover:bg-slate-800 text-slate-300 hover:text-white border border-slate-700 rounded-xl text-xs font-semibold flex items-center gap-1.5 transition self-start sm:self-auto"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin text-sky-400' : ''}`} />
          <span>Refresh</span>
        </button>"""
    text = text.replace(old_refresh_btn, header_buttons)

# 6. Add uploading banner
if "ADMIN SCAN PIPELINE:" not in text:
    text = text.replace(
        "{/* User Groups Tree */}",
        """{uploading && (
        <div className="glass-card p-4 border border-sky-500/50 bg-sky-950/40 animate-pulse flex items-center gap-3">
          <RefreshCw className="w-5 h-5 text-sky-400 animate-spin shrink-0" />
          <div className="text-xs font-mono text-sky-200">
            <strong>ADMIN SCAN PIPELINE:</strong> {uploadStage}
          </div>
        </div>
      )}

      {/* User Groups Tree */}"""
    )

# 7. Add modals at the bottom
if "AdminSecurityConfigModal" not in text or "<AdminSecurityConfigModal" not in text:
    bottom_modals = """
      {/* 1. Modal: Unlock Target Admin Repository */}
      {unlockVaultModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fade-in">
          <div className="glass-card max-w-md w-full border border-amber-500/50 shadow-2xl p-6 relative space-y-4 animate-scale-up">
            <button
              onClick={() => setUnlockVaultModal(null)}
              className="absolute right-4 top-4 text-slate-400 hover:text-white p-1 rounded-lg"
            >
              <X className="w-5 h-5" />
            </button>

            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-xl bg-amber-950 border border-amber-500/40 flex items-center justify-center text-amber-400">
                <Lock className="w-5 h-5" />
              </div>
              <div>
                <h3 className="text-base font-black text-white">Cross-Admin Dual Authorization</h3>
                <p className="text-xs text-slate-400 font-mono">
                  Administrator: <strong>{unlockVaultModal.user && unlockVaultModal.user.username}</strong>
                </p>
              </div>
            </div>

            <p className="text-xs text-slate-300 leading-relaxed font-sans bg-amber-950/30 p-3 rounded-xl border border-amber-500/30">
              To inspect or scan files in Administrator <strong>{unlockVaultModal.user && unlockVaultModal.user.username}</strong>'s repository, please enter their secret Admin Security PIN.
            </p>

            <form onSubmit={handleUnlockAdminVaultSubmit} className="space-y-4">
              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1 font-mono">
                  Admin Authorization PIN:
                </label>
                <input
                  type="password"
                  placeholder="Enter 6-digit Security PIN..."
                  value={unlockVaultModal.pin}
                  onChange={(e) => setUnlockVaultModal({ ...unlockVaultModal, pin: e.target.value })}
                  required
                  autoFocus
                  className="w-full bg-slate-900 border border-slate-700 rounded-xl px-3.5 py-2.5 text-white font-mono text-sm tracking-widest focus:outline-none focus:border-amber-500"
                />
              </div>

              <div className="flex items-center justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setUnlockVaultModal(null)}
                  className="px-4 py-2 bg-slate-900 hover:bg-slate-800 text-slate-300 rounded-xl text-xs font-semibold"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 bg-amber-600 hover:bg-amber-500 text-white rounded-xl text-xs font-bold font-mono shadow-lg flex items-center gap-1.5"
                >
                  <Unlock className="w-4 h-4" /> Authorize & Unlock Vault
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      <AdminSecurityConfigModal
        isOpen={showConfigModal}
        onClose={() => setShowConfigModal(false)}
      />
    </div>
  );
}
"""
    text = text.replace(
        "    </div>\n  );\n}",
        bottom_modals
    )

with open("frontend/src/pages/admin/UserWiseFiles.jsx", "w", encoding="utf-8") as f:
    f.write(text)

print("[OK] Successfully patched UserWiseFiles.jsx!")
