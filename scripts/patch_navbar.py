with open("frontend/src/components/Navbar.jsx", "r", encoding="utf-8") as f:
    nav_text = f.read()

# 1. Imports
if "AdminSecurityConfigModal" not in nav_text:
    nav_text = nav_text.replace(
        "import React from 'react';",
        "import React, { useState, useRef } from 'react';\nimport { AdminSecurityConfigModal } from './AdminSecurityConfigModal';\nimport { fileApi } from '../api/fileApi';"
    )

if "UploadCloud" not in nav_text:
    nav_text = nav_text.replace(
        "KeyRound, Share2",
        "KeyRound, Share2, UploadCloud, RefreshCw"
    )

# 2. State & Admin upload handlers inside Navbar
if "const [showPinModal, setShowPinModal] = useState" not in nav_text:
    nav_text = nav_text.replace(
        "export function Navbar() {",
        """export function Navbar() {
  const [showPinModal, setShowPinModal] = useState(false);
  const [adminUploading, setAdminUploading] = useState(false);
  const adminFileInputRef = useRef(null);

  const handleAdminNavUpload = async (e) => {
    const files = Array.from(e.target.files || []);
    if (files.length === 0) return;

    setAdminUploading(true);
    try {
      for (let i = 0; i < files.length; i++) {
        const file = files[i];
        const res = await fileApi.uploadFile(file);
        if (res.scan && res.scan.security_status === 'MALICIOUS') {
          triggerCriticalAlert({
            filename: file.name,
            threat_score: res.scan.threat_score || 85.0
          });
        }
      }
      alert(`[SecureCloud] Successfully uploaded & scanned ${files.length} file(s) into Admin Vault!`);
      window.location.reload();
    } catch (err) {
      alert(`[Upload Error] ${err.message || 'Upload failed.'}`);
    } finally {
      setAdminUploading(false);
      if (adminFileInputRef.current) adminFileInputRef.current.value = '';
    }
  };"""
    )

# 3. Add the two buttons in Navbar right side actions
right_admin_buttons = """      {/* Admin Quick Upload & Security PIN Buttons */}
      {isAdmin && (
        <div className="flex items-center gap-1.5 mr-2">
          <input
            type="file"
            ref={adminFileInputRef}
            onChange={handleAdminNavUpload}
            multiple
            className="hidden"
          />
          <button
            onClick={() => adminFileInputRef.current && adminFileInputRef.current.click()}
            disabled={adminUploading}
            className="px-3 py-1.5 bg-gradient-to-r from-sky-600 to-cyan-500 hover:from-sky-500 hover:to-cyan-400 text-white rounded-lg text-xs font-bold flex items-center gap-1.5 shadow-md transition"
            title="Upload Files Directly into Administrator Vault"
          >
            {adminUploading ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <UploadCloud className="w-3.5 h-3.5" />}
            <span>Upload (Admin)</span>
          </button>

          <button
            onClick={() => setShowPinModal(true)}
            className="px-2.5 py-1.5 bg-indigo-950/80 hover:bg-indigo-900 border border-indigo-500/50 text-indigo-300 hover:text-white rounded-lg text-xs font-bold flex items-center gap-1 transition shadow"
            title="Configure Your Admin Dual-Authorization Security PIN"
          >
            <KeyRound className="w-3.5 h-3.5 text-indigo-400" />
            <span className="hidden sm:inline">Admin PIN</span>
          </button>
        </div>
      )}"""

if "Upload (Admin)" not in nav_text:
    nav_text = nav_text.replace(
        '<div className="flex items-center gap-3">',
        '<div className="flex items-center gap-3">\n' + right_admin_buttons
    )

# 4. Mount AdminSecurityConfigModal at bottom of Navbar
if "<AdminSecurityConfigModal" not in nav_text:
    nav_text = nav_text.replace(
        '</header>',
        """  <AdminSecurityConfigModal
        isOpen={showPinModal}
        onClose={() => setShowPinModal(false)}
      />
    </header>"""
    )

with open("frontend/src/components/Navbar.jsx", "w", encoding="utf-8") as f:
    f.write(nav_text)
print("[OK] Successfully integrated Admin Upload & PIN in Navbar.jsx!")
