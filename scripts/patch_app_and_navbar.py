# 1. Update frontend/src/App.jsx
with open("frontend/src/App.jsx", "r", encoding="utf-8") as f:
    app_text = f.read()

if "AdminFileUpload" not in app_text:
    app_text = app_text.replace(
        "import { AdminDashboard } from './pages/admin/AdminDashboard';",
        "import { AdminDashboard } from './pages/admin/AdminDashboard';\nimport { AdminFileUpload } from './pages/admin/AdminFileUpload';"
    )
    
    app_text = app_text.replace(
        '<Route path="/admin/user-wise-files" element={<UserWiseFiles />} />',
        '<Route path="/admin/upload" element={<AdminFileUpload />} />\n          <Route path="/admin/ingestion" element={<AdminFileUpload />} />\n          <Route path="/admin/user-wise-files" element={<UserWiseFiles />} />'
    )
    
    with open("frontend/src/App.jsx", "w", encoding="utf-8") as f:
        f.write(app_text)
    print("[OK] Added /admin/upload route to App.jsx")

# 2. Update frontend/src/components/Navbar.jsx
with open("frontend/src/components/Navbar.jsx", "r", encoding="utf-8") as f:
    nav_text = f.read()

# Add Ingest Files link in admin nav
nav_link_upload = """          <Link
            to="/admin/upload"
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition ${
              isActive('/admin/upload') ? 'bg-sky-600 text-white shadow' : 'text-sky-300 hover:text-white hover:bg-slate-800'
            }`}
          >
            <UploadCloud className="w-3.5 h-3.5" /> Upload Hub
          </Link>"""

if 'to="/admin/upload"' not in nav_text:
    nav_text = nav_text.replace(
        '<Link\n            to="/admin/user-wise-files"',
        nav_link_upload + '\n          <Link\n            to="/admin/user-wise-files"'
    )

# Fix handleAdminNavUpload to use FormData and showToast
old_handle_upload = """  const handleAdminNavUpload = async (e) => {
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

new_handle_upload = """  const handleAdminNavUpload = async (e) => {
    const files = Array.from(e.target.files || []);
    if (files.length === 0) return;

    setAdminUploading(true);
    try {
      for (let i = 0; i < files.length; i++) {
        const file = files[i];
        const formData = new FormData();
        formData.append('file', file);
        const res = await fileApi.uploadFile(formData);
        if (res.scan && res.scan.security_status === 'MALICIOUS') {
          triggerCriticalAlert({
            filename: file.name,
            threat_score: res.scan.threat_score || 85.0
          });
        }
      }
      showToast(`Successfully uploaded & scanned ${files.length} file(s) into Admin Vault!`, 'success');
      setTimeout(() => window.location.reload(), 1000);
    } catch (err) {
      const msg = err.message || (typeof err === 'object' ? JSON.stringify(err) : String(err));
      showToast(`Upload Failed: ${msg}`, 'error');
    } finally {
      setAdminUploading(false);
      if (adminFileInputRef.current) adminFileInputRef.current.value = '';
    }
  };"""

if old_handle_upload in nav_text:
    nav_text = nav_text.replace(old_handle_upload, new_handle_upload)

# Also update the quick navbar button to point directly to /admin/upload or open file picker
nav_text = nav_text.replace(
    '<span>Upload (Admin)</span>',
    '<span>Quick Upload</span>'
)

with open("frontend/src/components/Navbar.jsx", "w", encoding="utf-8") as f:
    f.write(nav_text)
print("[OK] Updated Navbar.jsx with Upload Hub navigation link and robust upload handler!")
