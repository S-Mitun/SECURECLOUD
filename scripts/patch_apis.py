# 1. Update frontend/src/api/fileApi.js
with open("frontend/src/api/fileApi.js", "r", encoding="utf-8") as f:
    f_text = f.read()

old_upload = """  uploadFile: async (formData) => {
    return await apiClient('/api/files/upload', {
      method: 'POST',
      body: formData
    });
  },"""

new_upload = """  uploadFile: async (fileOrFormData) => {
    let body = fileOrFormData;
    if (fileOrFormData instanceof File || fileOrFormData instanceof Blob) {
      body = new FormData();
      body.append('file', fileOrFormData);
    }
    return await apiClient('/api/files/upload', {
      method: 'POST',
      body
    });
  },"""

f_text = f_text.replace(old_upload, new_upload)
with open("frontend/src/api/fileApi.js", "w", encoding="utf-8") as f:
    f.write(f_text)
print("[OK] Updated frontend/src/api/fileApi.js with auto-FormData wrapping!")

# 2. Update frontend/src/api/adminApi.js with uploadFileForUser
with open("frontend/src/api/adminApi.js", "r", encoding="utf-8") as f:
    a_text = f.read()

admin_upload_method = """
  // Admin File Ingestion for Users
  uploadFileForUser: async (formData) => {
    return await apiClient('/api/soc/files/upload-for-user', {
      method: 'POST',
      body: formData
    });
  },
"""

if "uploadFileForUser" not in a_text:
    a_text = a_text.rstrip()
    if a_text.endswith("};"):
        a_text = a_text[:-2] + admin_upload_method + "};"
    elif a_text.endswith("}"):
        a_text = a_text[:-1] + admin_upload_method + "};"
    with open("frontend/src/api/adminApi.js", "w", encoding="utf-8") as f:
        f.write(a_text)
    print("[OK] Added uploadFileForUser to adminApi.js!")
