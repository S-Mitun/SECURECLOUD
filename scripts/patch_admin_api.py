with open("frontend/src/api/adminApi.js", "r", encoding="utf-8") as f:
    content = f.read()

if "getAdminSecurityCode" not in content:
    new_methods = """
  // Admin Security Configuration PIN / Dual Authorization
  getAdminSecurityCode: async () => {
    return await apiClient('/api/soc/admin/config-code');
  },

  updateAdminSecurityCode: async (data) => {
    return await apiClient('/api/soc/admin/config-code', {
      method: 'POST',
      body: JSON.stringify(data)
    });
  },

  unlockAdminVault: async (targetAdminId, adminSecurityCode) => {
    return await apiClient('/api/soc/admin/unlock-admin-vault', {
      method: 'POST',
      body: JSON.stringify({
        target_admin_id: targetAdminId,
        admin_security_code: adminSecurityCode
      })
    });
  },
"""
    # Insert before the last closing bracket
    content = content.rstrip()
    if content.endswith("};"):
        content = content[:-2] + new_methods + "};"
    elif content.endswith("}"):
        content = content[:-1] + new_methods + "};"
        
    with open("frontend/src/api/adminApi.js", "w", encoding="utf-8") as f:
        f.write(content)
    print("[OK] Updated frontend/src/api/adminApi.js with admin code methods!")
else:
    print("[OK] adminApi.js already updated")
