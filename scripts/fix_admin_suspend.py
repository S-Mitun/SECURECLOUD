with open("backend/app/api/soc.py", "r", encoding="utf-8") as f:
    text = f.read()

old_admin_toggle = """    if u.id == current_admin.id:
        raise HTTPException(status_code=400, detail="Cannot suspend own administrator account.")"""

new_admin_toggle = """    if u.role.upper() == "ADMIN":
        raise HTTPException(status_code=403, detail="Security Policy: Administrators cannot suspend or deactivate other Administrator accounts.")"""

if old_admin_toggle in text:
    text = text.replace(old_admin_toggle, new_admin_toggle)
    with open("backend/app/api/soc.py", "w", encoding="utf-8") as f:
        f.write(text)
    print("[OK] Updated soc.py: Admins cannot suspend other admins!")
else:
    print("[WARN] old_admin_toggle not found or already updated")

# Also update UsersManagement.jsx to disable button for Admins
with open("frontend/src/pages/admin/UsersManagement.jsx", "r", encoding="utf-8") as f:
    u_text = f.read()

old_btn = """                        <button
                          onClick={() => handleToggleStatus(u)}
                          title={u.is_active ? 'Suspend Account' : 'Activate Account'}"""

new_btn = """                        <button
                          onClick={() => {
                            if (u.role === 'ADMIN') {
                              showToast('Security Policy: Administrators cannot suspend other Administrator accounts.', 'warning');
                              return;
                            }
                            handleToggleStatus(u);
                          }}
                          disabled={u.role === 'ADMIN'}
                          title={u.role === 'ADMIN' ? 'Administrator accounts cannot be suspended' : (u.is_active ? 'Suspend Account' : 'Activate Account')}"""

if old_btn in u_text:
    u_text = u_text.replace(old_btn, new_btn)
    with open("frontend/src/pages/admin/UsersManagement.jsx", "w", encoding="utf-8") as f:
        f.write(u_text)
    print("[OK] Updated UsersManagement.jsx disable suspend for admins!")
else:
    print("[WARN] old_btn not found in UsersManagement.jsx")
