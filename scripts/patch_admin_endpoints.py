import re

with open("backend/app/api/soc.py", "r", encoding="utf-8") as f:
    content = f.read()

# Add endpoints for admin config code and unlock vault
admin_endpoints_code = """
# =========================================================================
# Admin Security Configuration Code & Dual Authorization Endpoints
# =========================================================================

@router.get("/admin/config-code")
def get_admin_security_config_code(
    current_admin: User = Depends(get_current_admin)
):
    \"\"\"Returns the current logged-in administrator's dual-authorization security code.\"\"\"
    return {
        \"status\": \"SUCCESS\",
        \"admin_security_code\": current_admin.admin_security_code or \"994422\",
        \"username\": current_admin.username,
        \"email\": current_admin.email,
        \"role\": current_admin.role
    }

@router.post("/admin/config-code")
def update_admin_security_config_code(
    payload: Dict[str, Any] = Body(...),
    current_admin: User = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    \"\"\"Updates or auto-generates a unique 6-digit Admin Security Code.\"\"\"
    import random
    
    if payload.get("regenerate"):
        new_code = f"{random.randint(100000, 999999)}"
    else:
        new_code = str(payload.get("admin_security_code", "")).strip()
        if len(new_code) < 4 or len(new_code) > 16:
            raise HTTPException(status_code=400, detail="Admin Security Code must be between 4 and 16 characters.")
            
    current_admin.admin_security_code = new_code
    db.commit()
    db.refresh(current_admin)
    
    AuditService.log(
        db, "ADMIN_SECURITY_CODE_UPDATE", f"Admin {current_admin.username}", "SUCCESS",
        "Unique Admin Dual-Authorization security code updated",
        user_id=current_admin.id, username=current_admin.username, role=current_admin.role
    )
    
    return {
        \"status\": \"SUCCESS\",
        \"admin_security_code\": new_code,
        \"message\": \"Admin Security Configuration code updated successfully.\"
    }

@router.post("/admin/unlock-admin-vault")
def unlock_admin_vault(
    payload: Dict[str, Any] = Body(...),
    current_admin: User = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    \"\"\"Verifies cross-admin authorization code to unlock another admin's repository.\"\"\"
    target_admin_id = payload.get("target_admin_id")
    entered_code = str(payload.get("admin_security_code", "")).strip()
    
    if not target_admin_id or not entered_code:
        raise HTTPException(status_code=400, detail="target_admin_id and admin_security_code are required.")
        
    target_admin = db.query(User).filter(User.id == target_admin_id).first()
    if not target_admin or target_admin.role.upper() != "ADMIN":
        raise HTTPException(status_code=404, detail="Target administrator not found.")
        
    expected_code = target_admin.admin_security_code or "994422"
    if entered_code != expected_code:
        # Create notification for target admin
        notif = Notification(
            user_id=target_admin.id,
            title="Cross-Admin Repository Access Blocked",
            message=f"Administrator '{current_admin.username}' ({current_admin.email}) attempted cross-admin repository access with an incorrect authorization PIN.",
            type="SECURITY_WARNING"
        )
        db.add(notif)
        db.commit()
        raise HTTPException(status_code=403, detail="Invalid Admin Security PIN. Access denied to Administrator repository.")
        
    # Valid code -> Grant unlock
    notif = Notification(
        user_id=target_admin.id,
        title="Cross-Admin Repository Access Granted",
        message=f"Administrator '{current_admin.username}' ({current_admin.email}) successfully authorized access to your repository using your Admin Security PIN.",
        type="SECURITY_INFO"
    )
    db.add(notif)
    db.commit()
    
    AuditService.log(
        db, "CROSS_ADMIN_VAULT_UNLOCK", f"Admin {target_admin.username}", "SUCCESS",
        f"Unlocked by Admin {current_admin.username}",
        user_id=current_admin.id, username=current_admin.username, role=current_admin.role
    )
    
    return {
        \"status\": \"SUCCESS\",
        \"unlocked\": True,
        \"target_admin_id\": target_admin.id,
        \"target_admin_username\": target_admin.username,
        \"message\": f"Administrator '{target_admin.username}' repository unlocked successfully."
    }
"""

if "get_admin_security_config_code" not in content:
    content += "\n" + admin_endpoints_code
    with open("backend/app/api/soc.py", "w", encoding="utf-8") as f:
        f.write(content)
    print("[OK] Added admin security config & unlock endpoints to backend/app/api/soc.py")
else:
    print("[OK] Endpoints already present in soc.py")
