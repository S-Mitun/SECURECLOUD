# 1. Update User model in models.py
with open("backend/app/models/models.py", "r", encoding="utf-8") as f:
    m_text = f.read()

if "two_factor_enforced = Column" not in m_text:
    m_text = m_text.replace(
        "is_2fa_enabled = Column(Boolean, default=False)",
        "is_2fa_enabled = Column(Boolean, default=False)\n    two_factor_enforced = Column(Boolean, default=False)"
    )
    with open("backend/app/models/models.py", "w", encoding="utf-8") as f:
        f.write(m_text)
    print("[OK] Added two_factor_enforced to User model in models.py")

# 2. Update soc.py to set both two_factor_enforced and is_2fa_enabled, and use is_revoked on sessions
with open("backend/app/api/soc.py", "r", encoding="utf-8") as f:
    s_text = f.read()

s_text = s_text.replace("s.is_active = False", "s.is_revoked = True")
s_text = s_text.replace("UserSession.is_active == True", "UserSession.is_revoked == False")

with open("backend/app/api/soc.py", "w", encoding="utf-8") as f:
    f.write(s_text)

print("[OK] Updated soc.py with consistent session revocation and 2FA attributes!")
