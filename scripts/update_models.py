with open("backend/app/models/models.py", "r", encoding="utf-8") as f:
    text = f.read()

old_conf_model = """class ConfidentialFile(Base):
    __tablename__ = "confidential_files"

    id = Column(Integer, primary_key=True, index=True)
    file_id = Column(String(36), ForeignKey("files.id"), unique=True, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    pin_salt = Column(String(64), nullable=False)
    pin_hash = Column(String(256), nullable=False) # Hashed PIN / strong password
    encrypted_key = Column(Text, nullable=False)
    saved_pin = Column(String(128), nullable=True) # User-saved recovery PIN
    created_at = Column(DateTime, default=datetime.utcnow)"""

new_conf_model = """class ConfidentialFile(Base):
    __tablename__ = "confidential_files"

    id = Column(Integer, primary_key=True, index=True)
    file_id = Column(String(36), ForeignKey("files.id"), unique=True, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    pin_salt = Column(String(64), nullable=False)
    pin_hash = Column(String(256), nullable=False) # Hashed PIN / strong password
    encrypted_key = Column(Text, nullable=False)
    saved_pin = Column(String(128), nullable=True) # User-saved recovery PIN
    failed_attempts = Column(Integer, default=0) # Consecutive failed PIN attempts
    lockout_stage = Column(Integer, default=0) # 0: Normal, 1: 30min lockout, 2: 2hr lockout, 3: Permanent
    locked_until = Column(DateTime, nullable=True) # Temporary lockout expiration
    is_permanently_locked = Column(Boolean, default=False) # Permanent brick lock
    created_at = Column(DateTime, default=datetime.utcnow)"""

text = text.replace(old_conf_model, new_conf_model)

with open("backend/app/models/models.py", "w", encoding="utf-8") as f:
    f.write(text)

print("[OK] Updated models.py with ConfidentialFile lockout fields!")
