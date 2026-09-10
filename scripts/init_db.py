"""
SecureCloud - Database & Storage Initialization Script
Initializes clean schema, storage directories, and default admin/user credentials.
Includes automatic SQLite column migration.
"""

import os
import sys
from pathlib import Path
from sqlalchemy import text

# Set path to root
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from backend.app.database import engine, SessionLocal, Base
from backend.app.models.models import User, IPRule, AuditLog, ScanJob
from backend.app.security.auth_utils import hash_password
from backend.app.config import UPLOADS_DIR, QUARANTINE_DIR, CONFIDENTIAL_DIR, RECYCLE_BIN_DIR, TEMP_DIR

def migrate_missing_columns():
    """Safely adds newly defined columns to existing SQLite tables if missing."""
    with engine.connect() as conn:
        def add_col_if_missing(table, col, col_type):
            try:
                conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {col} {col_type}"))
                conn.commit()
            except Exception:
                pass

        add_col_if_missing("users", "reset_token", "VARCHAR(64)")
        add_col_if_missing("users", "reset_token_expiry", "DATETIME")
        add_col_if_missing("confidential_files", "saved_pin", "VARCHAR(128)")
        add_col_if_missing("files", "scan_status", "VARCHAR(32) DEFAULT 'COMPLETED'")
        add_col_if_missing("files", "last_scanned_at", "DATETIME")

def initialize_database():
    print("[1/3] Ensuring storage directories exist...")
    for d in [UPLOADS_DIR, QUARANTINE_DIR, CONFIDENTIAL_DIR, RECYCLE_BIN_DIR, TEMP_DIR]:
        os.makedirs(d, exist_ok=True)
    print("Storage directories verified.")

    print("[2/3] Initializing clean database tables...")
    Base.metadata.create_all(bind=engine)
    migrate_missing_columns()

    db = SessionLocal()
    try:
        # Check / create default administrator
        admin = db.query(User).filter(User.email == "admin@securecloud.com").first()
        if not admin:
            admin = User(
                username="soc_admin",
                email="admin@securecloud.com",
                hashed_password=hash_password("AdminPass123!"),
                role="ADMIN",
                is_active=True,
                quota_bytes=50 * 1024 * 1024 * 1024 # 50 GB
            )
            db.add(admin)
            print("Created default Admin account: admin@securecloud.com (Pass: AdminPass123!)")
        else:
            admin.hashed_password = hash_password("AdminPass123!")
            admin.role = "ADMIN"
            admin.is_active = True

        # Check / create default user
        analyst = db.query(User).filter(User.email == "analyst@securecloud.com").first()
        if not analyst:
            analyst = User(
                username="security_analyst",
                email="analyst@securecloud.com",
                hashed_password=hash_password("UserPass123!"),
                role="USER",
                is_active=True,
                quota_bytes=10 * 1024 * 1024 * 1024 # 10 GB
            )
            db.add(analyst)
            print("Created default User account: analyst@securecloud.com (Pass: UserPass123!)")
        else:
            analyst.hashed_password = hash_password("UserPass123!")
            analyst.role = "USER"
            analyst.is_active = True

        # Default IP Rule
        local_rule = db.query(IPRule).filter(IPRule.ip_address == "127.0.0.1").first()
        if not local_rule:
            local_rule = IPRule(
                ip_address="127.0.0.1",
                rule_type="WHITELIST",
                description="Localhost Loopback Interface",
                threat_status="CLEAN"
            )
            db.add(local_rule)

        db.commit()
        print("[3/3] Database initialization complete.")
    finally:
        db.close()

if __name__ == "__main__":
    initialize_database()
