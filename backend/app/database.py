import os
import sqlite3
from typing import Optional
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./securecloud.db")
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(
    DATABASE_URL,
    connect_args=connect_args,
    echo=False
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def ensure_schema_migrated():
    """Idempotently adds any missing columns and handles dynamic paths."""
    if not DATABASE_URL.startswith("sqlite"):
        return
    db_file = DATABASE_URL.replace("sqlite:///", "")
    if not os.path.exists(db_file):
        return
    try:
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()

        # Check users table
        cursor.execute("PRAGMA table_info(users)")
        cols = [c[1] for c in cursor.fetchall()]
        if "two_factor_enforced" not in cols:
            cursor.execute("ALTER TABLE users ADD COLUMN two_factor_enforced BOOLEAN DEFAULT 0")
        if "two_factor_code" not in cols:
            cursor.execute("ALTER TABLE users ADD COLUMN two_factor_code VARCHAR(16)")
        if "two_factor_expires_at" not in cols:
            cursor.execute("ALTER TABLE users ADD COLUMN two_factor_expires_at TIMESTAMP")
        if "totp_secret" not in cols:
            cursor.execute("ALTER TABLE users ADD COLUMN totp_secret VARCHAR(32)")
        if "last_login_ip" not in cols:
            cursor.execute("ALTER TABLE users ADD COLUMN last_login_ip VARCHAR(45) DEFAULT '127.0.0.1'")

        # Check confidential_files table
        cursor.execute("PRAGMA table_info(confidential_files)")
        c_cols = [c[1] for c in cursor.fetchall()]
        if "failed_attempts" not in c_cols:
            cursor.execute("ALTER TABLE confidential_files ADD COLUMN failed_attempts INTEGER DEFAULT 0")
        if "lockout_stage" not in c_cols:
            cursor.execute("ALTER TABLE confidential_files ADD COLUMN lockout_stage INTEGER DEFAULT 0")
        if "locked_until" not in c_cols:
            cursor.execute("ALTER TABLE confidential_files ADD COLUMN locked_until TIMESTAMP")
        if "is_permanently_locked" not in c_cols:
            cursor.execute("ALTER TABLE confidential_files ADD COLUMN is_permanently_locked BOOLEAN DEFAULT 0")

        # Auto-relocate storage paths across all tables
        try:
            from backend.app.config import STORAGE_DIR, UPLOADS_DIR, CONFIDENTIAL_DIR, QUARANTINE_DIR

            def _find_candidate(raw_path: str) -> Optional[str]:
                if not raw_path:
                    return None
                if os.path.exists(raw_path):
                    return raw_path
                norm = raw_path.replace("\\", "/")
                # Subpart check
                sub = norm.split("/storage/")[-1] if "/storage/" in norm else (norm.split("storage/")[-1] if "storage/" in norm else None)
                if sub:
                    cand = os.path.join(STORAGE_DIR, *sub.strip("/").split("/"))
                    if os.path.exists(cand):
                        return cand
                # Basename check
                bname = os.path.basename(norm)
                if bname:
                    for folder in [UPLOADS_DIR, CONFIDENTIAL_DIR, QUARANTINE_DIR]:
                        cand = os.path.join(folder, bname)
                        if os.path.exists(cand):
                            return cand
                return None

            cursor.execute("SELECT id, storage_path FROM files")
            for fid, sp in cursor.fetchall():
                relocated = _find_candidate(sp)
                if relocated and relocated != sp:
                    cursor.execute("UPDATE files SET storage_path = ? WHERE id = ?", (relocated, fid))
            
            cursor.execute("SELECT id, storage_path FROM file_versions")
            for vid, sp in cursor.fetchall():
                relocated = _find_candidate(sp)
                if relocated and relocated != sp:
                    cursor.execute("UPDATE file_versions SET storage_path = ? WHERE id = ?", (relocated, vid))

            cursor.execute("SELECT id, restore_path FROM recycle_bin")
            for bid, rp in cursor.fetchall():
                relocated = _find_candidate(rp)
                if relocated and relocated != rp:
                    cursor.execute("UPDATE recycle_bin SET restore_path = ? WHERE id = ?", (relocated, bid))

            cursor.execute("SELECT id, quarantine_path FROM quarantine_files")
            for qid, qp in cursor.fetchall():
                relocated = _find_candidate(qp)
                if relocated and relocated != qp:
                    cursor.execute("UPDATE quarantine_files SET quarantine_path = ? WHERE id = ?", (relocated, qid))
        except Exception as p_err:
            print(f"Path auto-relocation notice: {p_err}")

        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Database schema migration notice: {e}")

# Run schema migration check
ensure_schema_migrated()

def get_db():
    """FastAPI database session dependency."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def seed_default_users():
    """Seeds default admin and analyst users if they do not exist."""
    try:
        import bcrypt
        from backend.app.models.models import User, IPRule
        
        def _hash(pw: str) -> str:
            salt = bcrypt.gensalt(rounds=12)
            return bcrypt.hashpw(pw.encode("utf-8"), salt).decode("utf-8")

        db = SessionLocal()
        try:
            admin = db.query(User).filter(User.email == "admin@securecloud.com").first()
            if not admin:
                admin = User(
                    username="soc_admin",
                    email="admin@securecloud.com",
                    hashed_password=_hash("AdminPass123!"),
                    role="ADMIN",
                    is_active=True,
                    quota_bytes=50 * 1024 * 1024 * 1024
                )
                db.add(admin)
                print("Seeded default admin: admin@securecloud.com")

            analyst = db.query(User).filter(User.email == "analyst@securecloud.com").first()
            if not analyst:
                analyst = User(
                    username="security_analyst",
                    email="analyst@securecloud.com",
                    hashed_password=_hash("UserPass123!"),
                    role="USER",
                    is_active=True,
                    quota_bytes=10 * 1024 * 1024 * 1024
                )
                db.add(analyst)
                print("Seeded default user: analyst@securecloud.com")

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
        finally:
            db.close()
    except Exception as e:
        print(f"User seed notice: {e}")

def init_db():
    """Initializes all database tables from models and seeds default accounts."""
    from backend.app.models import models
    Base.metadata.create_all(bind=engine)
    seed_default_users()

init_db()
