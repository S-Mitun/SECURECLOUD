with open("backend/app/database.py", "r", encoding="utf-8") as f:
    text = f.read()

migration_check = """
        # Migration for confidential_files lockout columns
        try:
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
            conn.commit()
        except Exception:
            pass
"""

if "failed_attempts" not in text:
    text = text.replace(
        'conn.commit()',
        'conn.commit()\n' + migration_check,
        1
    )
    with open("backend/app/database.py", "w", encoding="utf-8") as f:
        f.write(text)
    print("[OK] Added confidential migration to database.py")
else:
    print("[OK] Migration already present in database.py")
