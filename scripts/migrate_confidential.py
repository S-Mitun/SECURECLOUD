import sqlite3

conn = sqlite3.connect("securecloud.db")
c = conn.cursor()

# Check confidential_files columns
c.execute("PRAGMA table_info(confidential_files)")
cols = [row[1] for row in c.fetchall()]
print("Current confidential_files columns:", cols)

if "failed_attempts" not in cols:
    c.execute("ALTER TABLE confidential_files ADD COLUMN failed_attempts INTEGER DEFAULT 0")
if "lockout_stage" not in cols:
    c.execute("ALTER TABLE confidential_files ADD COLUMN lockout_stage INTEGER DEFAULT 0")
if "locked_until" not in cols:
    c.execute("ALTER TABLE confidential_files ADD COLUMN locked_until TIMESTAMP")
if "is_permanently_locked" not in cols:
    c.execute("ALTER TABLE confidential_files ADD COLUMN is_permanently_locked BOOLEAN DEFAULT 0")

conn.commit()
conn.close()
print("[OK] Migrated confidential_files table for progressive lockout!")
