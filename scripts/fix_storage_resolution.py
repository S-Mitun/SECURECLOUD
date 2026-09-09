import os
import re

# 1. Update storage_service.py
storage_service_path = "backend/app/services/storage_service.py"
with open(storage_service_path, "r", encoding="utf-8") as f:
    content = f.read()

if "def resolve_storage_path" not in content:
    resolve_func = """
def resolve_storage_path(stored_path: Optional[str]) -> Optional[str]:
    \"\"\"
    Dynamically resolves stored_path against the current active STORAGE_DIR.
    Self-heals if the project folder was renamed or moved.
    \"\"\"
    if not stored_path:
        return stored_path
    if os.path.exists(stored_path):
        return stored_path
    
    norm_path = stored_path.replace("\\\\", "/")
    if "/storage/" in norm_path:
        sub_part = norm_path.split("/storage/")[-1]
        from backend.app.config import STORAGE_DIR
        candidate = os.path.join(STORAGE_DIR, *sub_part.split("/"))
        if os.path.exists(candidate):
            return candidate
    elif "storage" in norm_path:
        sub_part = norm_path.split("storage")[-1].lstrip("/")
        from backend.app.config import STORAGE_DIR
        candidate = os.path.join(STORAGE_DIR, *sub_part.split("/"))
        if os.path.exists(candidate):
            return candidate
            
    return stored_path
"""
    content = content.replace("from backend.app.config import UPLOADS_DIR, QUARANTINE_DIR, CONFIDENTIAL_DIR, RECYCLE_BIN_DIR", "from backend.app.config import UPLOADS_DIR, QUARANTINE_DIR, CONFIDENTIAL_DIR, RECYCLE_BIN_DIR, STORAGE_DIR")
    content = content + "\n" + resolve_func
    with open(storage_service_path, "w", encoding="utf-8") as f:
        f.write(content)
    print("[OK] Added resolve_storage_path to storage_service.py")
else:
    print("[OK] storage_service.py already has resolve_storage_path")

# 2. Update database.py to auto-migrate and relocate stored paths on every startup
database_path = "backend/app/database.py"
with open(database_path, "r", encoding="utf-8") as f:
    db_content = f.read()

if "UPDATE files SET storage_path" not in db_content:
    db_migration_snippet = """
        # Check and auto-relocate storage_path in files & quarantine_files if project was renamed
        try:
            from backend.app.config import STORAGE_DIR
            cursor.execute("SELECT id, storage_path FROM files")
            for fid, sp in cursor.fetchall():
                if sp and not os.path.exists(sp) and "storage" in sp:
                    sub_part = sp.replace("\\\\", "/").split("/storage/")[-1] if "/storage/" in sp.replace("\\\\", "/") else sp.split("storage")[-1].lstrip("\\\\/")
                    candidate = os.path.join(STORAGE_DIR, *sub_part.split("/"))
                    if os.path.exists(candidate):
                        cursor.execute("UPDATE files SET storage_path = ? WHERE id = ?", (candidate, fid))
            cursor.execute("SELECT id, quarantine_path FROM quarantine_files")
            for qid, qp in cursor.fetchall():
                if qp and not os.path.exists(qp) and "storage" in qp:
                    sub_part = qp.replace("\\\\", "/").split("/storage/")[-1] if "/storage/" in qp.replace("\\\\", "/") else qp.split("storage")[-1].lstrip("\\\\/")
                    candidate = os.path.join(STORAGE_DIR, *sub_part.split("/"))
                    if os.path.exists(candidate):
                        cursor.execute("UPDATE quarantine_files SET quarantine_path = ? WHERE id = ?", (candidate, qid))
            conn.commit()
        except Exception as p_err:
            print(f"Path auto-relocation notice: {p_err}")
"""
    db_content = db_content.replace("conn.commit()\n        conn.close()", db_migration_snippet + "\n        conn.commit()\n        conn.close()")
    with open(database_path, "w", encoding="utf-8") as f:
        f.write(db_content)
    print("[OK] Updated database.py with dynamic path relocation")

# 3. Update files.py to use resolve_storage_path
files_api_path = "backend/app/api/files.py"
with open(files_api_path, "r", encoding="utf-8") as f:
    files_content = f.read()

if "resolve_storage_path" not in files_content:
    files_content = files_content.replace("generate_storage_path,", "generate_storage_path, resolve_storage_path,")
    files_content = files_content.replace("if not os.path.exists(f.storage_path):", "f.storage_path = resolve_storage_path(f.storage_path)\n    if not os.path.exists(f.storage_path):")
    with open(files_api_path, "w", encoding="utf-8") as f:
        f.write(files_content)
    print("[OK] Updated files.py with resolve_storage_path")

# 4. Update shares.py to use resolve_storage_path
shares_api_path = "backend/app/api/shares.py"
with open(shares_api_path, "r", encoding="utf-8") as f:
    shares_content = f.read()

if "resolve_storage_path" not in shares_content:
    shares_content = shares_content.replace("from backend.app.services.storage_service import sanitize_filename", "from backend.app.services.storage_service import sanitize_filename, resolve_storage_path")
    shares_content = shares_content.replace("if not f or not os.path.exists(f.storage_path):", "if f: f.storage_path = resolve_storage_path(f.storage_path)\n    if not f or not os.path.exists(f.storage_path):")
    with open(shares_api_path, "w", encoding="utf-8") as f:
        f.write(shares_content)
    print("[OK] Updated shares.py with resolve_storage_path")

# 5. Update confidential.py to use resolve_storage_path
conf_api_path = "backend/app/api/confidential.py"
with open(conf_api_path, "r", encoding="utf-8") as f:
    conf_content = f.read()

if "resolve_storage_path" not in conf_content:
    conf_content = conf_content.replace("from backend.app.services.storage_service import format_size", "from backend.app.services.storage_service import format_size, resolve_storage_path")
    conf_content = conf_content.replace("if not os.path.exists(f.storage_path):", "f.storage_path = resolve_storage_path(f.storage_path)\n    if not os.path.exists(f.storage_path):")
    with open(conf_api_path, "w", encoding="utf-8") as f:
        f.write(conf_content)
    print("[OK] Updated confidential.py with resolve_storage_path")

# 6. Update soc.py to use resolve_storage_path
soc_api_path = "backend/app/api/soc.py"
with open(soc_api_path, "r", encoding="utf-8") as f:
    soc_content = f.read()

if "resolve_storage_path" not in soc_content:
    soc_content = soc_content.replace("from backend.app.services.storage_service import format_size", "from backend.app.services.storage_service import format_size, resolve_storage_path")
    soc_content = soc_content.replace("if not os.path.exists(f.storage_path):", "f.storage_path = resolve_storage_path(f.storage_path)\n    if not os.path.exists(f.storage_path):")
    with open(soc_api_path, "w", encoding="utf-8") as f:
        f.write(soc_content)
    print("[OK] Updated soc.py with resolve_storage_path")

print(">>> ALL STORAGE RESOLUTION ENGINES UPDATED AND ARMORED!")
