"""
SecureCloud 2.0 - Confidential File Vault API
AES-256-GCM authenticated encryption with 6-digit PIN/password key derivation.
Ensures zero-knowledge privacy where administrators cannot view confidential contents.
Includes Confidential Password Saves (Encrypted Key Recovery Vault).
"""

import os
import io
import json
import base64
import mammoth
import docx
import openpyxl
import pptx
import zipfile
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Response, Body
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from backend.app.config import CONFIDENTIAL_DIR, UPLOADS_DIR
from backend.app.database import get_db
from backend.app.models.models import User, FileRecord, ConfidentialFile
from backend.app.schemas.schemas import ConfidentialLockRequest, ConfidentialUnlockRequest
from backend.app.security.auth_utils import get_current_user
from backend.app.security.pin_crypto import hash_pin, verify_pin_hash, encrypt_file_data, decrypt_file_data
from backend.app.services.audit_service import AuditService
from backend.app.services.storage_service import format_size, resolve_storage_path

def to_ist(dt: Optional[datetime]) -> str:
    if not dt:
        return "Never"
    ist_time = dt + timedelta(hours=5, minutes=30)
    return ist_time.strftime("%d %b %Y, %I:%M:%S %p IST")

def to_ist_short(dt: Optional[datetime]) -> str:
    if not dt:
        return "Never"
    ist_time = dt + timedelta(hours=5, minutes=30)
    return ist_time.strftime("%d %b %Y, %I:%M %p IST")

router = APIRouter(prefix="/api/confidential", tags=["Confidential Vault"])

def _process_lock(file_id: str, pin: str, save_password: bool, current_user: User, db: Session):
    f = db.query(FileRecord).filter(
        FileRecord.id == file_id,
        FileRecord.user_id == current_user.id,
        FileRecord.is_in_recycle_bin == False
    ).first()

    if not f:
        raise HTTPException(status_code=404, detail="File not found.")

    if f.is_confidential:
        raise HTTPException(status_code=400, detail="File is already marked as confidential.")

    f.storage_path = resolve_storage_path(f.storage_path)
    if not os.path.exists(f.storage_path):
        raise HTTPException(status_code=404, detail="Physical file not found.")

    with open(f.storage_path, "rb") as fp:
        raw_bytes = fp.read()

    salt_b64, pin_hash = hash_pin(pin)
    encrypted_bytes = encrypt_file_data(raw_bytes, pin, salt_b64)

    os.makedirs(CONFIDENTIAL_DIR, exist_ok=True)
    confidential_path = os.path.join(CONFIDENTIAL_DIR, f"vault_{f.id}.enc")
    with open(confidential_path, "wb") as enc_file:
        enc_file.write(encrypted_bytes)

    if os.path.exists(f.storage_path) and f.storage_path != confidential_path:
        try:
            os.remove(f.storage_path)
        except Exception:
            pass

    f.is_confidential = True
    f.storage_path = confidential_path

    c_meta = ConfidentialFile(
        file_id=f.id,
        user_id=current_user.id,
        pin_salt=salt_b64,
        pin_hash=pin_hash,
        encrypted_key="AES-256-GCM-PBKDF2",
        saved_pin=pin if save_password else None,
        created_at=datetime.utcnow()
    )
    db.add(c_meta)
    db.commit()

    AuditService.log(
        db, "LOCK_CONFIDENTIAL", f"File {f.filename}", "SUCCESS",
        "Encrypted with AES-256-GCM and PIN protection",
        user_id=current_user.id, username=current_user.username, role=current_user.role
    )

    return {
        "status": "SUCCESS",
        "message": f"File '{f.filename}' is now encrypted and locked in your Confidential Vault."
    }

@router.post("/lock")
def lock_file_as_confidential(
    req: ConfidentialLockRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if not req.file_id:
        raise HTTPException(status_code=400, detail="file_id is required.")
    return _process_lock(req.file_id, req.pin, req.save_password, current_user, db)

@router.post("/{file_id}/lock")
def lock_file_by_path(
    file_id: str,
    req: ConfidentialLockRequest = Body(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    return _process_lock(file_id, req.pin, req.save_password, current_user, db)

@router.get("/list")
def list_confidential_files(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    files = db.query(FileRecord).filter(
        FileRecord.user_id == current_user.id,
        FileRecord.is_confidential == True,
        FileRecord.is_in_recycle_bin == False
    ).order_by(FileRecord.created_at.desc()).all()

    return [
        {
            "id": f.id,
            "filename": f.filename,
            "file_size": f.file_size,
            "file_size_formatted": format_size(f.file_size),
            "file_hash": f.file_hash,
            "mime_type": f.mime_type,
            "extension": f.extension,
            "is_confidential": True,
            "threat_score": f.threat_score,
            "security_status": f.security_status,
            "failed_attempts": f.confidential_meta.failed_attempts if f.confidential_meta else 0,
            "lockout_stage": f.confidential_meta.lockout_stage if f.confidential_meta else 0,
            "locked_until": to_ist(f.confidential_meta.locked_until) if (f.confidential_meta and f.confidential_meta.locked_until) else None,
            "is_permanently_locked": f.confidential_meta.is_permanently_locked if f.confidential_meta else False,
            "created_at": to_ist(f.confidential_meta.created_at) if (f.confidential_meta and f.confidential_meta.created_at) else to_ist(f.created_at),
            "encrypted_at": to_ist(f.confidential_meta.created_at) if (f.confidential_meta and f.confidential_meta.created_at) else to_ist(f.created_at),
            "locked_at": to_ist(f.confidential_meta.created_at) if (f.confidential_meta and f.confidential_meta.created_at) else to_ist(f.created_at)
        }
        for f in files
    ]

@router.get("/saved-passwords")
def get_confidential_saved_passwords(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Confidential Password Saves (Recovery Vault):
    Provides user with the secure list of saved PINs/passphrases for their encrypted files.
    """
    entries = db.query(ConfidentialFile).filter(
        ConfidentialFile.user_id == current_user.id
    ).all()

    res = []
    for c in entries:
        f = c.file
        if not f or f.is_in_recycle_bin:
            continue
        if not c.saved_pin:
            continue
        res.append({
            "file_id": f.id,
            "filename": f.filename,
            "file_size_formatted": format_size(f.file_size),
            "encryption_type": "AES-256-GCM (PBKDF2)",
            "saved_pin": c.saved_pin,
            "has_saved_pin": True,
            "created_at": to_ist_short(c.created_at)
        })
    return res

def _process_unlock(file_id: str, pin: str, current_user: User, db: Session):
    f = db.query(FileRecord).filter(
        FileRecord.id == file_id,
        FileRecord.user_id == current_user.id,
        FileRecord.is_confidential == True
    ).first()

    if not f:
        raise HTTPException(status_code=404, detail="Confidential file not found.")

    c_meta = f.confidential_meta
    if not c_meta:
        raise HTTPException(status_code=400, detail="Missing vault encryption metadata.")

    # 1. Check Permanent Lockout
    if c_meta.is_permanently_locked or (c_meta.failed_attempts and c_meta.failed_attempts >= 9):
        c_meta.is_permanently_locked = True
        db.commit()
        raise HTTPException(
            status_code=403,
            detail="File locked permanently. Cannot open ever sorry. Security threshold exceeded."
        )

    # 2. Check Timed Lockout (30 min or 2 hrs)
    now = datetime.utcnow()
    if c_meta.locked_until and c_meta.locked_until > now:
        remaining_secs = int((c_meta.locked_until - now).total_seconds())
        rem_min = (remaining_secs // 60) + 1
        lock_label = "30 minutes" if c_meta.lockout_stage == 1 else "2 hours"
        raise HTTPException(
            status_code=423,
            detail=f"File locked for {lock_label} due to consecutive failed PIN attempts. Try again later in {rem_min} minute(s)."
        )

    # If timed lockout expired, clear locked_until
    if c_meta.locked_until and c_meta.locked_until <= now:
        c_meta.locked_until = None
        db.commit()

    # 3. Check PIN Verification
    if not verify_pin_hash(pin, c_meta.pin_hash):
        c_meta.failed_attempts = (c_meta.failed_attempts or 0) + 1
        fa = c_meta.failed_attempts

        AuditService.log(
            db, "UNLOCK_CONFIDENTIAL_FAIL", f"File {f.filename}", "FAILED",
            f"Incorrect PIN attempt #{fa}", user_id=current_user.id, username=current_user.username
        )

        if fa == 1:
            db.commit()
            raise HTTPException(status_code=400, detail="Incorrect PIN. 2 attempts remaining.")
        elif fa == 2:
            db.commit()
            raise HTTPException(status_code=400, detail="Incorrect PIN. WARNING: Only 1 attempt remaining before 30-minute lockout!")
        elif fa == 3:
            c_meta.lockout_stage = 1
            c_meta.locked_until = datetime.utcnow() + timedelta(minutes=30)
            db.commit()
            raise HTTPException(
                status_code=423,
                detail="File locked for 30 minutes due to 3 consecutive failed attempts. Try again later."
            )
        elif fa == 4:
            db.commit()
            raise HTTPException(status_code=400, detail="Incorrect PIN. 2 attempts remaining before 2-hour lockout.")
        elif fa == 5:
            db.commit()
            raise HTTPException(status_code=400, detail="Incorrect PIN. WARNING: Only 1 attempt remaining before 2-hour lockout!")
        elif fa == 6:
            c_meta.lockout_stage = 2
            c_meta.locked_until = datetime.utcnow() + timedelta(hours=2)
            db.commit()
            raise HTTPException(
                status_code=423,
                detail="File locked for 2 hours due to repeated failed attempts. Try again later."
            )
        elif fa == 7:
            db.commit()
            raise HTTPException(status_code=400, detail="Incorrect PIN. 2 attempts remaining before PERMANENT LOCKOUT.")
        elif fa == 8:
            db.commit()
            raise HTTPException(status_code=400, detail="Incorrect PIN. FINAL WARNING: Only 1 attempt remaining before PERMANENT LOCKOUT!")
        else:
            c_meta.lockout_stage = 3
            c_meta.is_permanently_locked = True
            c_meta.locked_until = None
            db.commit()
            raise HTTPException(
                status_code=403,
                detail="File locked permanently. Cannot open ever sorry."
            )

    # 4. Correct PIN -> Reset Lockout Status
    c_meta.failed_attempts = 0
    c_meta.lockout_stage = 0
    c_meta.locked_until = None
    db.commit()

    f.storage_path = resolve_storage_path(f.storage_path)
    if not os.path.exists(f.storage_path):
        raise HTTPException(status_code=404, detail="Vault file missing.")

    with open(f.storage_path, "rb") as enc_file:
        encrypted_bytes = enc_file.read()

    try:
        decrypted_bytes = decrypt_file_data(encrypted_bytes, pin, c_meta.pin_salt)
    except Exception:
        raise HTTPException(status_code=500, detail="Decryption failed. Data might be corrupted.")

    AuditService.log(
        db, "UNLOCK_CONFIDENTIAL", f"File {f.filename}", "SUCCESS",
        "PIN verified and content unlocked", user_id=current_user.id, username=current_user.username
    )

    ext = f.extension.lower()
    file_size = len(decrypted_bytes)

    # 1. Plain Text, CSV, JSON, XML, Code
    if ext in [".txt", ".log", ".md", ".py", ".js", ".ts", ".html", ".css", ".sh", ".bat", ".ps1", ".java", ".c", ".cpp", ".sql", ".ini", ".conf", ".yaml", ".yml"]:
        try:
            text_content = decrypted_bytes.decode("utf-8", errors="replace")
        except Exception:
            text_content = str(decrypted_bytes)
        return {
            "format": "TEXT",
            "filename": f.filename,
            "file_size": file_size,
            "mime_type": f.mime_type,
            "content": text_content
        }

    if ext == ".json":
        try:
            parsed = json.loads(decrypted_bytes.decode("utf-8", errors="replace"))
            formatted = json.dumps(parsed, indent=2)
        except Exception:
            formatted = decrypted_bytes.decode("utf-8", errors="replace")
        return {
            "format": "JSON",
            "filename": f.filename,
            "file_size": file_size,
            "content": formatted
        }

    if ext == ".csv":
        text_content = decrypted_bytes.decode("utf-8", errors="replace")
        lines = [line.split(",") for line in text_content.splitlines()]
        return {
            "format": "CSV_TABLE",
            "filename": f.filename,
            "file_size": file_size,
            "rows": lines
        }

    # 2. DOCX Word Document
    if ext in [".docx", ".doc"]:
        html_content = ""
        try:
            mammoth_res = mammoth.convert_to_html(io.BytesIO(decrypted_bytes))
            html_content = mammoth_res.value
        except Exception:
            pass

        paragraphs = []
        tables = []
        try:
            doc = docx.Document(io.BytesIO(decrypted_bytes))
            for p in doc.paragraphs:
                if p.text.strip():
                    paragraphs.append({"style": p.style.name if p.style else "Normal", "text": p.text})
            
            for t in doc.tables:
                table_rows = []
                for row in t.rows:
                    table_rows.append([cell.text.strip() for cell in row.cells])
                tables.append(table_rows)
        except Exception:
            pass

        return {
            "format": "DOCX_RENDERED",
            "filename": f.filename,
            "file_size": file_size,
            "html_content": html_content,
            "paragraph_count": len(paragraphs),
            "paragraphs": paragraphs,
            "tables": tables
        }

    # 3. XLSX Excel Sheet
    if ext in [".xlsx", ".xls"]:
        try:
            wb = openpyxl.load_workbook(io.BytesIO(decrypted_bytes), data_only=True)
            sheets_data = {}
            for sheetname in wb.sheetnames:
                ws = wb[sheetname]
                rows = []
                for row in ws.iter_rows(values_only=True):
                    if any(c is not None for c in row):
                        rows.append([str(c) if c is not None else "" for c in row])
                    if len(rows) >= 500:
                        break
                sheets_data[sheetname] = rows

            return {
                "format": "XLSX_RENDERED",
                "filename": f.filename,
                "file_size": file_size,
                "sheet_names": wb.sheetnames,
                "sheets": sheets_data
            }
        except Exception as e:
            return {"format": "ERROR", "filename": f.filename, "error": str(e)}

    # 4. PPTX Presentation
    if ext in [".pptx", ".ppt", ".pps", ".ppsx", ".odp", ".pot", ".potx"]:
        from backend.app.services.presentation_service import PresentationService
        return PresentationService.render_presentation(decrypted_bytes, f.file_hash, f.filename)

    # 5. PDF, Images, Audio, Video -> In-memory Base64 Data URI stream
    if ext in [".pdf", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".mp3", ".wav", ".ogg", ".flac", ".mp4", ".webm", ".mov", ".avi"]:
        b64_data = base64.b64encode(decrypted_bytes).decode('utf-8')
        mime = f.mime_type or "application/octet-stream"
        data_url = f"data:{mime};base64,{b64_data}"
        return {
            "format": "STREAMABLE_MEDIA",
            "filename": f.filename,
            "file_size": file_size,
            "mime_type": mime,
            "stream_url": data_url
        }

    return {
        "format": "UNSUPPORTED_BINARY",
        "filename": f.filename,
        "file_size": file_size,
        "file_size_formatted": format_size(file_size),
        "mime_type": f.mime_type,
        "file_hash": f.file_hash,
        "message": "Preview unavailable for this binary format."
    }

@router.post("/unlock-view")
def unlock_and_view_confidential_file(
    req: ConfidentialUnlockRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    return _process_unlock(req.file_id, req.pin, current_user, db)

@router.post("/unlock")
def unlock_confidential_file_alias(
    req: ConfidentialUnlockRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    return _process_unlock(req.file_id, req.pin, current_user, db)

@router.post("/{file_id}/unlock")
def unlock_confidential_file_by_path(
    file_id: str,
    req: ConfidentialUnlockRequest = Body(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    return _process_unlock(file_id, req.pin, current_user, db)

@router.post("/unlock-download")
def unlock_and_download_confidential_file(
    req: ConfidentialUnlockRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    file_id = req.file_id
    f = db.query(FileRecord).filter(
        FileRecord.id == file_id,
        FileRecord.user_id == current_user.id,
        FileRecord.is_confidential == True
    ).first()

    if not f:
        raise HTTPException(status_code=404, detail="File not found.")

    c_meta = f.confidential_meta
    if not c_meta or not verify_pin_hash(req.pin, c_meta.pin_hash):
        raise HTTPException(status_code=401, detail="Incorrect 6-digit PIN or password.")

    with open(f.storage_path, "rb") as enc_file:
        encrypted_bytes = enc_file.read()

    decrypted_bytes = decrypt_file_data(encrypted_bytes, req.pin, c_meta.pin_salt)

    return StreamingResponse(
        io.BytesIO(decrypted_bytes),
        media_type=f.mime_type,
        headers={"Content-Disposition": f'attachment; filename="{f.filename}"'}
    )

@router.post("/{file_id}/unlock-download")
def unlock_and_download_by_path(
    file_id: str,
    req: ConfidentialUnlockRequest = Body(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    req.file_id = file_id
    return unlock_and_download_confidential_file(req, current_user, db)
