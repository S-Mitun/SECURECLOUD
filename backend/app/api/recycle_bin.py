"""
SecureCloud 2.0 - Recycle Bin & Soft-Delete API
Prevents direct access to deleted files and provides safe restoration and permanent destruction.
"""

import os
from datetime import datetime, timedelta
from typing import Dict, Any, List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.app.database import get_db
from backend.app.models.models import User, FileRecord, RecycleBinItem, FileVersion
from backend.app.schemas.schemas import RecycleBinItemResponse
from backend.app.security.auth_utils import get_current_user
from backend.app.services.audit_service import AuditService
from backend.app.services.storage_service import format_size, recalculate_user_storage, get_user_storage_metrics

router = APIRouter(prefix="/api/recycle-bin", tags=["Recycle Bin"])

def to_ist(dt: Any) -> str:
    """Formats a datetime or ISO string to standard Indian Standard Time (IST)."""
    if not dt:
        dt = datetime.utcnow()
    if isinstance(dt, str):
        try:
            dt = datetime.fromisoformat(dt.replace("Z", "+00:00"))
        except Exception:
            return dt
    if hasattr(dt, 'tzinfo') and dt.tzinfo is not None:
        ist = dt + timedelta(hours=5, minutes=30)
    else:
        ist = dt + timedelta(hours=5, minutes=30)
    return ist.strftime("%d %b %Y, %I:%M:%S %p IST")

@router.get("/list")
def list_recycle_bin(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Lists files currently residing in the user's Recycle Bin."""
    items = db.query(RecycleBinItem).filter(
        RecycleBinItem.user_id == current_user.id
    ).order_by(RecycleBinItem.deleted_at.desc()).all()

    res = []
    for item in items:
        f = item.file
        if f:
            ist_formatted = to_ist(item.deleted_at)
            iso_str = (item.deleted_at or datetime.utcnow()).strftime("%Y-%m-%dT%H:%M:%SZ")
            res.append({
                "id": item.id,
                "file_id": f.id,
                "original_name": item.original_name,
                "file_size": f.file_size,
                "file_size_formatted": format_size(f.file_size),
                "file_hash": f.file_hash,
                "deleted_at": ist_formatted,
                "deleted_at_ist": ist_formatted,
                "deleted_at_iso": iso_str
            })
    return res

@router.post("/{file_id}/restore")
def restore_file_from_recycle_bin(
    file_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Restores a soft-deleted file back to active My Files."""
    item = db.query(RecycleBinItem).filter(
        RecycleBinItem.file_id == file_id,
        RecycleBinItem.user_id == current_user.id
    ).first()

    if not item:
        raise HTTPException(status_code=404, detail="Item not found in Recycle Bin.")

    f = item.file
    if f:
        f.is_in_recycle_bin = False
        f.updated_at = datetime.utcnow()

    db.delete(item)
    db.commit()

    # Recalculate storage quota
    metrics = get_user_storage_metrics(db, current_user.id)

    AuditService.log(
        db, "RESTORE_FILE", f"File {item.original_name}", "SUCCESS",
        "Restored from Recycle Bin", user_id=current_user.id, username=current_user.username
    )

    return {
        "status": "SUCCESS",
        "message": f"File '{item.original_name}' restored successfully.",
        "storage": metrics
    }

@router.delete("/{file_id}/permanent")
def permanently_delete_file(
    file_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Permanently purges file from disk and database."""
    item = db.query(RecycleBinItem).filter(
        RecycleBinItem.file_id == file_id,
        RecycleBinItem.user_id == current_user.id
    ).first()

    if not item:
        raise HTTPException(status_code=404, detail="Item not found in Recycle Bin.")

    f = item.file
    original_name = item.original_name
    if f:
        # Delete versions from disk
        versions = db.query(FileVersion).filter(FileVersion.file_id == f.id).all()
        for v in versions:
            if v.storage_path and os.path.exists(v.storage_path):
                try:
                    os.remove(v.storage_path)
                except Exception:
                    pass

        # Delete main file from disk
        if f.storage_path and os.path.exists(f.storage_path):
            try:
                os.remove(f.storage_path)
            except Exception:
                pass

        db.delete(f)

    db.delete(item)
    db.commit()

    # Recalculate storage quota
    metrics = get_user_storage_metrics(db, current_user.id)

    AuditService.log(
        db, "PERMANENT_DELETE_FILE", f"File {original_name}", "SUCCESS",
        "Permanently deleted from disk and database",
        user_id=current_user.id, username=current_user.username
    )

    return {
        "status": "SUCCESS",
        "message": f"File '{original_name}' permanently deleted.",
        "storage": metrics
    }
