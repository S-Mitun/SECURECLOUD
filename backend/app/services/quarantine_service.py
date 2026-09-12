"""
SecureCloud - Threat Quarantine Service
Isolates malicious files in secure quarantine vault, preventing direct execution or user access.
"""

import os
import shutil
from datetime import datetime
from typing import Optional
from sqlalchemy.orm import Session

from backend.app.config import QUARANTINE_DIR, UPLOADS_DIR
from backend.app.models.models import QuarantineFile, FileRecord

class QuarantineService:
    @staticmethod
    def quarantine_file(
        db: Session,
        original_filename: str,
        file_hash: str,
        reason: str,
        user_id: Optional[int] = None,
        file_id: Optional[str] = None,
        file_path: Optional[str] = None,
        raw_bytes: Optional[bytes] = None
    ) -> QuarantineFile:
        """Moves file to quarantine vault and creates database entry."""
        os.makedirs(QUARANTINE_DIR, exist_ok=True)
        safe_name = os.path.basename(original_filename)
        quarantine_filename = f"quarantine_{file_hash[:16]}_{safe_name}"
        quarantine_dest = os.path.join(QUARANTINE_DIR, quarantine_filename)

        from backend.app.services.storage_service import save_file_bytes
        quarantine_key = f"quarantine/{user_id}/{file_id}/{quarantine_filename}"
        if raw_bytes is not None:
            quarantine_dest = save_file_bytes(quarantine_key, raw_bytes)
        elif file_path and os.path.exists(file_path):
            with open(file_path, "rb") as fp:
                quarantine_dest = save_file_bytes(quarantine_key, fp.read())
            try:
                os.remove(file_path)
            except Exception:
                pass

        q_entry = QuarantineFile(
            file_id=file_id,
            user_id=user_id,
            file_hash=file_hash,
            original_filename=original_filename,
            quarantine_path=quarantine_dest,
            quarantined_at=datetime.utcnow(),
            reason=reason,
            status="QUARANTINED"
        )
        db.add(q_entry)
        db.commit()
        db.refresh(q_entry)
        return q_entry

    @staticmethod
    def restore_file(db: Session, quarantine_id: int) -> bool:
        """Restores a quarantined file back to uploads."""
        entry = db.query(QuarantineFile).filter(QuarantineFile.id == quarantine_id).first()
        if not entry or entry.status != "QUARANTINED":
            return False

        if os.path.exists(entry.quarantine_path):
            restore_dest = os.path.join(UPLOADS_DIR, f"restored_{os.path.basename(entry.quarantine_path)}")
            shutil.move(entry.quarantine_path, restore_dest)
            entry.quarantine_path = restore_dest

        entry.status = "RESTORED"
        db.commit()
        return True

    @staticmethod
    def delete_permanently(db: Session, quarantine_id: int) -> bool:
        """Permanently purges quarantined threat file from disk and database."""
        entry = db.query(QuarantineFile).filter(QuarantineFile.id == quarantine_id).first()
        if not entry:
            return False

        if entry.quarantine_path and os.path.exists(entry.quarantine_path):
            try:
                os.remove(entry.quarantine_path)
            except Exception:
                pass

        db.delete(entry)
        db.commit()
        return True
