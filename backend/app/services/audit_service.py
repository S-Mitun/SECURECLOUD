"""
SecureCloud - Security Audit Logging Service
Structured audit records for every security and platform action.
"""

from datetime import datetime
from typing import Optional
from sqlalchemy.orm import Session
from backend.app.models.models import AuditLog

class AuditService:
    @staticmethod
    def log(
        db: Session,
        action: str,
        resource: str,
        result: str = "SUCCESS",
        details: Optional[str] = None,
        user_id: Optional[int] = None,
        username: str = "Anonymous",
        role: str = "USER",
        ip_address: str = "127.0.0.1"
    ) -> AuditLog:
        """Persists a structured security audit log entry."""
        log_entry = AuditLog(
            user_id=user_id,
            username=username,
            role=role,
            ip_address=ip_address,
            action=action,
            resource=resource,
            result=result,
            details=details,
            timestamp=datetime.utcnow()
        )
        db.add(log_entry)
        db.commit()
        db.refresh(log_entry)
        return log_entry
