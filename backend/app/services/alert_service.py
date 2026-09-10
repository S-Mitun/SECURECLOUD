"""
SecureCloud - Security Alert & Notification Service
Manages threat alerts, SOC incidents, and broadcast notifications.
"""

from datetime import datetime
from typing import Optional
from sqlalchemy.orm import Session
from backend.app.models.models import SecurityAlert, Notification

class AlertService:
    @staticmethod
    def create_alert(
        db: Session,
        title: str,
        description: str,
        severity: str = "INFO", # INFO, LOW, MEDIUM, HIGH, CRITICAL
        source: str = "Hybrid Threat Engine",
        user_id: Optional[int] = None
    ) -> SecurityAlert:
        """Creates a security alert and dispatches an associated user notification."""
        alert = SecurityAlert(
            title=title,
            description=description,
            severity=severity,
            source=source,
            is_resolved=False,
            created_at=datetime.utcnow()
        )
        db.add(alert)

        # Also create a notification entry
        notif = Notification(
            user_id=user_id,
            title=title,
            message=description,
            severity=severity,
            is_read=False,
            timestamp=datetime.utcnow()
        )
        db.add(notif)
        db.commit()
        db.refresh(alert)
        return alert
