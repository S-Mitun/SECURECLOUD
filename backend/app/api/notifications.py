"""
SecureCloud - Notifications & Real-Time Alerts API
"""

from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import or_

from backend.app.database import get_db
from backend.app.models.models import User, Notification, SecurityAlert
from backend.app.security.auth_utils import get_current_user

def to_ist(dt: Optional[datetime]) -> str:
    if not dt:
        return "Never"
    ist_time = dt + timedelta(hours=5, minutes=30)
    return ist_time.strftime("%d %b %Y, %I:%M:%S %p IST")

def to_ist_short(dt: Optional[datetime]) -> str:
    if not dt:
        return "Never"
    ist_time = dt + timedelta(hours=5, minutes=30)
    return ist_time.strftime("%d %b %Y, %I:%M %p")

router = APIRouter(prefix="/api/notifications", tags=["Notifications"])

@router.get("/list")
def list_notifications(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Retrieves notifications for the current user and global system alerts."""
    notifs = db.query(Notification).filter(
        or_(Notification.user_id == current_user.id, Notification.user_id == None)
    ).order_by(Notification.timestamp.desc()).limit(50).all()

    return [
        {
            "id": n.id,
            "title": n.title,
            "message": n.message,
            "severity": n.severity,
            "is_read": n.is_read,
            "timestamp": to_ist_short(n.timestamp)
        }
        for n in notifs
    ]

@router.post("/{notification_id}/read")
def mark_notification_read(
    notification_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Marks a single notification as read."""
    n = db.query(Notification).filter(Notification.id == notification_id).first()
    if not n:
        raise HTTPException(status_code=404, detail="Notification not found.")
    n.is_read = True
    db.commit()
    return {"status": "SUCCESS", "message": "Marked as read."}

@router.post("/mark-all-read")
def mark_all_notifications_read(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Marks all notifications for current user as read."""
    db.query(Notification).filter(
        or_(Notification.user_id == current_user.id, Notification.user_id == None)
    ).update({Notification.is_read: True}, synchronize_session=False)
    db.commit()
    return {"status": "SUCCESS", "message": "All notifications marked as read."}

@router.get("/alerts")
def list_security_alerts(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Retrieves active security alerts."""
    alerts = db.query(SecurityAlert).order_by(SecurityAlert.created_at.desc()).limit(30).all()
    return [
        {
            "id": a.id,
            "title": a.title,
            "description": a.description,
            "severity": a.severity,
            "source": a.source,
            "is_resolved": a.is_resolved,
            "created_at": to_ist(a.created_at)
        }
        for a in alerts
    ]

@router.post("/alerts/{alert_id}/resolve")
def resolve_security_alert(
    alert_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Marks a security alert as resolved."""
    a = db.query(SecurityAlert).filter(SecurityAlert.id == alert_id).first()
    if not a:
        raise HTTPException(status_code=404, detail="Alert not found.")
    a.is_resolved = True
    db.commit()
    return {"status": "SUCCESS", "message": "Security alert resolved."}
