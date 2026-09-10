"""
SecureCloud - IP Access Guard
Verifies client IP addresses against active whitelist and blacklist rules.
"""

from datetime import datetime
from fastapi import Request, HTTPException, status
from sqlalchemy.orm import Session
from backend.app.models.models import IPRule

def get_client_ip(request: Request) -> str:
    """Extracts client IP address considering proxy headers."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "127.0.0.1"

def check_ip_access(request: Request, db: Session):
    """
    Validates client IP against IP rules in database.
    Raises 403 Forbidden if client IP is blacklisted.
    """
    client_ip = get_client_ip(request)
    
    # Check if there is an active rule for this IP
    rule = db.query(IPRule).filter(IPRule.ip_address == client_ip, IPRule.is_active == True).first()
    
    if rule:
        rule.last_seen = datetime.utcnow()
        db.commit()

        if rule.rule_type.upper() == "BLACKLIST":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access Blocked by IP Access Guard: IP {client_ip} is blacklisted."
            )
